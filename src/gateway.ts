/**
 * TMWAccess: the Wi-Fi access gateway.
 *
 *   TMnodes --UDP 5200 (LAN)--> TMWAccess ==one TCP link (TMGW v1)==> TMedge :5210
 *   TMnodes <--UDP 5201------- TMWAccess <==commands on the same link== TMedge
 *
 * Deliberately dumb about content: it checks that a datagram is shaped like a
 * TMnode packet and relays it byte for byte. It holds no node key, so it can
 * neither forge nor read-and-alter occupancy; TMedge verifies every node's
 * HMAC exactly as if the node were on its own network.
 *
 * The link is outbound only, so the gateway's site needs no inbound port and
 * works behind NAT, on campus Wi-Fi, or through a SOCKS5 proxy. It can take
 * several routes (e.g. Cloudflare Tunnel first, Tailscale as fallback): the
 * first that works carries the link, and while on a fallback the primary is
 * retried periodically and taken back as soon as it answers.
 */
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import { createServer, BlockList, isIP, type Server } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { Config } from './config.js';
import {
  addressed, frame, FrameReader, helloMac, parseAddressed, tmShape,
  T_DENY, T_DOWNLINK, T_HELLO, T_IMAGE_CHUNK, T_IMAGE_META, T_IMAGE_READY, T_PING, T_PONG, T_STATS, T_UPLINK, T_WELCOME,
  TM_DOWNLINK_TYPES, TM_UPLINK_TYPES, TMGW_VERSION,
} from './gwlink.js';
import { ImageStore } from './images.js';
import { describe, openRoute, type Pipe } from './transport.js';

export const VERSION = '1.0.0';
const DEAD_LINK_MS = 45_000;
const MAX_BUFFERED_BYTES = 2 * 1024 * 1024;

interface NodeSeen {
  uid: string;
  addr: string;
  port: number;
  firstSeen: number;
  lastSeen: number;
  packets: number;
  commands: number;
}

type LinkState = 'down' | 'connecting' | 'up';

export class Gateway extends EventEmitter {
  readonly nodes = new Map<string, NodeSeen>();
  private readonly udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
  private readonly allow = new BlockList();
  private readonly images = new ImageStore(this.allow, (m) => this.log(m));
  private link: Pipe | null = null;
  private routeIndex = -1;
  private failbackTimer: NodeJS.Timeout | null = null;
  /**
   * Set while taking back the preferred route. The edge replaces our session
   * as soon as the new one says HELLO, which closes the old pipe a moment
   * before adopt() runs; that close is expected, not a failure.
   */
  private switching = false;
  private state: LinkState = 'down';
  private edgeId: string | null = null;
  private queue: Buffer[] = [];
  private backoffMs = 1000;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private timers: NodeJS.Timeout[] = [];
  private lastFromEdge = 0;
  private statusServer: Server | null = null;
  private stopped = false;
  private readonly startedAt = Date.now();
  readonly counters = {
    received: 0, relayed: 0, queued: 0, droppedQueue: 0, droppedBackpressure: 0,
    rejectedSource: 0, rejectedShape: 0, commandsIn: 0, commandsSent: 0, commandsRefused: 0,
    connects: 0, denies: 0, lastError: '' as string,
  };

  constructor(readonly cfg: Config) {
    super();
    for (const c of cfg.nodeCidrs) {
      const [net, bits] = c.split('/');
      const fam = isIP(net ?? '');
      if (!net || !fam || bits === undefined) throw new Error(`NODE_CIDRS: "${c}" is not a CIDR`);
      this.allow.addSubnet(net, Number(bits), fam === 6 ? 'ipv6' : 'ipv4');
    }
  }

  async start(): Promise<void> {
    this.udp.on('message', (msg, r) => this.fromNode(msg, r.address, r.port));
    this.udp.on('error', (e) => this.log(`udp error: ${e.message}`));
    await new Promise<void>((resolve) => this.udp.bind(this.cfg.listenPort, this.cfg.listenHost, () => resolve()));
    this.log(`listening for TMnodes on udp ${this.cfg.listenHost}:${this.cfg.listenPort} (from ${this.cfg.nodeCidrs.join(', ')})`);
    this.connect();
    this.timers.push(setInterval(() => this.heartbeat(), 15_000));
    this.timers.push(setInterval(() => this.sendStats(), 10_000));
    if (this.cfg.statusPort > 0) this.startStatus();
    if (this.cfg.imagePort > 0) {
      // Firmware images are served on the node network, the one network the
      // nodes can reach; the same CIDR rule as the uplink applies.
      await this.images.listen(this.cfg.imagePort, this.cfg.listenHost);
      this.log(`firmware images on http://${this.cfg.listenHost}:${this.cfg.imagePort}/fw/<id>.bin`);
    }
  }

  /** Tell the edge whether an image arrived intact. */
  private sendImageResult(id: string, ok: boolean, error?: string): void {
    if (!ok) this.log(`image rejected: ${error ?? 'unknown'}`);
    this.link?.write(frame(T_IMAGE_READY, Buffer.from(JSON.stringify({
      id, ok, error, port: this.cfg.imagePort,
    }))));
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const t of this.timers) clearInterval(t);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.failbackTimer) clearInterval(this.failbackTimer);
    this.link?.destroy();
    this.statusServer?.close();
    await new Promise<void>((resolve) => this.udp.close(() => resolve()));
  }

  linkState(): LinkState {
    return this.state;
  }

  // --- nodes -> edge -------------------------------------------------------------

  private fromNode(msg: Buffer, addr: string, port: number): void {
    this.counters.received += 1;
    const fam = isIP(addr);
    if (!fam || !this.allow.check(addr, fam === 6 ? 'ipv6' : 'ipv4')) {
      this.counters.rejectedSource += 1;
      return;
    }
    const shape = tmShape(msg);
    if (!shape || !TM_UPLINK_TYPES.has(shape.type)) {
      this.counters.rejectedShape += 1;
      return;
    }
    const now = Date.now();
    const n = this.nodes.get(shape.uid);
    if (n) {
      n.addr = addr;
      n.port = port;
      n.lastSeen = now;
      n.packets += 1;
    } else {
      this.nodes.set(shape.uid, { uid: shape.uid, addr, port, firstSeen: now, lastSeen: now, packets: 1, commands: 0 });
      this.log(`new node ${shape.uid} at ${addr}`);
    }
    const f = frame(T_UPLINK, addressed(addr, port, msg));
    if (this.state === 'up' && this.link) {
      // A stalled link must not grow memory without bound: past a couple of
      // MB unsent, drop -- a REPORT is superseded a second later anyway.
      if (this.link.buffered() > MAX_BUFFERED_BYTES) {
        this.counters.droppedBackpressure += 1;
        return;
      }
      this.link.write(f);
      this.counters.relayed += 1;
    } else {
      this.queue.push(f);
      this.counters.queued += 1;
      while (this.queue.length > this.cfg.queueMax) {
        this.queue.shift();
        this.counters.droppedQueue += 1;
      }
    }
  }

  // --- edge -> nodes -------------------------------------------------------------

  private fromEdge(type: number, payload: Buffer): void {
    this.lastFromEdge = Date.now();
    switch (type) {
      case T_DOWNLINK: {
        this.counters.commandsIn += 1;
        const d = parseAddressed(payload);
        const shape = d && tmShape(d.datagram);
        const node = shape ? this.nodes.get(shape.uid) : undefined;
        // Only a TM COMMAND, only to a node this gateway has heard from, at the
        // address it was heard from: the gateway must not become a relay into
        // the LAN for anything the edge (or someone on the link) asks.
        if (!d || !shape || !TM_DOWNLINK_TYPES.has(shape.type) || !node || node.addr !== d.addr) {
          this.counters.commandsRefused += 1;
          return;
        }
        this.udp.send(d.datagram, this.cfg.nodeCommandPort, node.addr, (err) => {
          if (err) this.counters.lastError = `command send: ${err.message}`;
        });
        node.commands += 1;
        this.counters.commandsSent += 1;
        this.log(`command for ${node.uid} delivered to ${node.addr}:${this.cfg.nodeCommandPort}`);
        return;
      }
      // A firmware image, in pieces. The gateway only holds and serves it;
      // whether it is the right image is settled by the node, against the
      // hash in the signed request the edge sent it.
      case T_IMAGE_META: {
        try {
          const meta = JSON.parse(payload.toString('utf8')) as { id: string; size: number; sha256: string };
          this.images.begin(meta);
        } catch (err) {
          this.sendImageResult('', false, (err as Error).message);
        }
        return;
      }
      case T_IMAGE_CHUNK: {
        // [idLen u8][id][offset u32][bytes]
        try {
          const idLen = payload[0] ?? 0;
          const id = payload.subarray(1, 1 + idLen).toString('latin1');
          const offset = payload.readUInt32LE(1 + idLen);
          const bytes = payload.subarray(1 + idLen + 4);
          const done = this.images.chunk(id, offset, bytes);
          if (done) this.sendImageResult(done.id, true);
        } catch (err) {
          this.sendImageResult('', false, (err as Error).message);
        }
        return;
      }
      case T_PING:
        this.link?.write(frame(T_PONG, payload));
        return;
      default:
        return;
    }
  }

  // --- link -----------------------------------------------------------------------

  /** Try each route in order; the first to complete the handshake carries the link. */
  private connect(): void {
    if (this.stopped || this.state !== 'down') return;
    this.state = 'connecting';
    void (async () => {
      const errors: string[] = [];
      for (let i = 0; i < this.cfg.routes.length; i++) {
        const route = this.cfg.routes[i];
        if (!route || this.stopped) return;
        try {
          const pipe = await this.handshake(await openRoute(route, this.cfg));
          this.adopt(pipe, i);
          return;
        } catch (err) {
          errors.push(`${describe(route)}: ${(err as Error).message}`);
        }
      }
      this.linkDown(`no route to the edge (${errors.join('; ')})`);
    })();
  }

  /**
   * HELLO on a fresh pipe; resolves once the edge WELCOMEs us. Frames that
   * arrive after that are handled by adopt().
   */
  private handshake(pipe: Pipe): Promise<Pipe> {
    return new Promise((resolve, reject) => {
      const reader = new FrameReader();
      const ts = Date.now();
      const nonce = randomBytes(8).toString('hex');
      let done = false;
      const t = setTimeout(() => finish(new Error('no WELCOME from edge')), 10_000);
      const finish = (err?: Error) => {
        if (done) return;
        done = true;
        clearTimeout(t);
        if (err) {
          pipe.destroy(err);
          reject(err);
        } else {
          resolve(pipe);
        }
      };
      (pipe as Pipe & { reader?: FrameReader }).reader = reader;
      pipe.onData((chunk) => {
        if (done) return;
        try {
          reader.push(chunk, (type, payload) => {
            if (type === T_WELCOME) {
              try {
                this.edgeId = (JSON.parse(payload.toString('utf8')) as { edgeId?: string }).edgeId ?? null;
              } catch {
                this.edgeId = null;
              }
              finish();
            } else if (type === T_DENY) {
              this.counters.denies += 1;
              // Refused credentials will not fix themselves: back off hard.
              this.backoffMs = 60_000;
              finish(new Error(`edge refused this gateway: ${payload.toString('utf8')}`));
            }
          });
        } catch (err) {
          finish(err as Error);
        }
      });
      pipe.onClose((err) => finish(err ?? new Error('closed during handshake')));
      pipe.write(frame(T_HELLO, Buffer.from(JSON.stringify({ v: TMGW_VERSION, gatewayId: this.cfg.gatewayId, ts, nonce, mac: helloMac(this.cfg.token, this.cfg.gatewayId, ts, nonce) }))));
    });
  }

  /** Make a handshaken pipe the live link (replacing any current one). */
  private adopt(pipe: Pipe, index: number): void {
    const old = this.link;
    this.link = pipe;
    this.routeIndex = index;
    this.state = 'up';
    this.backoffMs = 1000;
    this.counters.connects += 1;
    this.lastFromEdge = Date.now();
    const reader = (pipe as Pipe & { reader?: FrameReader }).reader ?? new FrameReader();
    pipe.onData((chunk) => {
      if (this.link !== pipe) return;
      try {
        reader.push(chunk, (type, payload) => this.fromEdge(type, payload));
      } catch (err) {
        pipe.destroy(err as Error);
      }
    });
    pipe.onClose((err) => {
      if (this.link !== pipe || this.switching) return;
      this.link = null;
      this.linkDown(err?.message ?? this.counters.lastError ?? 'link closed');
    });
    // The edge has already replaced the old session with this one.
    old?.destroy();
    const flushed = this.queue.length;
    for (const f of this.queue) pipe.write(f);
    this.counters.relayed += flushed;
    this.queue = [];
    const fallback = index > 0 ? ' [fallback]' : '';
    this.log(`link up to edge ${this.edgeId ?? '?'} via ${describe(pipe.route)}${fallback}${flushed ? `, flushed ${flushed} queued datagram(s)` : ''}`);
    this.sendStats();
    this.emit('up');
    this.scheduleFailback();
  }

  /** On a fallback route, periodically try the preferred ones again. */
  private scheduleFailback(): void {
    if (this.failbackTimer) clearInterval(this.failbackTimer);
    this.failbackTimer = null;
    if (this.routeIndex <= 0 || this.cfg.failbackMs <= 0) return;
    this.failbackTimer = setInterval(() => {
      void (async () => {
        for (let i = 0; i < this.routeIndex; i++) {
          const route = this.cfg.routes[i];
          if (!route || this.stopped || this.state !== 'up') return;
          this.switching = true;
          try {
            const pipe = await this.handshake(await openRoute(route, this.cfg));
            this.log(`preferred route ${describe(route)} is back; switching`);
            this.adopt(pipe, i);
            return;
          } catch {
            /* still down; stay on the fallback */
          } finally {
            this.switching = false;
          }
        }
      })();
    }, this.cfg.failbackMs);
  }

  private linkDown(reason: string): void {
    const was = this.state;
    this.state = 'down';
    this.routeIndex = -1;
    this.counters.lastError = reason;
    if (this.failbackTimer) clearInterval(this.failbackTimer);
    this.failbackTimer = null;
    if (was === 'up') this.emit('down');
    if (this.stopped) return;
    this.log(`link down: ${reason}; retrying in ${Math.round(this.backoffMs / 1000)} s`);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectTimer = setTimeout(() => this.connect(), this.backoffMs);
    this.backoffMs = Math.min(this.backoffMs * 2, 30_000);
  }

  private heartbeat(): void {
    if (this.state !== 'up' || !this.link) return;
    // TCP keepalive can take minutes to notice a dead path (a VPN or Wi-Fi
    // roam); the edge pings every 10 s, so 45 s of silence means it is gone.
    if (Date.now() - this.lastFromEdge > DEAD_LINK_MS) {
      this.link.destroy(new Error('no traffic from edge for 45 s'));
      return;
    }
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(BigInt(Date.now()));
    this.link.write(frame(T_PING, b));
  }

  status() {
    const now = Date.now();
    return {
      gatewayId: this.cfg.gatewayId,
      version: VERSION,
      uptimeS: Math.round((now - this.startedAt) / 1000),
      link: {
        state: this.state,
        route: this.link ? describe(this.link.route) : null,
        fallback: this.routeIndex > 0,
        routes: this.cfg.routes.map(describe),
        edgeId: this.edgeId,
      },
      queue: this.queue.length,
      counters: { ...this.counters },
      nodes: [...this.nodes.values()].map((n) => ({ ...n, ageS: Math.round((now - n.lastSeen) / 1000) })),
    };
  }

  private sendStats(): void {
    if (this.state !== 'up' || !this.link) return;
    const s = this.status();
    const stats = {
      version: VERSION, uptimeS: s.uptimeS, route: s.link.route, fallback: s.link.fallback, queue: s.queue,
      nodes: s.nodes.filter((n) => n.ageS < 60).length,
      nodeList: s.nodes.map((n) => ({ uid: n.uid, addr: n.addr, ageS: n.ageS, packets: n.packets })),
      ...this.counters,
    };
    this.link.write(frame(T_STATS, Buffer.from(JSON.stringify(stats))));
  }

  private startStatus(): void {
    // Local diagnostics only (127.0.0.1): what the gateway sees and whether the link is up.
    this.statusServer = createServer((sock) => {
      sock.once('data', () => {
        const body = JSON.stringify(this.status(), null, 2);
        sock.end(`HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n\r\n${body}`);
      });
      sock.on('error', () => undefined);
    });
    this.statusServer.listen(this.cfg.statusPort, '127.0.0.1');
  }

  private log(msg: string): void {
    console.log(`[tmwaccess] ${msg}`);
  }
}
