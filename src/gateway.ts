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
 * works behind NAT, on campus Wi-Fi, or through a SOCKS5 proxy.
 */
import dgram from 'node:dgram';
import { EventEmitter } from 'node:events';
import { createServer, connect, BlockList, isIP, type Server, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import type { Config } from './config.js';
import {
  addressed, frame, FrameReader, helloMac, parseAddressed, tmShape,
  T_DENY, T_DOWNLINK, T_HELLO, T_PING, T_PONG, T_STATS, T_UPLINK, T_WELCOME, TM_COMMAND, TM_UPLINK_TYPES, TMGW_VERSION,
} from './gwlink.js';
import { socks5Connect } from './socks5.js';

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
  private link: Socket | null = null;
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
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const t of this.timers) clearInterval(t);
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
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
      if (this.link.writableLength > MAX_BUFFERED_BYTES) {
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
        if (!d || !shape || shape.type !== TM_COMMAND || !node || node.addr !== d.addr) {
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
      case T_PING:
        this.link?.write(frame(T_PONG, payload));
        return;
      default:
        return;
    }
  }

  // --- link -----------------------------------------------------------------------

  private connect(): void {
    if (this.stopped || this.state !== 'down') return;
    this.state = 'connecting';
    const via = this.cfg.socks5 ? ` via SOCKS5 ${this.cfg.socks5.host}:${this.cfg.socks5.port}` : '';
    const open: Promise<Socket> = this.cfg.socks5
      ? socks5Connect(this.cfg.socks5.host, this.cfg.socks5.port, this.cfg.edgeHost, this.cfg.edgePort)
      : new Promise((resolve, reject) => {
        const s = connect(this.cfg.edgePort, this.cfg.edgeHost);
        const t = setTimeout(() => { s.destroy(); reject(new Error('connect timed out')); }, 10_000);
        s.once('connect', () => { clearTimeout(t); resolve(s); });
        s.once('error', (e) => { clearTimeout(t); reject(e); });
      });
    open.then((s) => this.handshake(s), (err: Error) => this.linkDown(`cannot reach edge ${this.cfg.edgeHost}:${this.cfg.edgePort}${via}: ${err.message}`));
  }

  private handshake(s: Socket): void {
    this.link = s;
    s.setNoDelay(true);
    s.setKeepAlive(true, 15_000);
    const reader = new FrameReader();
    const ts = Date.now();
    const nonce = randomBytes(8).toString('hex');
    s.write(frame(T_HELLO, Buffer.from(JSON.stringify({ v: TMGW_VERSION, gatewayId: this.cfg.gatewayId, ts, nonce, mac: helloMac(this.cfg.token, this.cfg.gatewayId, ts, nonce) }))));
    const welcomeTimer = setTimeout(() => s.destroy(new Error('no WELCOME from edge')), 10_000);
    s.on('data', (chunk) => {
      try {
        reader.push(chunk, (type, payload) => {
          if (this.state === 'connecting') {
            if (type === T_WELCOME) {
              clearTimeout(welcomeTimer);
              this.state = 'up';
              this.backoffMs = 1000;
              this.counters.connects += 1;
              this.lastFromEdge = Date.now();
              try {
                this.edgeId = (JSON.parse(payload.toString('utf8')) as { edgeId?: string }).edgeId ?? null;
              } catch {
                this.edgeId = null;
              }
              const flushed = this.queue.length;
              for (const f of this.queue) s.write(f);
              this.counters.relayed += flushed;
              this.queue = [];
              this.log(`link up to edge ${this.edgeId ?? '?'} (${this.cfg.edgeHost}:${this.cfg.edgePort})${flushed ? `, flushed ${flushed} queued datagram(s)` : ''}`);
              this.sendStats();
              this.emit('up');
            } else if (type === T_DENY) {
              clearTimeout(welcomeTimer);
              this.counters.denies += 1;
              // Refused credentials will not fix themselves: back off hard.
              this.backoffMs = 60_000;
              s.destroy(new Error(`edge refused this gateway: ${payload.toString('utf8')}`));
            }
            return;
          }
          this.fromEdge(type, payload);
        });
      } catch (err) {
        s.destroy(err as Error);
      }
    });
    s.on('error', (e) => { this.counters.lastError = e.message; });
    s.on('close', () => {
      clearTimeout(welcomeTimer);
      if (this.link === s) this.link = null;
      this.linkDown(this.counters.lastError || 'link closed');
    });
  }

  private linkDown(reason: string): void {
    const was = this.state;
    this.state = 'down';
    this.counters.lastError = reason;
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
      link: { state: this.state, edge: `${this.cfg.edgeHost}:${this.cfg.edgePort}`, via: this.cfg.socks5 ? `socks5 ${this.cfg.socks5.host}:${this.cfg.socks5.port}` : 'direct', edgeId: this.edgeId },
      queue: this.queue.length,
      counters: { ...this.counters },
      nodes: [...this.nodes.values()].map((n) => ({ ...n, ageS: Math.round((now - n.lastSeen) / 1000) })),
    };
  }

  private sendStats(): void {
    if (this.state !== 'up' || !this.link) return;
    const s = this.status();
    const stats = {
      version: VERSION, uptimeS: s.uptimeS, via: s.link.via, queue: s.queue,
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
