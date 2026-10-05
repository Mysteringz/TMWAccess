/**
 * Claims about TMWAccess, against a fake edge speaking TMGW v1.
 * (`npm run crosscheck` repeats the important ones against the real TMedge.)
 */
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import dgram from 'node:dgram';
import { connect, createServer, type AddressInfo, type Socket } from 'node:net';
import { test } from 'node:test';
import type { Config } from '../src/config.js';
import { Gateway } from '../src/gateway.js';
import { addressed, frame, FrameReader, helloMac, parseAddressed, T_DOWNLINK, T_HELLO, T_UPLINK, T_WELCOME, T_DENY, T_IMAGE_META, T_IMAGE_CHUNK } from '../src/gwlink.js';
import { socks5Connect } from '../src/socks5.js';

const TOKEN = Buffer.from('gateway-token-for-tests');

/** A TMnode-shaped datagram (the gateway never checks the tag, so any 8 bytes do). */
function tmPacket(type: number, uid = '30:ed:a0:cb:f5:f8', payload = Buffer.alloc(14)): Buffer {
  const b = Buffer.alloc(22 + payload.length + 8);
  b.write('TM', 0, 'latin1');
  b[2] = 1;
  b[3] = type;
  Buffer.from(uid.replace(/:/g, ''), 'hex').copy(b, 4);
  b.writeUInt16LE(payload.length, 20);
  payload.copy(b, 22);
  createHmac('sha256', 'k').update(b.subarray(0, 22 + payload.length)).digest().subarray(0, 8).copy(b, 22 + payload.length);
  return b;
}

interface FakeEdge {
  port: number;
  uplinks: { addr: string; port: number; datagram: Buffer }[];
  sockets: Socket[];
  sendDown(addr: string, port: number, d: Buffer): void;
  close(): Promise<void>;
}

async function fakeEdge(token = TOKEN, port = 0): Promise<FakeEdge> {
  const uplinks: FakeEdge['uplinks'] = [];
  const sockets: Socket[] = [];
  const server = createServer((s) => {
    sockets.push(s);
    const r = new FrameReader();
    let ok = false;
    s.on('data', (c) => r.push(c, (type, p) => {
      if (type === T_HELLO) {
        const h = JSON.parse(p.toString()) as { gatewayId: string; ts: number; nonce: string; mac: string };
        ok = h.mac === helloMac(token, h.gatewayId, h.ts, h.nonce);
        s.write(ok ? frame(T_WELCOME, Buffer.from('{"v":1,"edgeId":"fake"}')) : frame(T_DENY, Buffer.from('{"reason":"bad token"}')));
      } else if (type === T_UPLINK && ok) {
        const u = parseAddressed(p);
        if (u) uplinks.push({ ...u, datagram: Buffer.from(u.datagram) });
      }
    }));
    s.on('error', () => undefined);
  });
  await new Promise<void>((r) => server.listen(port, '127.0.0.1', () => r()));
  return {
    port: (server.address() as AddressInfo).port,
    uplinks,
    sockets,
    sendDown: (addr, p, d) => sockets.at(-1)?.write(frame(T_DOWNLINK, addressed(addr, p, d))),
    close: () => new Promise((r) => { sockets.forEach((s) => s.destroy()); server.close(() => r()); }),
  };
}

function cfg(edgePort: number, over: Partial<Config> = {}): Config {
  return {
    gatewayId: 'test-gw', routes: [{ kind: 'tcp', host: '127.0.0.1', port: edgePort }], token: TOKEN, socks5: null, cfAccess: null, failbackMs: 0,
    listenHost: '127.0.0.1', listenPort: 0, nodeCommandPort: 0, nodeCidrs: ['127.0.0.0/8'], imagePort: 0,
    statusPort: 0, queueMax: 100, ...over,
  };
}

const until = async (f: () => boolean, ms = 3000) => {
  const t0 = Date.now();
  while (!f()) {
    if (Date.now() - t0 > ms) throw new Error('timed out waiting');
    await new Promise((r) => setTimeout(r, 20));
  }
};

/** Bind the gateway on a random port and return a node socket aimed at it. */
async function node(gw: Gateway) {
  const s = dgram.createSocket('udp4');
  await new Promise<void>((r) => s.bind(0, '127.0.0.1', () => r()));
  const gwPort = (gw as unknown as { udp: dgram.Socket }).udp.address().port;
  return { s, send: (b: Buffer) => s.send(b, gwPort, '127.0.0.1'), port: s.address().port };
}

test('relays TMnode packets byte for byte, with the node address; drops anything else', async () => {
  const edge = await fakeEdge();
  const gw = new Gateway(cfg(edge.port));
  await gw.start();
  const n = await node(gw);
  try {
    await until(() => gw.linkState() === 'up');
    const report = tmPacket(0x01);
    n.send(report);
    n.send(Buffer.from('hello, not a TM packet'));
    n.send(tmPacket(0x10));                        // a COMMAND pretending to come from a node
    await until(() => edge.uplinks.length >= 1);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(edge.uplinks.length, 1);
    assert.ok(edge.uplinks[0]?.datagram.equals(report), 'unchanged, tag included');
    assert.equal(edge.uplinks[0]?.addr, '127.0.0.1');
    assert.equal(edge.uplinks[0]?.port, n.port);
    assert.equal(gw.counters.rejectedShape, 2);
  } finally {
    n.s.close();
    await gw.stop();
    await edge.close();
  }
});

test('only nodes on the configured networks are relayed', async () => {
  const edge = await fakeEdge();
  const gw = new Gateway(cfg(edge.port, { nodeCidrs: ['192.168.0.0/16'] }));
  await gw.start();
  const n = await node(gw);
  try {
    await until(() => gw.linkState() === 'up');
    n.send(tmPacket(0x01));
    await until(() => gw.counters.rejectedSource === 1);
    assert.equal(edge.uplinks.length, 0);
  } finally {
    n.s.close();
    await gw.stop();
    await edge.close();
  }
});

test('edge-approved node addresses survive spoofed address-candidate floods', async () => {
  const edge = await fakeEdge();
  const cmdSock = dgram.createSocket('udp4');
  await new Promise<void>(r => cmdSock.bind(0, '127.0.0.1', r));
  const got: Buffer[] = []; cmdSock.on('message', b => got.push(b));
  const gw = new Gateway(cfg(edge.port, { nodeCommandPort: cmdSock.address().port }));
  await gw.start(); const n = await node(gw);
  try {
    await until(() => gw.linkState() === 'up'); n.send(tmPacket(1));
    await until(() => edge.uplinks.length === 1);
    edge.sendDown('127.0.0.1', n.port, tmPacket(0x10)); await until(() => got.length === 1);
    // macOS does not automatically bind every address in 127/8. Inject the
    // candidate datagrams into the same source/shape admission callback while
    // retaining real UDP traffic and the authenticated edge downlink above.
    const receiver = gw as unknown as { fromNode(msg: Buffer, addr: string, port: number): void };
    for (let i = 2; i <= 12; i++) {
      receiver.fromNode(tmPacket(1), `127.0.0.${i}`, n.port);
    }
    await until(() => edge.uplinks.length === 12);
    assert.equal(gw.nodes.get('30:ed:a0:cb:f5:f8')?.addr, '127.0.0.1');
    edge.sendDown('127.0.0.1', n.port, tmPacket(0x10)); await until(() => got.length === 2);
    assert.equal(gw.counters.commandsRefused, 0);
  } finally { n.s.close(); cmdSock.close(); await gw.stop(); await edge.close(); }
});

test('while the edge is unreachable packets queue (bounded), and flush when the link comes up', async () => {
  // Reserve a port, then close it: the gateway's first attempts fail.
  const probe = await fakeEdge();
  const port = probe.port;
  await probe.close();
  const gw = new Gateway(cfg(port, { queueMax: 5 }));
  await gw.start();
  const n = await node(gw);
  let edge: FakeEdge | null = null;
  try {
    for (let i = 0; i < 8; i++) n.send(tmPacket(0x01, '30:ed:a0:cb:f5:f8', Buffer.alloc(14, i)));
    await until(() => gw.counters.queued === 8);
    assert.equal(gw.counters.droppedQueue, 3, 'oldest dropped beyond QUEUE_MAX');
    edge = await fakeEdge(TOKEN, port);
    await until(() => (edge?.uplinks.length ?? 0) === 5, 8000);
    assert.equal(edge.uplinks[0]?.datagram[22], 3, 'the newest five survive, in order');
  } finally {
    n.s.close();
    await gw.stop();
    await edge?.close();
  }
});

test('a gateway with the wrong token is refused and backs off', async () => {
  const edge = await fakeEdge(Buffer.from('a-different-token-entirely'));
  const gw = new Gateway(cfg(edge.port));
  await gw.start();
  try {
    await until(() => gw.counters.denies === 1);
    assert.notEqual(gw.linkState(), 'up');
  } finally {
    await gw.stop();
    await edge.close();
  }
});

test('commands reach a known node on its command port, and nothing else is relayed into the LAN', async () => {
  const edge = await fakeEdge();
  const cmdSock = dgram.createSocket('udp4');
  await new Promise<void>((r) => cmdSock.bind(0, '127.0.0.1', () => r()));
  const got: Buffer[] = [];
  cmdSock.on('message', (m) => got.push(m));
  const gw = new Gateway(cfg(edge.port, { nodeCommandPort: cmdSock.address().port }));
  await gw.start();
  const n = await node(gw);
  try {
    await until(() => gw.linkState() === 'up');
    n.send(tmPacket(0x01));                        // the gateway learns the node
    await until(() => edge.uplinks.length === 1);
    edge.sendDown('127.0.0.1', n.port, tmPacket(0x10));                          // a command for it
    edge.sendDown('127.0.0.1', n.port, tmPacket(0x10, '02:00:00:00:00:99'));     // for a node never heard from
    edge.sendDown('127.0.0.1', n.port, tmPacket(0x01));                          // not a command
    edge.sendDown('10.9.9.9', n.port, tmPacket(0x10));                           // wrong address for this node
    await until(() => gw.counters.commandsIn === 4);
    await new Promise((r) => setTimeout(r, 100));
    assert.equal(got.length, 1);
    assert.equal(got[0]?.[3], 0x10);
    assert.equal(gw.counters.commandsRefused, 3);
  } finally {
    n.s.close();
    cmdSock.close();
    await gw.stop();
    await edge.close();
  }
});

test('SOCKS5 client: CONNECT through a proxy and carry data', async () => {
  const target = createServer((s) => s.on('data', (d) => s.write(Buffer.concat([Buffer.from('echo:'), d]))));
  await new Promise<void>((r) => target.listen(0, '127.0.0.1', () => r()));
  const tport = (target.address() as AddressInfo).port;
  // A minimal SOCKS5 proxy: no auth, CONNECT to IPv4 only.
  const proxy = createServer((c) => {
    let stage = 0;
    c.on('data', function onData(d: Buffer) {
      if (stage === 0) {
        c.write(Buffer.from([5, 0]));
        stage = 1;
        return;
      }
      c.removeListener('data', onData);
      const port = d.readUInt16BE(8);
      const t = connect(port, `${d[4]}.${d[5]}.${d[6]}.${d[7]}`, () => {
        c.write(Buffer.from([5, 0, 0, 1, 127, 0, 0, 1, 0, 0]));
        c.pipe(t);
        t.pipe(c);
      });
    });
    c.on('error', () => undefined);
  });
  await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', () => r()));
  try {
    const s = await socks5Connect('127.0.0.1', (proxy.address() as AddressInfo).port, '127.0.0.1', tport);
    const reply = await new Promise<string>((r) => { s.once('data', (d) => r(d.toString())); s.write('ping'); });
    assert.equal(reply, 'echo:ping');
    s.destroy();
  } finally {
    proxy.close();
    target.close();
  }
});

test('routes: a dead primary falls back to the next route, and the gateway returns to the primary once it answers', async () => {
  const probe = await fakeEdge();
  const primaryPort = probe.port;
  await probe.close();                                   // primary: nothing listening yet
  const fallback = await fakeEdge();
  const gw = new Gateway(cfg(0, {
    routes: [{ kind: 'tcp', host: '127.0.0.1', port: primaryPort }, { kind: 'tcp', host: '127.0.0.1', port: fallback.port }],
    failbackMs: 300,
  }));
  await gw.start();
  const n = await node(gw);
  let primary: FakeEdge | null = null;
  try {
    await until(() => gw.linkState() === 'up');
    assert.equal(gw.status().link.fallback, true);
    n.send(tmPacket(0x01));
    await until(() => fallback.uplinks.length === 1);
    // Like TMedge, the fake edge drops the old session when the same gateway says HELLO again.
    fallback.sockets.forEach((s) => s.on('close', () => undefined));
    const downs: string[] = [];
    gw.on('down', () => downs.push('down'));
    primary = await fakeEdge(TOKEN, primaryPort);        // primary comes back
    await until(() => gw.status().link.fallback === false, 5000);
    fallback.sockets.forEach((s) => s.destroy());        // the edge closing the replaced session
    await new Promise((r) => setTimeout(r, 200));
    assert.equal(gw.linkState(), 'up');
    assert.deepEqual(downs, [], 'switching routes is not a link failure');
    n.send(tmPacket(0x01, '30:ed:a0:cb:f5:f8', Buffer.alloc(14, 7)));
    await until(() => (primary?.uplinks.length ?? 0) === 1);
    assert.equal(primary.uplinks[0]?.datagram[22], 7, 'traffic now goes to the primary');
    assert.equal(fallback.uplinks.length, 1, 'and no longer to the fallback');
  } finally {
    n.s.close();
    await gw.stop();
    await fallback.close();
    await primary?.close();
  }
});

test('config: routes parse, and a plaintext ws:// to a remote host is refused', async () => {
  const { parseRoute } = await import('../src/config.js');
  assert.deepEqual(parseRoute('wss://gw.hkumyseat.com/tmgw'), { kind: 'wss', url: 'wss://gw.hkumyseat.com/tmgw' });
  assert.deepEqual(parseRoute('tcp://100.106.57.2:5210'), { kind: 'tcp', host: '100.106.57.2', port: 5210 });
  assert.deepEqual(parseRoute('100.106.57.2:5210'), { kind: 'tcp', host: '100.106.57.2', port: 5210 });
  assert.throws(() => parseRoute('ws://gw.hkumyseat.com/tmgw'), /use wss/);
  assert.equal(parseRoute('ws://127.0.0.1:5210/tmgw').kind, 'wss');
});

test('a forged uplink from another LAN address does not overwrite the signed return route', async () => {
  const edge = await fakeEdge();
  const cmdSock = dgram.createSocket('udp4');
  await new Promise<void>((r) => cmdSock.bind(0, '127.0.0.1', () => r()));
  const commands: Buffer[] = [];
  cmdSock.on('message', (m) => commands.push(m));
  const gw = new Gateway(cfg(edge.port, { nodeCommandPort: cmdSock.address().port }));
  await gw.start();
  const real = await node(gw);
  try {
    await until(() => gw.linkState() === 'up');
    real.send(tmPacket(0x01));
    await until(() => edge.uplinks.length === 1);
    // Exercise the datagram callback without depending on macOS loopback aliases.
    (gw as unknown as { fromNode(msg: Buffer, addr: string, port: number): void }).fromNode(tmPacket(0x01), '127.0.0.2', real.port);
    await until(() => edge.uplinks.length === 2);
    // The real edge rejects the forged signature and retains the first route.
    edge.sendDown('127.0.0.1', real.port, tmPacket(0x10));
    await until(() => commands.length === 1);
    assert.equal(gw.counters.commandsRefused, 0);
  } finally {
    real.s.close(); cmdSock.close(); await gw.stop(); await edge.close();
  }
});

test('node identities, old return routes and the STATS frame stay bounded under LAN floods', async () => {
  const gw = new Gateway(cfg(1));
  const internals = gw as unknown as { fromNode(b: Buffer, addr: string, port: number): void; pruneNodes(now: number): void; log(msg: string): void; sendStats(): void; state: string; link: { route: Config['routes'][number]; write(b: Buffer): void }; };
  internals.log = () => undefined;
  for (let i = 0; i < 600; i++) {
    const uid = `02:00:00:00:${(i >> 8).toString(16).padStart(2, '0')}:${(i & 255).toString(16).padStart(2, '0')}`;
    internals.fromNode(tmPacket(0x01, uid), '127.0.0.1', 5200);
  }
  assert.equal(gw.nodes.size, 512);
  const frames: Buffer[] = [];
  internals.state = 'up';
  internals.link = { route: gw.cfg.routes[0]!, write: (b) => frames.push(b) };
  internals.sendStats();
  assert.ok(frames[0] && frames[0].length < 64 * 1024);
  internals.pruneNodes(Date.now() + 5 * 60_000 + 1);
  assert.equal(gw.nodes.size, 0);
});

test('WELCOME and firmware frames in one TCP read are all processed', async () => {
  const { createHash } = await import('node:crypto');
  const bytes = Buffer.alloc(100, 0x3a);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const id = sha256.slice(0, 16);
  const sockets: Socket[] = [];
  const server = createServer((sock) => {
    sockets.push(sock);
    sock.once('data', () => {
      const head = Buffer.alloc(1 + id.length + 4);
      head[0] = id.length;
      head.write(id, 1, 'latin1');
      sock.write(Buffer.concat([
        frame(T_WELCOME, Buffer.from('{"v":1,"edgeId":"fake"}')),
        frame(T_IMAGE_META, Buffer.from(JSON.stringify({ id, size: bytes.length, sha256 }))),
        frame(T_IMAGE_CHUNK, Buffer.concat([head, bytes])),
      ]));
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', () => r()));
  const gw = new Gateway(cfg((server.address() as AddressInfo).port));
  try {
    await gw.start();
    await until(() => gw.linkState() === 'up');
    assert.equal((gw as unknown as { images: { has(id: string): boolean } }).images.has(id), true);
  } finally {
    await gw.stop(); sockets.forEach((s) => s.destroy()); await new Promise<void>((r) => server.close(() => r()));
  }
});

test('stop closes the firmware HTTP listener and is idempotent', async () => {
  const edge = await fakeEdge();
  const probe = await fakeEdge();
  const imagePort = probe.port;
  await probe.close();
  const gw = new Gateway(cfg(edge.port, { imagePort }));
  try {
    await gw.start();
    await until(() => gw.linkState() === 'up');
    assert.equal((await fetch(`http://127.0.0.1:${imagePort}/missing`)).status, 404);
    await gw.stop();
    await gw.stop();
    await assert.rejects(fetch(`http://127.0.0.1:${imagePort}/missing`, { signal: AbortSignal.timeout(1000) }));
  } finally { await gw.stop(); await edge.close(); }
});

test('startup reports an occupied UDP port instead of hanging', async () => {
  const occupied = dgram.createSocket('udp4');
  await new Promise<void>((r) => occupied.bind(0, '127.0.0.1', () => r()));
  const gw = new Gateway(cfg(1, { listenPort: occupied.address().port }));
  try { await assert.rejects(gw.start(), /EADDRINUSE/); }
  finally { await gw.stop(); occupied.close(); }
});

test('SOCKS5 rejects malformed replies and early close promptly', async () => {
  for (const reply of [Buffer.from([4, 0, 0, 1, 127, 0, 0, 1, 0, 0]), Buffer.from([5, 0, 0, 99, 0, 0, 0]), null]) {
    const sockets: Socket[] = [];
    const proxy = createServer((s) => {
      sockets.push(s);
      let stage = 0;
      s.on('data', () => {
        if (stage++ === 0) s.write(Buffer.from([5, 0]));
        else if (reply) s.write(reply);
        else s.end();
      });
    });
    await new Promise<void>((r) => proxy.listen(0, '127.0.0.1', () => r()));
    try {
      await assert.rejects(socks5Connect('127.0.0.1', (proxy.address() as AddressInfo).port, '127.0.0.1', 5200, 1000), /invalid SOCKS5 CONNECT reply|closed during CONNECT/);
    } finally { sockets.forEach((s) => s.destroy()); await new Promise<void>((r) => proxy.close(() => r())); }
  }
  await assert.rejects(socks5Connect('127.0.0.1', 1, 'x'.repeat(256), 5200), /invalid SOCKS5 target/);
});

test('config rejects invalid route ports, URL credentials, proxy ports and CIDRs', async () => {
  const { loadConfig, parseRoute } = await import('../src/config.js');
  for (const route of ['tcp://localhost:0', 'localhost:65536', 'wss://user:password@example.com/tmgw']) assert.throws(() => parseRoute(route));
  assert.equal(parseRoute('ws://[::1]:5210/tmgw').kind, 'wss');
  const env = { EDGE: 'tcp://localhost:5210', TMGW_TOKEN: TOKEN.toString() };
  for (const cidr of ['', '127.0.0.1/', '127.0.0.0/33', '127.0.0.1/8/9', '::1/129']) assert.throws(() => loadConfig({ ...env, NODE_CIDRS: cidr }), /NODE_CIDRS/);
  assert.throws(() => loadConfig({ ...env, SOCKS5: '127.0.0.1:70000' }), /SOCKS5 port/);
});

test('firmware failures retain their image id, and a disabled HTTP listener never advertises success', async () => {
  const { createHash } = await import('node:crypto');
  const bytes = Buffer.alloc(20, 0x7e);
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  const id = sha256.slice(0, 16);
  const gw = new Gateway(cfg(1));
  const sent: { type: number; payload: Buffer }[] = [];
  const reader = new FrameReader();
  const internals = gw as unknown as { fromEdge(type: number, payload: Buffer): void; link: { write(b: Buffer): void }; log(msg: string): void };
  internals.log = () => undefined;
  internals.link = { write: (b) => reader.push(b, (type, payload) => sent.push({ type, payload: Buffer.from(payload) })) };
  const head = Buffer.alloc(21);
  head[0] = id.length; head.write(id, 1, 'latin1');
  internals.fromEdge(T_IMAGE_META, Buffer.from(JSON.stringify({ id, size: bytes.length, sha256 })));
  internals.fromEdge(T_IMAGE_CHUNK, Buffer.concat([head, Buffer.alloc(bytes.length, 0)]));
  assert.equal(JSON.parse(sent[0]!.payload.toString()).id, id);
  assert.equal(JSON.parse(sent[0]!.payload.toString()).ok, false);
  sent.length = 0;
  internals.fromEdge(T_IMAGE_META, Buffer.from(JSON.stringify({ id, size: bytes.length, sha256 })));
  internals.fromEdge(T_IMAGE_CHUNK, Buffer.concat([head, bytes]));
  assert.deepEqual(JSON.parse(sent[0]!.payload.toString()), { id, ok: false, error: 'firmware image server disabled', port: 0 });
});
