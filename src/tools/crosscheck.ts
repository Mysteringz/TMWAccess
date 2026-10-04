/**
 * TMWAccess against the REAL TMedge (TMEDGE_DIR, default ../TMedge, built):
 * its GatewayServer and Ingest, with packets signed the way TMnodes sign
 * them. `npm test` uses a fake edge; this is the check that the two copies of
 * TMGW have not drifted apart.
 */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Gateway } from '../gateway.js';

const dir = resolve(process.env.TMEDGE_DIR ?? '../TMedge');
const imp = (p: string) => import(pathToFileURL(resolve(dir, 'dist/src/edge', p)).href);
const { GatewayServer } = await imp('gwlink.js');
const { Ingest } = await imp('ingest.js');
const { buildReport, CMD_IDENTIFY } = await imp('protocol.js');

const TOKEN = Buffer.from('crosscheck-gateway-token');
const KEY = Buffer.from('crosscheck-node-key');
const UID = '30:ed:a0:cb:f5:f8';
let checks = 0;
const ok = (m: string) => { checks++; console.log(`ok  ${m}`); };
const until = async (f: () => boolean, ms = 4000) => {
  const t0 = Date.now();
  while (!f()) {
    if (Date.now() - t0 > ms) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 20));
  }
};

const seen: { uid: string; address: string; people: number }[] = [];
const rejected: string[] = [];
let gws: InstanceType<typeof GatewayServer>;
const ing = new Ingest({
  port: 0, host: '127.0.0.1', verify: { keys: [KEY], allowUnsigned: false }, commandKey: KEY,
  routeViaGateway: (a: string, b: Buffer) => gws.sendDownlink(a, b),
});
ing.on('report', (p: { uid: string; detections: unknown[] }, address: string) => seen.push({ uid: p.uid, address, people: p.detections.length }));
ing.on('rejected', (_a: string, r: string) => rejected.push(r));
gws = new GatewayServer({ port: 0, host: '127.0.0.1', token: TOKEN, edgeId: 'crosscheck-edge', onUplink: (d: Buffer, s: string) => ing.handle(d, s) });
const edgePort: number = await gws.listen();

const cmd = dgram.createSocket('udp4');
await new Promise<void>((r) => cmd.bind(0, '127.0.0.1', () => r()));
const commands: Buffer[] = [];
cmd.on('message', (m) => commands.push(m));

const gw = new Gateway({
  gatewayId: 'crosscheck-gw', routes: [{ kind: 'tcp', host: '127.0.0.1', port: edgePort }], token: TOKEN, socks5: null, cfAccess: null, failbackMs: 0,
  listenHost: '127.0.0.1', listenPort: 0, nodeCommandPort: cmd.address().port, nodeCidrs: ['127.0.0.0/8'], statusPort: 0, imagePort: 0, queueMax: 100,
});
await gw.start();
await until(() => gw.linkState() === 'up');
ok('TMWAccess authenticates to the real TMedge GatewayServer');

const node = dgram.createSocket('udp4');
await new Promise<void>((r) => node.bind(0, '127.0.0.1', () => r()));
const gwPort = (gw as unknown as { udp: dgram.Socket }).udp.address().port;
const id = { uid: UID, boot: 3, seq: 0, key: KEY };
const det = { x: 12.5, y: 9, area: 8, contrast: 3.1, peak: 31, heat: 40 };
node.send(buildReport(id, 1000, { frame: 1, ta: 30, sceneMin: 22, sceneMax: 31, bgMean: 23, flags: 1, detections: [det] }), gwPort, '127.0.0.1');
await until(() => seen.length === 1);
assert.equal(seen[0]?.uid, UID);
assert.equal(seen[0]?.people, 1);
assert.match(seen[0]?.address ?? '', /^gw:crosscheck-gw\|127\.0\.0\.1:\d+$/);
ok(`a signed REPORT relayed by TMWAccess is accepted by TMedge's parser as ${seen[0]?.address}`);

const forged = buildReport({ uid: UID, boot: 3, seq: 50, key: Buffer.from('wrong') }, 2000, { frame: 2, ta: 30, sceneMin: 22, sceneMax: 31, bgMean: 23, flags: 1, detections: [det] });
node.send(forged, gwPort, '127.0.0.1');
await until(() => rejected.length === 1);
assert.equal(rejected[0], 'bad signature');
ok('a forged packet relayed by the gateway is still rejected by TMedge');

await ing.sendCommand(UID, CMD_IDENTIFY, 0, 3);
await until(() => commands.length === 1);
assert.equal(commands[0]?.[3], 0x10);
ok("TMedge's command reaches the node's command port through the gateway");

const bad = new Gateway({ ...gw.cfg, gatewayId: 'intruder', token: Buffer.from('not-the-gateway-token'), listenPort: 0 });
await bad.start();
await until(() => bad.counters.denies === 1);
ok('a gateway with the wrong token is refused by TMedge');
await bad.stop();
await gw.stop();

// The same, over the WebSocket route TMedge serves on the same port (what
// Cloudflare Tunnel carries), with Access headers as Cloudflare would forward them.
seen.length = 0;
const wsgw = new Gateway({
  ...gw.cfg, gatewayId: 'crosscheck-wss', listenPort: 0,
  routes: [{ kind: 'wss', url: `ws://127.0.0.1:${edgePort}/tmgw` }],
  cfAccess: { id: 'test-id.access', secret: 'test-secret' },
});
await wsgw.start();
await until(() => wsgw.linkState() === 'up');
const info = gws.gateways().find((g: { id: string }) => g.id === 'crosscheck-wss');
assert.equal(info?.transport, 'websocket');
ok('TMWAccess connects to the real TMedge over the WebSocket route');
const wsPort = (wsgw as unknown as { udp: dgram.Socket }).udp.address().port;
node.send(buildReport({ uid: UID, boot: 4, seq: 0, key: KEY }, 1000, { frame: 1, ta: 30, sceneMin: 22, sceneMax: 31, bgMean: 23, flags: 1, detections: [det] }), wsPort, '127.0.0.1');
await until(() => seen.length === 1);
assert.match(seen[0]?.address ?? '', /^gw:crosscheck-wss\|/);
ok('a signed REPORT relayed over the WebSocket route is accepted by TMedge');
await ing.sendCommand(UID, CMD_IDENTIFY, 0, 3);
await until(() => commands.length === 2);
ok('commands come back over the WebSocket route');
await wsgw.stop();

// Wire v2 uses the real firmware builder/parser at both ends. The gateway has
// no device keys; exercise durable admission, REPORT ACK and COMMAND over both
// link types, with no plaintext exposed on the gateway link.
const { DeviceKeys } = await imp('secure.js');
const firmware = resolve(process.env.TMSENSE_DIR ?? resolve(dir, '../TMsense'));
const harness = execFileSync(resolve(firmware, 'test/host/build_packet_host.sh'), [resolve('dist/packet_host')], { encoding: 'utf8' }).trim();
const fixtures = execFileSync(harness, ['emit-secure'], { encoding: 'utf8' }).trim().split('\n').map((line) => JSON.parse(line) as { name: string; hex: string });
const encryptedReport = Buffer.from(fixtures.find(f => f.name === 'report_empty')!.hex, 'hex');
const encryptedUid = [...encryptedReport.subarray(4, 10)].map(b => b.toString(16).padStart(2, '0')).join(':');
for (const transport of ['tcp', 'wss'] as const) {
  const temp = mkdtempSync(resolve(tmpdir(), 'gateway-encrypted-'));
  let secureGws: InstanceType<typeof GatewayServer>;
  const devices = new DeviceKeys({ version: 2, nodes: { [encryptedUid]: { current: { id: 7, secret: '11'.repeat(32) } } } });
  const secureIngest = new Ingest({ port: 0, host: '127.0.0.1', verify: { keys: [], allowUnsigned: false, devices }, commandKey: null,
    cursorPath: resolve(temp, 'replay.jsonl'), routeViaGateway: (a: string, b: Buffer) => secureGws.sendDownlink(a, b) });
  let accepted = 0, denied = 0;
  secureIngest.on('report', () => accepted++); secureIngest.on('rejected', () => denied++);
  secureGws = new GatewayServer({ port: 0, host: '127.0.0.1', token: TOKEN, edgeId: 'encrypted-edge', allowRawTcp: true,
    onUplink: (d: Buffer, a: string) => { void secureIngest.handleDurable(d, a); } });
  const securePort: number = await secureGws.listen();
  const secureGw = new Gateway({ ...gw.cfg, gatewayId: `encrypted-${transport}`, listenPort: 0,
    routes: transport === 'tcp' ? [{ kind: 'tcp', host: '127.0.0.1', port: securePort }] : [{ kind: 'wss', url: `ws://127.0.0.1:${securePort}/tmgw` }] });
  try {
    await secureGw.start(); await until(() => secureGw.linkState() === 'up');
    const port = (secureGw as unknown as { udp: dgram.Socket }).udp.address().port;
    const start = commands.length;
    node.send(encryptedReport, port, '127.0.0.1');
    await until(() => accepted === 1 && commands.length === start + 1);
    const ack = commands[start]!;
    assert.equal(ack[2], 2); assert.equal(ack[3], 0x12);
    const parsedAck = JSON.parse(execFileSync(harness, ['parse-ack', ack.toString('hex'), 'secure'], { encoding: 'utf8' })) as { result: number; type: number };
    assert.equal(parsedAck.result, 0); assert.equal(parsedAck.type, 1);
    ok(`encrypted firmware REPORT crosses ${transport} gateway and its durable ACK authenticates in real firmware`);
    await secureIngest.sendCommand(encryptedUid, CMD_IDENTIFY, 0, 3);
    await until(() => commands.length === start + 2);
    const parsedCmd = JSON.parse(execFileSync(harness, ['parse', commands[start + 1]!.toString('hex'), 'secure'], { encoding: 'utf8' })) as { result: number; opcode: number };
    assert.equal(parsedCmd.result, 0); assert.equal(parsedCmd.opcode, CMD_IDENTIFY);
    ok(`encrypted COMMAND crosses ${transport} gateway and authenticates in real firmware`);
    node.send(encryptedReport, port, '127.0.0.1');
    const altered = Buffer.from(encryptedReport); altered[altered.length - 1]! ^= 1;
    node.send(altered, port, '127.0.0.1');
    await until(() => denied === 2); await new Promise(r => setTimeout(r, 50));
    assert.equal(accepted, 1); assert.equal(commands.length, start + 2);
    ok(`${transport} relay replay and tag alteration produce no application event or ACK`);
  } finally { await secureGw.stop(); await secureIngest.stop(); await secureGws.close(); rmSync(temp, { recursive: true, force: true }); }
}
node.close();
cmd.close();
await gws.close();
console.log(`\ncrosscheck: ${checks} checks passed against ${dir}`);
process.exit(0);
