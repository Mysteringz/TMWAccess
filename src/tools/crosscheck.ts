/**
 * TMWAccess against the REAL TMedge (TMEDGE_DIR, default ../TMedge, built):
 * its GatewayServer and Ingest, with packets signed the way TMnodes sign
 * them. `npm test` uses a fake edge; this is the check that the two copies of
 * TMGW have not drifted apart.
 */
import assert from 'node:assert/strict';
import dgram from 'node:dgram';
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
  gatewayId: 'crosscheck-gw', edgeHost: '127.0.0.1', edgePort, token: TOKEN, socks5: null,
  listenHost: '127.0.0.1', listenPort: 0, nodeCommandPort: cmd.address().port, nodeCidrs: ['127.0.0.0/8'], statusPort: 0, queueMax: 100,
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
node.close();
cmd.close();
await gws.close();
console.log(`\ncrosscheck: ${checks} checks passed against ${dir}`);
process.exit(0);
