/**
 * Claims about firmware images passing through the gateway: it holds them,
 * serves them to its own node network and to nobody else, and refuses one
 * whose bytes do not match what the edge said it was sending.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { BlockList } from 'node:net';
import { test } from 'node:test';
import { ImageStore } from '../src/images.js';

const bytes = Buffer.alloc(5000, 0x5a);
const sha256 = createHash('sha256').update(bytes).digest('hex');
const meta = { id: sha256.slice(0, 16), size: bytes.length, sha256 };

function store(cidr = '127.0.0.0/8') {
  const allow = new BlockList();
  const [net, bits] = cidr.split('/');
  allow.addSubnet(net ?? '127.0.0.0', Number(bits ?? 8), 'ipv4');
  return new ImageStore(allow, () => undefined);
}

test('an image arrives in pieces and is served once it is whole', async () => {
  const s = store();
  s.begin(meta);
  assert.equal(s.has(meta.id), false, 'half an image is not servable');
  assert.equal(s.chunk(meta.id, 0, bytes.subarray(0, 4000)), null);
  const done = s.chunk(meta.id, 4000, bytes.subarray(4000));
  assert.equal(done?.id, meta.id);
  assert.equal(s.get(meta.id)?.length, bytes.length);

  const port = await s.listen(0, '127.0.0.1');
  try {
    const res = await fetch(`http://127.0.0.1:${port}/fw/${meta.id}.bin`);
    assert.equal(res.status, 200);
    const got = Buffer.from(await res.arrayBuffer());
    assert.equal(createHash('sha256').update(got).digest('hex'), sha256, 'served byte for byte');
    assert.equal((await fetch(`http://127.0.0.1:${port}/fw/0123456789abcdef.bin`)).status, 404);
    assert.equal((await fetch(`http://127.0.0.1:${port}/../etc/passwd`)).status, 404);
  } finally {
    s.close();
  }
});

test('an image whose bytes do not match the hash never becomes servable', () => {
  const s = store();
  s.begin(meta);
  const tampered = Buffer.from(bytes);
  tampered[42] = 0x00;
  assert.throws(() => s.chunk(meta.id, 0, tampered), /hash mismatch/);
  assert.equal(s.has(meta.id), false);
  assert.equal(s.get(meta.id), null);
});

test('chunks outside the image, or for an image nobody announced, are refused', () => {
  const s = store();
  assert.throws(() => s.chunk(meta.id, 0, bytes), /no such image/);
  s.begin(meta);
  assert.throws(() => s.chunk(meta.id, 4990, bytes), /outside the image/);
  assert.throws(() => s.begin({ ...meta, sha256: 'nonsense' }), /bad image hash/);
  assert.throws(() => s.begin({ ...meta, size: 0 }), /bad image size/);
});

test('only the node network may fetch an image', async () => {
  // The gateway trusts 10.0.0.0/8 here, and the test client is on loopback.
  const s = store('10.0.0.0/8');
  s.begin(meta);
  s.chunk(meta.id, 0, bytes);
  const port = await s.listen(0, '127.0.0.1');
  try {
    const res = await fetch(`http://127.0.0.1:${port}/fw/${meta.id}.bin`);
    assert.equal(res.status, 403, 'a machine outside the node network is refused');
  } finally {
    s.close();
  }
});
