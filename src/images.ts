/**
 * Firmware images on their way to the nodes.
 *
 * TMedge sends an image down the existing link in chunks; the gateway holds
 * it in memory and serves it over plain HTTP on the node network, because
 * that is the only network the nodes can reach. Nothing here is trusted: the
 * node checks the image against the SHA-256 in the signed request it got from
 * the edge, so a wrong or tampered image is thrown away by the node rather
 * than booted.
 *
 * Only the site's own networks may fetch an image, and only by its id, which
 * is the first 16 hex of its hash.
 */
import { createHash } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { isIP } from 'node:net';

export interface ImageMeta {
  /** First 16 hex characters of the SHA-256: the name it is served under. */
  id: string;
  size: number;
  sha256: string;
}

interface Pending {
  meta: ImageMeta;
  buf: Buffer;
  got: number;
}

export class ImageStore {
  /** Two at most: the one rolling out, and the one before it. */
  private readonly ready = new Map<string, { meta: ImageMeta; bytes: Buffer; storedAt: number }>();
  private pending: Pending | null = null;
  private server: Server | null = null;
  readonly serves = new Map<string, number>();

  /** `allow` is the gateway's node-network BlockList: same rule as the uplink. */
  constructor(
    private readonly allow: { check(address: string, family?: 'ipv4' | 'ipv6'): boolean },
    private readonly log: (m: string) => void,
  ) {}

  /** Start receiving an image. Any half-received one is dropped. */
  begin(meta: ImageMeta): void {
    if (!/^[0-9a-f]{16}$/.test(meta.id)) throw new Error('bad image id');
    if (!/^[0-9a-f]{64}$/.test(meta.sha256)) throw new Error('bad image hash');
    if (!Number.isInteger(meta.size) || meta.size <= 0 || meta.size > 8 * 1024 * 1024) throw new Error('bad image size');
    this.pending = { meta, buf: Buffer.alloc(meta.size), got: 0 };
    this.log(`image ${meta.id}: receiving ${meta.size} bytes`);
  }

  /**
   * Write one chunk. Returns the image once the last byte lands and its hash
   * checks out, so a truncated or altered transfer never becomes servable.
   */
  chunk(id: string, offset: number, bytes: Buffer): ImageMeta | null {
    const p = this.pending;
    if (!p || p.meta.id !== id) throw new Error('no such image in flight');
    if (offset < 0 || offset + bytes.length > p.meta.size) throw new Error('chunk outside the image');
    bytes.copy(p.buf, offset);
    p.got += bytes.length;
    return p.got >= p.meta.size ? this.finish(id) : null;
  }

  private finish(id: string): ImageMeta {
    const p = this.pending;
    if (!p || p.meta.id !== id) throw new Error('no such image in flight');
    if (p.got !== p.meta.size) throw new Error(`have ${p.got} of ${p.meta.size} bytes`);
    const sha = createHash('sha256').update(p.buf).digest('hex');
    if (sha !== p.meta.sha256) throw new Error('image hash mismatch');
    this.ready.set(id, { meta: p.meta, bytes: p.buf, storedAt: Date.now() });
    this.pending = null;
    for (const [oldest] of [...this.ready.entries()].sort((a, b) => a[1].storedAt - b[1].storedAt).slice(0, -2)) {
      this.ready.delete(oldest);
    }
    this.log(`image ${id}: ready, ${p.meta.size} bytes`);
    return p.meta;
  }

  has(id: string): boolean { return this.ready.has(id); }
  get(id: string): Buffer | null { return this.ready.get(id)?.bytes ?? null; }
  list(): { id: string; size: number; serves: number }[] {
    return [...this.ready.values()].map((r) => ({ id: r.meta.id, size: r.meta.size, serves: this.serves.get(r.meta.id) ?? 0 }));
  }

  /** Serve images to the node network only. */
  listen(port: number, host: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const server = createServer((req, res) => {
        const from = (req.socket.remoteAddress ?? '').replace(/^::ffff:/, '');
        const fam = isIP(from);
        if (!fam || !this.allow.check(from, fam === 6 ? 'ipv6' : 'ipv4')) {
          res.writeHead(403).end('not your network\n');
          return;
        }
        const m = /^\/fw\/([0-9a-f]{16})\.bin$/.exec((req.url ?? '').split('?')[0] ?? '');
        const id = m?.[1];
        const bytes = id ? this.get(id) : null;
        if (!id || !bytes) {
          res.writeHead(404).end('no such image\n');
          return;
        }
        this.serves.set(id, (this.serves.get(id) ?? 0) + 1);
        res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': String(bytes.length) });
        if (req.method === 'HEAD') res.end();
        else res.end(bytes);
        this.log(`image ${id}: served to ${from}`);
      });
      server.on('error', reject);
      server.listen(port, host, () => {
        this.server = server;
        const addr = server.address();
        resolve(typeof addr === 'object' && addr ? addr.port : port);
      });
    });
  }

  close(): void {
    this.server?.close();
    this.server = null;
  }
}
