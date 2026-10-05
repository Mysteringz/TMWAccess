/**
 * TMGW v1 -- mirror of TMedge/src/edge/gwlink.ts, which is the source of
 * truth. Change both together; `npm run crosscheck` runs this client against
 * TMedge's real server.
 *
 * Framing: u32 LE length (of type + payload), u8 type, payload. Max 64 KiB.
 */
import { createHmac } from 'node:crypto';
import { isIP } from 'node:net';

export const TMGW_VERSION = 1;
export const T_HELLO = 0x01;
export const T_WELCOME = 0x02;
export const T_DENY = 0x03;
export const T_UPLINK = 0x10;
export const T_DOWNLINK = 0x20;
export const T_PING = 0x30;
export const T_PONG = 0x31;
export const T_STATS = 0x40;
/** Firmware images on their way to a gateway, for an over-the-air update. */
export const T_IMAGE_META = 0x50;
export const T_IMAGE_CHUNK = 0x51;
export const T_IMAGE_READY = 0x52;
export const MAX_FRAME = 64 * 1024;

export function frame(type: number, payload: Buffer): Buffer {
  if (!Number.isInteger(type) || type < 0 || type > 255 || payload.length + 1 > MAX_FRAME) throw new Error('bad frame');
  const head = Buffer.alloc(5);
  head.writeUInt32LE(payload.length + 1, 0);
  head[4] = type;
  return Buffer.concat([head, payload]);
}

export function addressed(addr: string, port: number, datagram: Buffer): Buffer {
  if (!isIP(addr) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('bad node address');
  const a = Buffer.from(addr, 'ascii');
  const head = Buffer.alloc(1 + a.length + 2);
  head[0] = a.length;
  a.copy(head, 1);
  head.writeUInt16LE(port, 1 + a.length);
  return Buffer.concat([head, datagram]);
}

export function parseAddressed(p: Buffer): { addr: string; port: number; datagram: Buffer } | null {
  const n = p[0];
  if (n === undefined || p.length < 1 + n + 2) return null;
  const raw = p.subarray(1, 1 + n);
  // ASCII decoding masks high bits; reject them before checking the IP.
  if (raw.some((b) => b > 127)) return null;
  const addr = raw.toString('ascii');
  const port = p.readUInt16LE(1 + n);
  if (!isIP(addr) || port === 0) return null;
  return { addr, port, datagram: p.subarray(3 + n) };
}

export function helloMac(token: Buffer, gatewayId: string, ts: number, nonce: string): string {
  return createHmac('sha256', token).update(`tmgw1|${gatewayId}|${ts}|${nonce}`).digest('hex');
}

export class FrameReader {
  private readonly header = Buffer.alloc(4);
  private headerBytes = 0;
  private body: Buffer | null = null;
  private bodyBytes = 0;

  push(chunk: Buffer, onFrame: (type: number, payload: Buffer) => void): void {
    let offset = 0;
    while (offset < chunk.length) {
      if (!this.body) {
        const n = Math.min(4 - this.headerBytes, chunk.length - offset);
        chunk.copy(this.header, this.headerBytes, offset, offset + n);
        this.headerBytes += n;
        offset += n;
        if (this.headerBytes < 4) return;
        const len = this.header.readUInt32LE(0);
        if (len < 1 || len > MAX_FRAME) throw new Error(`bad frame length ${len}`);
        // Allocate once per frame: byte-at-a-time peers must not force
        // quadratic Buffer.concat work or retain an unbounded input chunk.
        this.body = Buffer.allocUnsafe(len);
        this.bodyBytes = 0;
      }
      const n = Math.min(this.body.length - this.bodyBytes, chunk.length - offset);
      chunk.copy(this.body, this.bodyBytes, offset, offset + n);
      this.bodyBytes += n;
      offset += n;
      if (this.bodyBytes < this.body.length) return;
      const complete = this.body;
      this.body = null;
      this.headerBytes = 0;
      onFrame(complete[0] ?? 0, complete.subarray(1));
    }
  }
}

// --- TMnode datagram sanity (the gateway never verifies HMAC: it has no key) ---

export const TM_UPLINK_TYPES = new Set([0x01, 0x02, 0x03, 0x04]);   // report, raw, status, ota progress
export const TM_COMMAND = 0x10;
export const TM_OTA = 0x11;
/** The only things a gateway may put back on the node network. */
export const TM_DOWNLINK_TYPES = new Set([TM_COMMAND, TM_OTA, 0x12]);
export const TM_HEADER = 22;
export const TM_TAG = 8;

/** Cheap structural check so the link only carries things that look like TMnode packets. */
export function tmShape(d: Buffer): { type: number; uid: string } | null {
  if (d.length < TM_HEADER + TM_TAG || d.length > 1400) return null;
  if (d[0] !== 0x54 || d[1] !== 0x4d) return null;
  if (d[2] === 1) {
    if (d.readUInt16LE(20) + TM_HEADER + TM_TAG !== d.length) return null;
  } else if (d[2] === 2) {
    if (d.length < 58 || d.readUInt16LE(22) + 42 + 16 !== d.length || d.readUInt16LE(24) === 0) return null;
  } else return null;
  return { type: d[3] ?? 0, uid: [...d.subarray(4, 10)].map((b) => b.toString(16).padStart(2, '0')).join(':') };
}
