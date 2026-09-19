/**
 * TMGW v1 -- mirror of TMedge/src/edge/gwlink.ts, which is the source of
 * truth. Change both together; `npm run crosscheck` runs this client against
 * TMedge's real server.
 *
 * Framing: u32 LE length (of type + payload), u8 type, payload. Max 64 KiB.
 */
import { createHmac } from 'node:crypto';

export const TMGW_VERSION = 1;
export const T_HELLO = 0x01;
export const T_WELCOME = 0x02;
export const T_DENY = 0x03;
export const T_UPLINK = 0x10;
export const T_DOWNLINK = 0x20;
export const T_PING = 0x30;
export const T_PONG = 0x31;
export const T_STATS = 0x40;
export const MAX_FRAME = 64 * 1024;

export function frame(type: number, payload: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.writeUInt32LE(payload.length + 1, 0);
  head[4] = type;
  return Buffer.concat([head, payload]);
}

export function addressed(addr: string, port: number, datagram: Buffer): Buffer {
  const a = Buffer.from(addr, 'ascii');
  if (a.length > 255) throw new Error('address too long');
  const head = Buffer.alloc(1 + a.length + 2);
  head[0] = a.length;
  a.copy(head, 1);
  head.writeUInt16LE(port, 1 + a.length);
  return Buffer.concat([head, datagram]);
}

export function parseAddressed(p: Buffer): { addr: string; port: number; datagram: Buffer } | null {
  const n = p[0];
  if (n === undefined || p.length < 1 + n + 2) return null;
  return { addr: p.subarray(1, 1 + n).toString('ascii'), port: p.readUInt16LE(1 + n), datagram: p.subarray(3 + n) };
}

export function helloMac(token: Buffer, gatewayId: string, ts: number, nonce: string): string {
  return createHmac('sha256', token).update(`tmgw1|${gatewayId}|${ts}|${nonce}`).digest('hex');
}

export class FrameReader {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer, onFrame: (type: number, payload: Buffer) => void): void {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    for (;;) {
      if (this.buf.length < 4) return;
      const len = this.buf.readUInt32LE(0);
      if (len < 1 || len > MAX_FRAME) throw new Error(`bad frame length ${len}`);
      if (this.buf.length < 4 + len) return;
      const type = this.buf[4] ?? 0;
      const payload = this.buf.subarray(5, 4 + len);
      this.buf = this.buf.subarray(4 + len);
      onFrame(type, payload);
    }
  }
}

// --- TMnode datagram sanity (the gateway never verifies HMAC: it has no key) ---

export const TM_UPLINK_TYPES = new Set([0x01, 0x02, 0x03]);
export const TM_COMMAND = 0x10;
export const TM_HEADER = 22;
export const TM_TAG = 8;

/** Cheap structural check so the link only carries things that look like TMnode packets. */
export function tmShape(d: Buffer): { type: number; uid: string } | null {
  if (d.length < TM_HEADER + TM_TAG || d.length > 1400) return null;
  if (d[0] !== 0x54 || d[1] !== 0x4d || d[2] !== 1) return null;
  if (d.readUInt16LE(20) + TM_HEADER + TM_TAG !== d.length) return null;
  return { type: d[3] ?? 0, uid: [...d.subarray(4, 10)].map((b) => b.toString(16).padStart(2, '0')).join(':') };
}
