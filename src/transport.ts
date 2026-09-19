/**
 * Routes to the edge. A route is where TMGW frames can travel:
 *
 *   wss://gw.example.com/tmgw   WebSocket over HTTPS -- e.g. through Cloudflare
 *                               Tunnel; only outbound 443 is needed. With
 *                               CF_ACCESS_CLIENT_ID/SECRET, the Cloudflare Access
 *                               service-token headers are sent.
 *   tcp://100.106.57.2:5210     raw TCP -- e.g. over Tailscale; via SOCKS5 if set.
 *
 * Both carry identical frames, so the gateway logic above does not care which
 * one is in use.
 */
import { connect, type Socket } from 'node:net';
import type { Config, Route } from './config.js';
import { socks5Connect } from './socks5.js';

export interface Pipe {
  route: Route;
  write(b: Buffer): void;
  destroy(reason?: Error): void;
  /** Bytes accepted but not yet sent: backpressure signal. */
  buffered(): number;
  onData(cb: (b: Buffer) => void): void;
  onClose(cb: (err?: Error) => void): void;
}

export function describe(r: Route): string {
  return r.kind === 'wss' ? r.url : `tcp://${r.host}:${r.port}`;
}

export async function openRoute(r: Route, cfg: Config, timeoutMs = 10_000): Promise<Pipe> {
  return r.kind === 'wss' ? openWebSocket(r, cfg, timeoutMs) : openTcp(r, cfg, timeoutMs);
}

async function openTcp(r: Extract<Route, { kind: 'tcp' }>, cfg: Config, timeoutMs: number): Promise<Pipe> {
  const s: Socket = cfg.socks5
    ? await socks5Connect(cfg.socks5.host, cfg.socks5.port, r.host, r.port, timeoutMs)
    : await new Promise((resolve, reject) => {
      const sock = connect(r.port, r.host);
      const t = setTimeout(() => { sock.destroy(); reject(new Error('connect timed out')); }, timeoutMs);
      sock.once('connect', () => { clearTimeout(t); resolve(sock); });
      sock.once('error', (e) => { clearTimeout(t); reject(e); });
    });
  s.setNoDelay(true);
  s.setKeepAlive(true, 15_000);
  let lastErr: Error | undefined;
  s.on('error', (e) => { lastErr = e; });
  return {
    route: r,
    write: (b) => void s.write(b),
    destroy: (reason) => s.destroy(reason),
    buffered: () => s.writableLength,
    onData: (cb) => void s.on('data', cb),
    onClose: (cb) => void s.on('close', () => cb(lastErr)),
  };
}

function openWebSocket(r: Extract<Route, { kind: 'wss' }>, cfg: Config, timeoutMs: number): Promise<Pipe> {
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (cfg.cfAccess) {
      headers['CF-Access-Client-Id'] = cfg.cfAccess.id;
      headers['CF-Access-Client-Secret'] = cfg.cfAccess.secret;
    }
    // Node's built-in WebSocket (undici) accepts headers in its options.
    const ws = new WebSocket(r.url, { headers } as unknown as string[]);
    ws.binaryType = 'arraybuffer';
    let opened = false;
    let closeErr: Error | undefined;
    const dataCbs: ((b: Buffer) => void)[] = [];
    const closeCbs: ((e?: Error) => void)[] = [];
    const t = setTimeout(() => { ws.close(); reject(new Error('WebSocket connect timed out')); }, timeoutMs);
    ws.onopen = () => {
      opened = true;
      clearTimeout(t);
      resolve({
        route: r,
        write: (b) => ws.send(b),
        destroy: (reason) => {
          closeErr = reason;
          try { ws.close(1000); } catch { /* already closing */ }
        },
        buffered: () => ws.bufferedAmount,
        onData: (cb) => void dataCbs.push(cb),
        onClose: (cb) => void closeCbs.push(cb),
      });
    };
    ws.onmessage = (e) => {
      const b = Buffer.from(e.data as ArrayBuffer);
      for (const cb of dataCbs) cb(b);
    };
    ws.onerror = () => {
      closeErr ??= new Error(`WebSocket error on ${r.url}`);
    };
    ws.onclose = (e) => {
      clearTimeout(t);
      if (!opened) {
        // A refused Cloudflare Access check surfaces here as a failed upgrade.
        reject(closeErr ?? new Error(`WebSocket to ${r.url} closed before opening (code ${e.code})`));
        return;
      }
      for (const cb of closeCbs) cb(closeErr ?? (e.code === 1000 ? undefined : new Error(`WebSocket closed (${e.code}${e.reason ? ` ${e.reason}` : ''})`)));
    };
  });
}
