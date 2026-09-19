/**
 * Minimal SOCKS5 CONNECT client (RFC 1928, no auth), no dependencies.
 *
 * Used where the gateway host cannot route to the edge itself -- e.g. the dev
 * Mac, where a VPN swallows tailnet traffic and a userspace Tailscale client
 * offers SOCKS5 instead. The mini PC with kernel Tailscale connects directly.
 */
import { connect, isIP, type Socket } from 'node:net';

export function socks5Connect(proxyHost: string, proxyPort: number, host: string, port: number, timeoutMs = 10_000): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const s = connect(proxyPort, proxyHost);
    let stage = 0;
    let buf = Buffer.alloc(0);
    const fail = (e: Error) => {
      s.destroy();
      reject(e);
    };
    const timer = setTimeout(() => fail(new Error(`SOCKS5 ${proxyHost}:${proxyPort} timed out`)), timeoutMs);
    s.once('error', (e) => {
      clearTimeout(timer);
      reject(e);
    });
    s.once('connect', () => s.write(Buffer.from([5, 1, 0])));   // v5, 1 method, "no auth"
    const onData = (chunk: Buffer) => {
      buf = Buffer.concat([buf, chunk]);
      if (stage === 0) {
        if (buf.length < 2) return;
        if (buf[0] !== 5 || buf[1] !== 0) return fail(new Error('SOCKS5 proxy refused no-auth'));
        buf = buf.subarray(2);
        stage = 1;
        const fam = isIP(host);
        let addr: Buffer;
        if (fam === 4) addr = Buffer.from([1, ...host.split('.').map(Number)]);
        else if (fam === 6) {
          return fail(new Error('IPv6 targets are not supported by this client'));
        } else {
          const h = Buffer.from(host);
          addr = Buffer.concat([Buffer.from([3, h.length]), h]);
        }
        const p = Buffer.alloc(2);
        p.writeUInt16BE(port);
        s.write(Buffer.concat([Buffer.from([5, 1, 0]), addr, p]));
      }
      if (stage === 1) {
        if (buf.length < 5) return;
        if (buf[1] !== 0) return fail(new Error(`SOCKS5 CONNECT to ${host}:${port} failed (code ${buf[1]})`));
        const atyp = buf[3];
        const need = atyp === 1 ? 10 : atyp === 4 ? 22 : 7 + (buf[4] ?? 0);
        if (buf.length < need) return;
        const rest = buf.subarray(need);
        clearTimeout(timer);
        s.removeListener('data', onData);
        s.removeAllListeners('error');
        if (rest.length) s.unshift(rest);
        resolve(s);
      }
      return undefined;
    };
    s.on('data', onData);
  });
}
