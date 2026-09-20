/** TMWAccess settings, from the environment (or .env via `npm start`). */
import { hostname } from 'node:os';

export type Route =
  | { kind: 'wss'; url: string }
  | { kind: 'tcp'; host: string; port: number };

export interface Config {
  gatewayId: string;
  /** Tried in order; the first that works is used, the rest are fallbacks. */
  routes: Route[];
  token: Buffer;
  /** Applies to tcp routes only. */
  socks5: { host: string; port: number } | null;
  /** Cloudflare Access service token, sent on wss routes. */
  cfAccess: { id: string; secret: string } | null;
  /** While on a fallback route, how often to try the primary again (0 = never). */
  failbackMs: number;
  listenHost: string;
  listenPort: number;
  nodeCommandPort: number;
  /** Only datagrams from these networks are relayed (the site's LAN). */
  nodeCidrs: string[];
  statusPort: number;
  /** Where nodes fetch a firmware image from this gateway (0 = updates off). */
  imagePort: number;
  queueMax: number;
}

export class ConfigError extends Error {}

/** "wss://host/path", "tcp://host:port", or a bare "host:port" (tcp). */
export function parseRoute(s: string): Route {
  if (/^wss?:\/\//.test(s)) {
    try {
      const u = new URL(s);
      if (u.protocol === 'ws:' && !['127.0.0.1', 'localhost', '::1'].includes(u.hostname)) {
        throw new ConfigError(`EDGE: "${s}" -- use wss:// (TLS) for anything but localhost`);
      }
      return { kind: 'wss', url: u.toString() };
    } catch (err) {
      if (err instanceof ConfigError) throw err;
      throw new ConfigError(`EDGE: "${s}" is not a URL`);
    }
  }
  const m = /^(?:tcp:\/\/)?([^:/]+):(\d+)$/.exec(s);
  if (!m) throw new ConfigError(`EDGE: "${s}" is neither wss://host/path nor tcp://host:port`);
  return { kind: 'tcp', host: m[1] ?? '', port: Number(m[2]) };
}

function int(env: NodeJS.ProcessEnv, k: string, def: number, min: number, max: number): number {
  const raw = env[k];
  if (raw === undefined || raw === '') return def;
  const v = Number(raw);
  if (!Number.isInteger(v) || v < min || v > max) throw new ConfigError(`${k} must be an integer ${min}..${max}, got "${raw}"`);
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const routes = (env.EDGE ?? '').split(',').map((s) => s.trim()).filter(Boolean).map(parseRoute);
  if (routes.length === 0) throw new ConfigError('EDGE must list at least one route, e.g. wss://gw.example.com/tmgw,tcp://100.106.57.2:5210');
  const token = env.TMGW_TOKEN ?? '';
  if (token.length < 16) throw new ConfigError('TMGW_TOKEN must be set (16+ chars), the same value as on TMedge');
  let socks5: Config['socks5'] = null;
  if (env.SOCKS5) {
    const s = /^([^:]+):(\d+)$/.exec(env.SOCKS5);
    if (!s) throw new ConfigError('SOCKS5 must be host:port, e.g. 127.0.0.1:1055');
    socks5 = { host: s[1] ?? '', port: Number(s[2]) };
  }
  const gatewayId = env.GATEWAY_ID || hostname().split('.')[0] || 'tmwaccess';
  if (!/^[A-Za-z0-9._-]{1,64}$/.test(gatewayId)) throw new ConfigError('GATEWAY_ID: letters, digits, . _ - only');
  const cfId = env.CF_ACCESS_CLIENT_ID ?? '';
  const cfSecret = env.CF_ACCESS_CLIENT_SECRET ?? '';
  if (Boolean(cfId) !== Boolean(cfSecret)) throw new ConfigError('set both CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET, or neither');
  return {
    gatewayId,
    routes,
    token: Buffer.from(token, 'utf8'),
    socks5,
    cfAccess: cfId ? { id: cfId, secret: cfSecret } : null,
    failbackMs: int(env, 'FAILBACK_S', 300, 0, 86400) * 1000,
    listenHost: env.LISTEN_HOST || '0.0.0.0',
    listenPort: int(env, 'LISTEN_PORT', 5200, 1, 65535),
    nodeCommandPort: int(env, 'NODE_COMMAND_PORT', 5201, 1, 65535),
    nodeCidrs: (env.NODE_CIDRS ?? '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16').split(',').map((s) => s.trim()).filter(Boolean),
    statusPort: int(env, 'STATUS_PORT', 5280, 0, 65535),
    imagePort: int(env, 'IMAGE_PORT', 5282, 0, 65535),
    queueMax: int(env, 'QUEUE_MAX', 5000, 10, 1_000_000),
  };
}
