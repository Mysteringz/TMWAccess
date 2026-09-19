/** TMWAccess settings, from the environment (or .env via `npm start`). */
import { hostname } from 'node:os';

export interface Config {
  gatewayId: string;
  edgeHost: string;
  edgePort: number;
  token: Buffer;
  socks5: { host: string; port: number } | null;
  listenHost: string;
  listenPort: number;
  nodeCommandPort: number;
  /** Only datagrams from these networks are relayed (the site's LAN). */
  nodeCidrs: string[];
  statusPort: number;
  queueMax: number;
}

export class ConfigError extends Error {}

function int(env: NodeJS.ProcessEnv, k: string, def: number, min: number, max: number): number {
  const raw = env[k];
  if (raw === undefined || raw === '') return def;
  const v = Number(raw);
  if (!Number.isInteger(v) || v < min || v > max) throw new ConfigError(`${k} must be an integer ${min}..${max}, got "${raw}"`);
  return v;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const edge = env.EDGE ?? '';
  const m = /^([^:]+):(\d+)$/.exec(edge);
  if (!m) throw new ConfigError('EDGE must be host:port of TMedge\'s gateway port, e.g. 100.106.57.2:5210');
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
  return {
    gatewayId,
    edgeHost: m[1] ?? '',
    edgePort: Number(m[2]),
    token: Buffer.from(token, 'utf8'),
    socks5,
    listenHost: env.LISTEN_HOST || '0.0.0.0',
    listenPort: int(env, 'LISTEN_PORT', 5200, 1, 65535),
    nodeCommandPort: int(env, 'NODE_COMMAND_PORT', 5201, 1, 65535),
    nodeCidrs: (env.NODE_CIDRS ?? '10.0.0.0/8,172.16.0.0/12,192.168.0.0/16').split(',').map((s) => s.trim()).filter(Boolean),
    statusPort: int(env, 'STATUS_PORT', 5280, 0, 65535),
    queueMax: int(env, 'QUEUE_MAX', 5000, 10, 1_000_000),
  };
}
