/** TMWAccess entry point: `npm start` (reads .env). */
import { ConfigError, loadConfig } from './config.js';
import { Gateway, VERSION } from './gateway.js';
import { describe } from './transport.js';

let cfg;
try {
  cfg = loadConfig();
} catch (err) {
  if (err instanceof ConfigError) {
    console.error(`[tmwaccess] refusing to start: ${err.message}`);
    process.exit(2);
  }
  throw err;
}

console.log(`[tmwaccess] ${VERSION} gateway "${cfg.gatewayId}" -> routes, in order: ${cfg.routes.map(describe).join(', ')}` +
  `${cfg.socks5 ? ` (tcp via SOCKS5 ${cfg.socks5.host}:${cfg.socks5.port})` : ''}${cfg.cfAccess ? ' (Cloudflare Access token set)' : ''}`);
const gw = new Gateway(cfg);
await gw.start();
if (cfg.statusPort) console.log(`[tmwaccess] status: http://127.0.0.1:${cfg.statusPort}/`);

const shutdown = async () => {
  console.log('[tmwaccess] shutting down');
  await gw.stop();
  process.exit(0);
};
process.on('SIGINT', () => void shutdown());
process.on('SIGTERM', () => void shutdown());
