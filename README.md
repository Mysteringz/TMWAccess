# TMWAccess

TMWAccess connects thermal nodes on a site's Wi-Fi network to TMedge. It receives UDP telemetry and forwards the original bytes over one authenticated outbound connection. Commands and firmware transfers return through the same connection.

Routes can use secure WebSockets or TCP, with optional SOCKS5 proxying for TCP. The gateway holds no sensor signing keys; TMedge authenticates sensor packets.

## Interesting techniques

- **Transport-independent framing.** The [TMGW protocol implementation](src/gwlink.ts) carries the same length-prefixed frames over TCP and WebSockets. Its incremental reader handles split and combined stream chunks.
- **Route failover and return.** The [gateway](src/gateway.ts) tries routes in order, reconnects with exponential backoff, and periodically checks whether a preferred route has recovered.
- **Bounded outage buffering.** Disconnected telemetry queues drop the oldest packets when full. Connected links also enforce an outgoing-byte limit so stalled transport cannot consume memory indefinitely.
- **Restricted downlinks.** Commands and OTA requests are forwarded only to previously observed nodes at their recorded LAN addresses.
- **Network allowlists.** UDP reception and firmware downloads use Node's [BlockList](https://nodejs.org/api/net.html#class-netblocklist) to restrict access to configured sensor networks.
- **Content-checked firmware caching.** The [image store](src/images.ts) assembles firmware chunks in memory and verifies SHA-256 before serving them. The sensor independently checks the image against its authenticated update request.
- **A small SOCKS5 client.** The [proxy implementation](src/socks5.ts) handles CONNECT negotiation directly using Node sockets and the [SOCKS5 specification](https://www.rfc-editor.org/rfc/rfc1928).
- **Built-in WebSocket transport.** The [route adapter](src/transport.ts) uses Node's native [WebSocket API](https://nodejs.org/api/globals.html#class-websocket), including buffered-byte monitoring. MDN explains the corresponding [WebSocket interface](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket).

## Technologies and integrations

- **No third-party runtime dependencies.** [Node.js](https://nodejs.org/) provides UDP, TCP, HTTP, cryptography, buffers, and WebSockets.
- [TypeScript](https://www.typescriptlang.org/) provides strict checking and explicit handling of possibly missing array entries.
- Optional [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/) and [Tailscale](https://tailscale.com/docs) routes connect sites without exposing an inbound gateway port.
- Deployment definitions support Docker, Linux systemd, and macOS launchd. Container details are documented in [DOCKER.md](DOCKER.md).

## Project structure

```text
TMWAccess/
├── .github/workflows/
├── deploy/
├── src/
│   └── tools/
├── test/
├── .env.example
├── DOCKER.md
├── Dockerfile
├── README.md
├── docker-compose.yml
├── package.json
└── tsconfig.json
```

- [src/](src/) contains configuration, telemetry relay, framing, transport adapters, proxy negotiation, and firmware caching.
- [src/tools/](src/tools/) contains the cross-check against TMedge's real gateway server.
- [deploy/](deploy/) contains native service installers and definitions.
- [test/](test/) covers relay rules, route recovery, buffering, and firmware integrity.

This service has no browser interface, image assets, or font dependencies. Its tests use a fake edge, while the cross-check exercises real TCP and WebSocket sessions with TMedge.
