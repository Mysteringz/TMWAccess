# TMWAccess in Docker

The `tmwaccess` image builds on any machine with Docker, on x86-64 or ARM. It
relays TMnode UDP packets from a site's LAN to TMedge over one outbound,
authenticated link. There are no runtime dependencies beyond Node, which the
image carries.

## Install

### 1. Prerequisites

- **A Linux host on the same LAN as the TMnodes** (a mini PC, NUC or Pi), with
  Docker Engine 24+ and the Compose plugin.
- **Outbound internet access** to at least one route to TMedge. HTTPS (443)
  is enough for the Cloudflare route. The site needs no inbound ports.

Docker Desktop on macOS or Windows is fine for testing, but not for a site; see
[Networking](#networking).

### 2. Configure

```sh
git clone <this repo> TMWAccess && cd TMWAccess
cp .env.example .env
```

| Variable | What it is |
|---|---|
| `GATEWAY_ID` | Name shown on the TMedge console, unique per gateway (e.g. `esanhouse-nuc`) |
| `EDGE` | Routes to TMedge, in preference order, e.g. `wss://gw.hkumyseat.com/tmgw,tcp://100.106.57.2:5210` |
| `TMGW_TOKEN` | Same value as `TMGW_TOKEN` in TMedge's `.env` |
| `CF_ACCESS_CLIENT_ID` / `_SECRET` | Cloudflare Access service token for the `wss://` route |
| `NODE_CIDRS` | Only nodes on these networks are relayed (default `192.168.0.0/16`) |
| `FAILBACK_S`, `QUEUE_MAX`, `STATUS_PORT` | See the comments in `.env.example` |

A `tcp://` route to a Tailscale address needs Tailscale on the host. Host
networking lets the container use it directly.

### 3. Build and start

```sh
docker compose up -d --build
docker compose logs -f          # expect: "link up to edge … via wss://…"
docker compose ps               # "healthy" once the link to TMedge is up
curl -s 127.0.0.1:5280/         # status JSON: link state, route, nodes seen, counters
```

Then point each TMnode at the host's LAN address over USB serial:
`set edges <host LAN IP>`, `save`, `reboot`. On the TMedge console the node
shows up with the address `gw:<GATEWAY_ID>|<node ip>:<port>`.

### 4. Other architectures and registries

```sh
docker buildx build --platform linux/amd64,linux/arm64 -t <registry>/tmwaccess:1.0 --push .
```

On the target, set `image: <registry>/tmwaccess:1.0`, then run
`docker compose pull && docker compose up -d`.

### Operate

```sh
docker compose logs -f                        # link changes, relays, drops
git pull && docker compose up -d --build      # update
docker compose down                           # stop (the gateway keeps no state)
```

Run only one TMWAccess per host: Docker or the systemd service
(`deploy/install-ubuntu.sh`), not both, because both listen on UDP 5200.

## How it works

### The image

A two-stage build on `node:22-alpine`. The build stage compiles the
TypeScript. The runtime stage keeps only `dist/src` and `package.json`, since
the gateway uses only Node built-ins, and runs as the unprivileged `node`
user. The container's **healthcheck** reads the status endpoint and passes
only when the link to TMedge is `up`. "Unhealthy" therefore means the nodes'
packets are being queued rather than delivered.

### The relay

```
TMnodes ──UDP 5200──► TMWAccess ══ one outbound link (TMGW v1) ══► TMedge :5210
TMnodes ◄─UDP 5201─── TMWAccess ◄═ commands on the same link ════ TMedge
```

1. **Uplink.** Each datagram from a node in `NODE_CIDRS` that looks like a
   TMnode packet (magic `TM`, version, sane length) is wrapped with the
   node's address and sent up the link. It is not decrypted, re-signed or
   altered. The gateway holds no node keys, and TMedge verifies every
   packet's HMAC and replay counter itself. A compromised gateway therefore
   can't forge occupancy.
2. **Link.** A TMGW v1 session: length-prefixed frames. It opens with a HELLO
   carrying an HMAC of `TMGW_TOKEN` (with a timestamp and nonce, so it can't
   be replayed). The same frames travel over raw TCP or inside a WebSocket,
   which is how the link crosses Cloudflare Tunnel on port 443.
3. **Routes and failover.** `EDGE` is tried in order, and the first route
   that completes the handshake carries the link. While on a fallback, the
   preferred route is retried every `FAILBACK_S`. The link is treated as dead
   after 45 s of silence and reconnects with backoff. In the meantime,
   datagrams wait in a bounded queue (the oldest are dropped past
   `QUEUE_MAX`).
4. **Downlink.** TMedge sends a node command (identify, reboot, config) down
   the link. The gateway forwards it only if it is a TM COMMAND, and only to
   a node it has already heard from, at that node's address and command port.
   It is never an open relay into the LAN.

### Networking

The compose file uses **`network_mode: host`**, and on Linux that's what you
want. The gateway must see each node's real LAN source address, for two
reasons: `NODE_CIDRS` filters on it, and commands are sent back to it.

Docker Desktop's bridge network hides that address behind NAT; every node
appears to come from something like `172.17.0.1`. The alternative in
`docker-compose.yml` (publish `5200:5200/udp`, widen `NODE_CIDRS`) does get
uplink through, but console commands can't reach the nodes. It is good for a
bench test only.

### Security

- It is outbound only. The only listening socket is UDP 5200 for the nodes,
  and the status page is bound to 127.0.0.1.
- Secrets (`TMGW_TOKEN`, the Cloudflare Access token) come only from `.env`.
  That file is git-ignored and `.dockerignore`d, so it is never in the image.
