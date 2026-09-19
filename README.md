# TMWAccess

**Wi-Fi access gateway for TMnodes.** TMnodes on a site's Wi-Fi send their
packets to TMWAccess, which relays them to **TMedge** over one outbound,
authenticated TCP link. Commands from TMedge come back the same way.

```
TMnodes --UDP 5200 (site LAN)--> TMWAccess ==TCP, TMGW v1==> TMedge :5210 (Proxmox VM)
TMnodes <--UDP 5201------------- TMWAccess <==commands, same link== TMedge
```

- **Outbound only.** The site needs no inbound port, so it works behind NAT, on
  a campus network, or through a SOCKS5 proxy.
- **Holds no node keys.** It checks that a datagram looks like a TMnode
  packet and relays it byte for byte. TMedge verifies each node's HMAC, so a
  compromised gateway can't forge occupancy.
- **Not an open relay.** It sends only TMnode COMMANDs, only to nodes it has
  heard from, and only at the address it heard them from.
- **Survives outages.** While the edge is unreachable it queues up to
  `QUEUE_MAX` datagrams (dropping the oldest first), reconnects with backoff,
  and flushes the queue when the link returns. It also treats 45 s of silence
  from the edge as a dead link.

**Routes.** `EDGE` lists routes in order: `wss://gw.hkumyseat.com/tmgw` (WebSocket
over Cloudflare Tunnel, which needs only outbound HTTPS and carries a Cloudflare
Access service token) and `tcp://100.106.57.2:5210` (Tailscale). The first
route that works carries the link. While on a fallback, the preferred route is
retried every `FAILBACK_S` seconds and taken back as soon as it answers; the
edge swaps sessions with no gap.

TMLAccess (a LoRa gateway) will use the same link protocol, TMGW, which is
defined in `TMedge/src/edge/gwlink.ts` and mirrored in `src/gwlink.ts`.

## Run

Node ≥ 22, no runtime dependencies.

```sh
cp .env.example .env      # GATEWAY_ID, EDGE, TMGW_TOKEN (same as TMedge's), NODE_CIDRS
npm ci && npm run build && npm start
curl -s 127.0.0.1:5280/   # status: link state, nodes seen, counters
```

- **macOS (dev launchpad):** `deploy/install-macos.sh` installs launchd agents
  for TMWAccess and, on a Mac whose VPN blocks the tailnet, a userspace
  Tailscale client that TMWAccess tunnels through (`SOCKS5=127.0.0.1:1055`).
- **Ubuntu (permanent mini PC):** `deploy/install-ubuntu.sh` installs to
  `/opt/tmwaccess` with a systemd unit (`tmwaccess`). With kernel Tailscale on
  the mini PC, leave `SOCKS5` unset.

## Point nodes at it

A TMnode sends to the edges set on it over USB serial:

```
set edges <gateway LAN IP>
save
reboot
```

The dev Mac is `192.168.0.179`. That's the node's default, so the live
"Above M3" node needed no change. When the mini PC takes over, give it a
fixed LAN address and re-point the nodes.

## Tests

```sh
npm test            # 8 claims, against a fake edge (incl. failover and failback)
npm run crosscheck  # against the real TMedge (../TMedge, built), over TCP and WebSocket: auth, relay, forged packet, commands
```
