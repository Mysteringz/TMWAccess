# TMWAccess — notes for AI coding sessions

Wi-Fi access gateway: TMnode UDP → one outbound TMGW link → TMedge. Pairs with
`../TMedge` (edge) and `../TMsense` (firmware, formerly TMnode).

- `src/gwlink.ts` mirrors `TMedge/src/edge/gwlink.ts` (the source of truth). Change both
  together, then run `npm run crosscheck` (it drives TMedge's real server).
- The gateway never holds or checks node keys. Keep it that way: it relays bytes
  unchanged, and TMedge is the only judge.
- Never relay into the LAN anything except a TM COMMAND, to a node already heard from,
  at the address it was heard from.
- Runtime deps: none (node built-ins only). Node ≥ 22. Must run on macOS (arm64) and Ubuntu.
- `.env` holds TMGW_TOKEN and is git-ignored. Never print it.
- The dev Mac's NordVPN blocks tailnet traffic, so there TMWAccess uses `SOCKS5=127.0.0.1:1055`
  (the userspace Tailscale client installed by `deploy/install-macos.sh`).
