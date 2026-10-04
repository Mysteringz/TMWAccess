#!/bin/sh
# Install TMWAccess as a per-user launchd agent on macOS (the dev launchpad).
# Also installs the userspace Tailscale client it tunnels through when the
# Mac's VPN blocks the tailnet (skip with NO_USERSPACE_TS=1).
set -e
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[ -f "$ROOT/.env" ] || { echo "create .env from .env.example first"; exit 1; }
chmod 600 "$ROOT/.env"
(cd "$ROOT" && npm ci && npm run build)
NODE="$(command -v node)"
"$NODE" -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 22 ? 0 : 1)' || { echo "Node 22 or newer is required"; exit 1; }
# plist text must escape XML metacharacters in user-controlled home/repo paths.
xml() { printf '%s' "$1" | sed 's/\&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }
PLIST_ROOT="$(xml "$ROOT")"
PLIST_NODE="$(xml "$NODE")"
PLIST_HOME="$(xml "$HOME")"
LA="$HOME/Library/LaunchAgents"; mkdir -p "$LA" "$HOME/Library/Logs"
if [ -z "$NO_USERSPACE_TS" ]; then
  TSD="$(command -v tailscaled || echo /opt/homebrew/bin/tailscaled)"
  PLIST_TSD="$(xml "$TSD")"
  cat > "$LA/com.tmnode.userspace-tailscale.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.tmnode.userspace-tailscale</string>
  <key>ProgramArguments</key><array>
    <string>$PLIST_TSD</string><string>--tun=userspace-networking</string>
    <string>--socks5-server=localhost:1055</string><string>--outbound-http-proxy-listen=localhost:1056</string>
    <string>--statedir=$PLIST_HOME/.tmedge-tailscale</string><string>--socket=$PLIST_HOME/.tmedge-tailscale/tailscaled.sock</string><string>--port=0</string>
  </array>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$PLIST_HOME/Library/Logs/userspace-tailscale.log</string>
  <key>StandardErrorPath</key><string>$PLIST_HOME/Library/Logs/userspace-tailscale.log</string>
</dict></plist>
PL
fi
cat > "$LA/com.tmnode.tmwaccess.plist" <<PL
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.tmnode.tmwaccess</string>
  <key>ProgramArguments</key><array>
    <string>$PLIST_NODE</string><string>--env-file=$PLIST_ROOT/.env</string><string>$PLIST_ROOT/dist/src/main.js</string>
  </array>
  <key>WorkingDirectory</key><string>$PLIST_ROOT</string>
  <key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$PLIST_HOME/Library/Logs/tmwaccess.log</string>
  <key>StandardErrorPath</key><string>$PLIST_HOME/Library/Logs/tmwaccess.log</string>
</dict></plist>
PL
for p in com.tmnode.userspace-tailscale com.tmnode.tmwaccess; do
  [ -f "$LA/$p.plist" ] || continue
  launchctl bootout "gui/$(id -u)/$p" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$LA/$p.plist"
done
echo "installed. logs: ~/Library/Logs/tmwaccess.log   status: curl -s 127.0.0.1:5280/"
echo "remove:   launchctl bootout gui/$(id -u)/com.tmnode.tmwaccess; rm ~/Library/LaunchAgents/com.tmnode.tmwaccess.plist"
