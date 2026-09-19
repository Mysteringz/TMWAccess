#!/bin/sh
# Install TMWAccess on Ubuntu (run from the repo root as a sudo-capable user).
# Needs Node >= 22 at /usr/local/bin/node and a filled-in .env in the repo root.
set -e
[ -f .env ] || { echo "create .env from .env.example first"; exit 1; }
command -v node >/dev/null || { echo "install Node 22 first (https://nodejs.org or NodeSource)"; exit 1; }
npm ci && npm run build && npm prune --omit=dev
sudo useradd --system --home /opt/tmwaccess --shell /usr/sbin/nologin tmwaccess 2>/dev/null || true
sudo mkdir -p /opt/tmwaccess
sudo rsync -a --delete --exclude .git ./ /opt/tmwaccess/
sudo chown -R root:root /opt/tmwaccess && sudo chown tmwaccess:tmwaccess /opt/tmwaccess/.env && sudo chmod 600 /opt/tmwaccess/.env
[ -x /usr/local/bin/node ] || sudo ln -sf "$(command -v node)" /usr/local/bin/node
sudo cp deploy/tmwaccess.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now tmwaccess
# If ufw is active, let the site's nodes reach UDP 5200.
if command -v ufw >/dev/null && sudo ufw status | grep -q active; then sudo ufw allow from 192.168.0.0/16 to any port 5200 proto udp; fi
sleep 3; systemctl --no-pager status tmwaccess | head -5
echo "logs: journalctl -u tmwaccess -f    status: curl -s 127.0.0.1:5280/"
