#!/usr/bin/env bash
# Set up the proxy-filter server on a fresh Ubuntu/Debian VPS.
#
# Idempotent — re-running is safe. Performs:
#   1. apt install strongswan + nftables; pipx install mitmproxy; install
#      a recent Node.js for the dashboard backend.
#   2. Create a 'proxyfilter' system user (runs mitmproxy + dashboard).
#   3. Mint server cert if missing (signed by our CA).
#   4. Wire ipsec.conf / ipsec.secrets / strongswan.conf into /etc/.
#   5. Enable IPv4 forwarding.
#   6. Load nftables ruleset (NAT, redirect TCP/80,443 → mitmproxy,
#      drop UDP/443 to kill QUIC).
#   7. Open firewall ports (UDP/500, UDP/4500, TCP for the dashboard).
#   8. Install systemd units for mitmproxy + dashboard backend.
#   9. systemctl enable + start everything.
#
# Usage:
#   PROXY_FILTER_VPN_HOST=filter.poel.ai \
#   PROXY_FILTER_VPN_HOST_2=89.167.100.228 \
#     sudo -E bash ./setup-server-vps.sh
#
# Environment variables:
#   PROXY_FILTER_VPN_HOST     (required) what devices' .mobileconfig
#                              will dial as RemoteAddress. Hostname or IP.
#   PROXY_FILTER_VPN_HOST_2   (optional) secondary SAN — useful when
#                              you want both a hostname and an IP to
#                              work (e.g. while DNS is still propagating).
#   DASHBOARD_PORT            (optional, default 5173) port the dashboard
#                              backend listens on. NOT exposed publicly
#                              by default — use a reverse proxy
#                              (Caddy/nginx) for HTTPS later.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: must run as root (use 'sudo -E bash $0')" >&2
  exit 1
fi

if [[ -z "${PROXY_FILTER_VPN_HOST:-}" ]]; then
  echo "ERROR: set PROXY_FILTER_VPN_HOST to the VPN's public hostname or IP." >&2
  echo "  e.g.  PROXY_FILTER_VPN_HOST=filter.poel.ai sudo -E bash $0" >&2
  exit 2
fi

DASHBOARD_PORT="${DASHBOARD_PORT:-5173}"
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SERVER_DIR="$REPO_DIR/proxy-filter/server"

echo "============================================="
echo "proxy-filter server setup (Linux/VPS)"
echo "  repo:           $REPO_DIR"
echo "  VPN host:       $PROXY_FILTER_VPN_HOST"
echo "  Secondary SAN:  ${PROXY_FILTER_VPN_HOST_2:-(none)}"
echo "  Dashboard port: $DASHBOARD_PORT"
echo "============================================="

# ----- 1. Packages -----
echo
echo ">>> Installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  strongswan strongswan-pki libstrongswan-extra-plugins libcharon-extra-plugins \
  nftables \
  python3 python3-pip pipx \
  curl gnupg ca-certificates \
  openssl

# Node.js 22 LTS via NodeSource (apt's version is too old)
if ! command -v node >/dev/null || [[ "$(node --version | sed 's/v//;s/\..*//')" -lt 22 ]]; then
  curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
  apt-get install -y -qq nodejs
fi

# mitmproxy via pipx (apt's version is years stale)
if ! command -v mitmdump >/dev/null; then
  pipx ensurepath 2>/dev/null || true
  PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install mitmproxy
fi

# ----- 2. proxyfilter user -----
if ! id proxyfilter >/dev/null 2>&1; then
  echo
  echo ">>> Creating proxyfilter system user"
  useradd --system --home "$SERVER_DIR" --shell /usr/sbin/nologin proxyfilter
fi

# ----- 3. CA + server cert -----
if [[ ! -f "$SERVER_DIR/ssl/ca.crt" || ! -f "$SERVER_DIR/ssl/ca.key" ]]; then
  echo
  echo ">>> Generating CA (no existing one found at $SERVER_DIR/ssl/)"
  ( cd "$SERVER_DIR/ssl" && bash ./generate-ca.sh )
else
  echo
  echo ">>> Using existing CA at $SERVER_DIR/ssl/"
fi

if [[ ! -f "$SERVER_DIR/ipsec/vpn-server.crt" ]]; then
  echo ">>> Minting server cert for $PROXY_FILTER_VPN_HOST"
  ( cd "$SERVER_DIR" && \
    PROXY_FILTER_VPN_HOST="$PROXY_FILTER_VPN_HOST" \
    PROXY_FILTER_VPN_HOST_2="${PROXY_FILTER_VPN_HOST_2:-}" \
    bash ./scripts/mint-server-cert.sh )
fi

# ----- 4. strongSwan config wiring -----
echo
echo ">>> Wiring strongSwan config under /etc/"

mkdir -p /etc/ipsec.d/cacerts /etc/ipsec.d/certs /etc/ipsec.d/private
cp -f "$SERVER_DIR/ssl/ca.crt" /etc/ipsec.d/cacerts/ca.crt
cp -f "$SERVER_DIR/ipsec/vpn-server.crt" /etc/ipsec.d/certs/vpn-server.crt
cp -f "$SERVER_DIR/ipsec/vpn-server.key" /etc/ipsec.d/private/vpn-server.key
chown root:root /etc/ipsec.d/private/vpn-server.key
chmod 600 /etc/ipsec.d/private/vpn-server.key

cp -f "$SERVER_DIR/ipsec/ipsec.conf.head" /etc/ipsec.conf
cp -f "$SERVER_DIR/ipsec/ipsec.secrets" /etc/ipsec.secrets
chmod 600 /etc/ipsec.secrets

# Don't replace strongswan.conf wholesale on Ubuntu — it has plugin
# loading paths that are distro-specific. Just append our charon block.
if ! grep -q "# proxy-filter" /etc/strongswan.conf; then
  cat >> /etc/strongswan.conf <<'EOF'

# proxy-filter
charon {
    install_routes = yes
    install_virtual_ip = yes
}
EOF
fi

# ----- 5. IP forwarding -----
echo
echo ">>> Enabling IPv4 forwarding"
cat > /etc/sysctl.d/99-proxy-filter.conf <<'EOF'
# proxy-filter
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 2
EOF
sysctl --system >/dev/null

# ----- 6. nftables rules -----
echo ">>> Loading nftables rules"
EGRESS_IF="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '/dev/ {for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')"
if [[ -z "$EGRESS_IF" ]]; then
  echo "ERROR: couldn't detect default-route interface" >&2
  exit 1
fi
echo "    egress interface: $EGRESS_IF"

mkdir -p /etc/nftables.d
sed "s|{{EGRESS_IF}}|$EGRESS_IF|g" "$SERVER_DIR/pf/nftables.conf" > /etc/nftables.d/proxy-filter.nft

# Make sure /etc/nftables.conf includes our drop-in
if ! grep -q "/etc/nftables.d/proxy-filter.nft" /etc/nftables.conf; then
  echo 'include "/etc/nftables.d/proxy-filter.nft"' >> /etc/nftables.conf
fi

systemctl enable nftables.service >/dev/null
nft -f /etc/nftables.conf

# ----- 7. Firewall (UFW if present, else iptables INPUT chain) -----
echo
echo ">>> Opening firewall ports (UDP/500, UDP/4500, TCP/$DASHBOARD_PORT)"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
  ufw allow 500/udp comment 'proxy-filter IKE' >/dev/null
  ufw allow 4500/udp comment 'proxy-filter NAT-T' >/dev/null
  ufw allow "$DASHBOARD_PORT/tcp" comment 'proxy-filter dashboard' >/dev/null
fi

# ----- 8. Sudoers entry so dashboard can reload strongSwan -----
echo
echo ">>> Installing sudoers entry"
cat > /etc/sudoers.d/proxyfilter <<EOF
# Allow proxyfilter user to reload strongSwan and install ipsec.conf
# without an interactive password prompt. Used by reload-config.sh.
proxyfilter ALL=(root) NOPASSWD: /usr/sbin/ipsec rereadall
proxyfilter ALL=(root) NOPASSWD: /usr/sbin/ipsec reload
proxyfilter ALL=(root) NOPASSWD: /usr/bin/install -m 644 /tmp/proxyfilter-ipsec.conf /etc/ipsec.conf
proxyfilter ALL=(root) NOPASSWD: /usr/bin/cp /tmp/proxyfilter-ipsec.conf /etc/ipsec.conf
EOF
chmod 440 /etc/sudoers.d/proxyfilter
visudo -cf /etc/sudoers.d/proxyfilter

# ----- 9. systemd units -----
echo
echo ">>> Installing systemd units"

# mitmproxy
sed "s|{{REPO_DIR}}|$REPO_DIR|g" "$SERVER_DIR/ipsec/proxyfilter-mitm.service" > /etc/systemd/system/proxyfilter-mitm.service

# dashboard backend
cat > /etc/systemd/system/proxyfilter-backend.service <<EOF
[Unit]
Description=proxy-filter dashboard backend (Node + SQLite)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=$REPO_DIR/backend
Environment=NODE_ENV=production
Environment=PROXY_HOST=$PROXY_FILTER_VPN_HOST
Environment=PORT=$DASHBOARD_PORT
EnvironmentFile=-$REPO_DIR/backend/.env
ExecStart=/usr/bin/node --no-warnings=ExperimentalWarning src/index.js
Restart=always
RestartSec=2
User=proxyfilter
Group=proxyfilter
StandardOutput=append:/var/log/proxyfilter-backend.log
StandardError=append:/var/log/proxyfilter-backend.log

[Install]
WantedBy=multi-user.target
EOF

# Make sure /var/log files exist with right ownership
touch /var/log/proxyfilter-mitm.log /var/log/proxyfilter-backend.log
chown proxyfilter:proxyfilter /var/log/proxyfilter-{mitm,backend}.log

# Make sure $REPO_DIR is writable by proxyfilter (it'll be writing
# vpn-allocations.json, rules.json, profiles/<id>/, ipsec.conf to /tmp).
chown -R proxyfilter:proxyfilter "$SERVER_DIR/profiles" 2>/dev/null || mkdir -p "$SERVER_DIR/profiles"
chown -R proxyfilter:proxyfilter "$SERVER_DIR"

# Backend deps
echo
echo ">>> Installing backend deps (npm install)"
( cd "$REPO_DIR/backend" && sudo -u proxyfilter npm install --silent --no-audit --no-fund )

# ----- 10. Bootstrap services -----
echo
echo ">>> Starting services"

systemctl daemon-reload
systemctl enable strongswan-starter.service >/dev/null 2>&1 || systemctl enable strongswan.service >/dev/null 2>&1 || true
systemctl restart strongswan-starter.service 2>/dev/null || systemctl restart strongswan.service || true

systemctl enable proxyfilter-mitm.service >/dev/null
systemctl restart proxyfilter-mitm.service

systemctl enable proxyfilter-backend.service >/dev/null
systemctl restart proxyfilter-backend.service

sleep 2

# ----- Status -----
echo
echo "============================================="
echo "✓ Setup complete"
echo
echo "Listening:"
ss -lnpu | awk '/:500\b|:4500\b/ {print "  "$0}' | head
ss -lnpt | awk "/:8080\b|:$DASHBOARD_PORT\b/ {print \"  \"$0}" | head
echo
echo "Logs:"
echo "  strongSwan:  journalctl -u strongswan-starter -f"
echo "  mitmproxy:   tail -f /var/log/proxyfilter-mitm.log"
echo "  dashboard:   tail -f /var/log/proxyfilter-backend.log"
echo
echo "Dashboard:    http://$PROXY_FILTER_VPN_HOST:$DASHBOARD_PORT/"
echo "  (Static frontend at admin/ — serve via 'python3 -m http.server'"
echo "   or behind Caddy/nginx with HTTPS. Backend API is on this port.)"
echo
echo "VPN endpoint: $PROXY_FILTER_VPN_HOST  (UDP/500 + UDP/4500)"
echo "============================================="
