#!/usr/bin/env bash
# Set up the proxy-filter server on this Mac.
#
# Idempotent — re-running is safe. Performs:
#   1. brew install strongswan + mitmproxy (if not already present)
#   2. Mint server cert (if missing)
#   3. Symlink our ipsec.conf / ipsec.secrets / strongswan.conf into
#      /opt/homebrew/etc/, and our certs into /opt/homebrew/etc/ipsec.d/
#   4. Enable IP forwarding via sysctl
#   5. Enable pf and load our pf.conf
#   6. Install LaunchDaemons for strongSwan and mitmproxy
#   7. Bootstrap (load) those daemons
#
# Usage:
#   sudo ./setup-server-mac.sh
#
# Re-run after editing pf.conf or after `mint-server-cert.sh`.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "ERROR: must run as root (use 'sudo $0')" >&2
  exit 1
fi

# Resolve paths even though we're run via sudo (preserve $REAL_USER).
REAL_USER="${SUDO_USER:-$USER}"
REPO_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
SERVER_DIR="$REPO_DIR/proxy-filter/server"
BREW_PREFIX="$(sudo -u "$REAL_USER" brew --prefix)"
ETC="$BREW_PREFIX/etc"
LD_DIR="/Library/LaunchDaemons"

cd "$SERVER_DIR"

echo "============================================="
echo "proxy-filter server setup (macOS)"
echo "  repo:        $REPO_DIR"
echo "  brew prefix: $BREW_PREFIX"
echo "  acting user: $REAL_USER"
echo "============================================="

# ----- 1. Packages -----
need_install=()
sudo -u "$REAL_USER" brew list strongswan >/dev/null 2>&1 || need_install+=(strongswan)
sudo -u "$REAL_USER" brew list mitmproxy >/dev/null 2>&1 || need_install+=(mitmproxy)
if (( ${#need_install[@]} > 0 )); then
  echo
  echo ">>> Installing: ${need_install[*]}"
  sudo -u "$REAL_USER" brew install "${need_install[@]}"
fi

# ----- 2. CA + server cert -----
if [[ ! -f ssl/ca.crt || ! -f ssl/ca.key ]]; then
  echo "ERROR: missing CA at ssl/ca.crt / ca.key — run ssl/generate-ca.sh first" >&2
  exit 1
fi

if [[ ! -f ipsec/vpn-server.crt ]]; then
  echo
  echo ">>> Minting server cert"
  sudo -u "$REAL_USER" ./scripts/mint-server-cert.sh
fi

# ----- 3. strongSwan config wiring -----
echo
echo ">>> Wiring strongSwan config under $ETC"

mkdir -p "$ETC/ipsec.d/cacerts" "$ETC/ipsec.d/certs" "$ETC/ipsec.d/private"

# Copy CA into strongSwan's cacerts (strongSwan reads from here)
cp -f ssl/ca.crt "$ETC/ipsec.d/cacerts/ca.crt"

# Copy server cert + key
cp -f ipsec/vpn-server.crt "$ETC/ipsec.d/certs/vpn-server.crt"
cp -f ipsec/vpn-server.key "$ETC/ipsec.d/private/vpn-server.key"
chmod 600 "$ETC/ipsec.d/private/vpn-server.key"

# Render initial ipsec.conf (just the head; per-device conn blocks
# are added by the dashboard via reload-config.sh)
cp -f ipsec/ipsec.conf.head "$ETC/ipsec.conf"

# ipsec.secrets + strongswan.conf
cp -f ipsec/ipsec.secrets "$ETC/ipsec.secrets"
chmod 600 "$ETC/ipsec.secrets"

cp -f ipsec/strongswan.conf "$ETC/strongswan.conf"

# ----- 4. IP forwarding -----
echo
echo ">>> Enabling IPv4 forwarding"
sysctl -w net.inet.ip.forwarding=1 >/dev/null
# Persist across reboot via /etc/sysctl.conf
if ! grep -q "^net.inet.ip.forwarding" /etc/sysctl.conf 2>/dev/null; then
  echo "net.inet.ip.forwarding=1" >> /etc/sysctl.conf
fi

# ----- 5. pf rules -----
echo ">>> Loading pf rules"
EGRESS_IF="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
if [[ -z "$EGRESS_IF" ]]; then
  echo "ERROR: couldn't detect default-route interface" >&2
  exit 1
fi
echo "    egress interface: $EGRESS_IF"

PF_CONF_OUT="$SERVER_DIR/pf/pf.conf.live"
sed "s|{{EGRESS_IF}}|$EGRESS_IF|g" pf/pf.conf > "$PF_CONF_OUT"

# Validate the ruleset
pfctl -n -f "$PF_CONF_OUT"

# Enable pf if not already, then load our ruleset
pfctl -E 2>/dev/null || true
pfctl -F all -f "$PF_CONF_OUT"
echo "    pf ruleset loaded"

# ----- 6. LaunchDaemons -----
echo
echo ">>> Installing LaunchDaemons"

install_plist() {
  local src="$1" dst="$2"
  sed "s|{{REPO_DIR}}|$REPO_DIR|g" "$src" > "$dst"
  chown root:wheel "$dst"
  chmod 644 "$dst"
}

install_plist "$SERVER_DIR/ipsec/com.proxyfilter.strongswan.plist" \
              "$LD_DIR/com.proxyfilter.strongswan.plist"

# mitmproxy's confdir (where its CA lives) — bootstrap it
mkdir -p "$SERVER_DIR/mitm/conf"
cat ssl/ca.key ssl/ca.crt > "$SERVER_DIR/mitm/conf/mitmproxy-ca.pem"
chmod 600 "$SERVER_DIR/mitm/conf/mitmproxy-ca.pem"

install_plist "$SERVER_DIR/mitm/com.proxyfilter.mitm.plist" \
              "$LD_DIR/com.proxyfilter.mitm.plist"

# ----- 7. Bootstrap daemons -----
echo
echo ">>> Loading daemons"

bootstrap_or_reload() {
  local label="$1" plist="$2"
  if launchctl print "system/$label" >/dev/null 2>&1; then
    launchctl bootout system/"$label" 2>/dev/null || true
  fi
  launchctl bootstrap system "$plist"
  echo "    ✓ $label loaded"
}

bootstrap_or_reload com.proxyfilter.strongswan "$LD_DIR/com.proxyfilter.strongswan.plist"
sleep 1
bootstrap_or_reload com.proxyfilter.mitm        "$LD_DIR/com.proxyfilter.mitm.plist"

# ----- Status -----
echo
echo "============================================="
echo "✓ Setup complete. Status:"
echo
ipsec statusall 2>/dev/null | head -20 || echo "  (strongSwan starting up — check /tmp/proxyfilter-strongswan.log)"
echo
echo "Listening ports:"
lsof -nP -iUDP:500 -iUDP:4500 -iTCP:8080 -sTCP:LISTEN 2>/dev/null | tail -n +2 | awk '{print "  "$1" "$8" "$9}'
echo
echo "Logs:"
echo "  strongSwan:  tail -f /tmp/proxyfilter-strongswan.log"
echo "  mitmproxy:   tail -f /tmp/proxyfilter-mitm.log"
echo
echo "Next: in the dashboard, create a profile and download its .mobileconfig."
echo "      Install on a target Mac/iPhone."
echo "============================================="
