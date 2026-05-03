#!/usr/bin/env bash
# Mint the IKEv2 SERVER certificate, signed by our existing CA. One-time
# operation — re-run only if you change PROXY_FILTER_VPN_HOST.
#
# Output:
#   server/ipsec/vpn-server.key   — server private key
#   server/ipsec/vpn-server.crt   — server cert signed by our CA
#
# The server cert needs:
#   - subject CN matching what the device's profile says (RemoteIdentifier)
#   - subjectAltName with iPAddress (for IP-based dial) and dNSName
#   - extKeyUsage: serverAuth + the Apple "ikeIntermediate" OID
#     (1.3.6.1.5.5.8.2.2). Apple's IKEv2 client requires the latter or
#     it rejects the cert.

set -euo pipefail
cd "$(dirname "$0")/.."

CA_CRT="ssl/ca.crt"
CA_KEY="ssl/ca.key"
OUT_KEY="ipsec/vpn-server.key"
OUT_CRT="ipsec/vpn-server.crt"

# Bind the cert to the host (hostname or IP) the device's profile will
# dial. Override via PROXY_FILTER_VPN_HOST env var. If not set:
#   - on macOS we auto-detect the default-route IP (dev convenience)
#   - on Linux we leave it unset and require the env var (production)
if [[ -z "${PROXY_FILTER_VPN_HOST:-}" ]]; then
  if [[ "$(uname -s)" == "Darwin" ]]; then
    DEFAULT_IFACE="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
    DEFAULT_IP="$(ifconfig "$DEFAULT_IFACE" 2>/dev/null | awk '/inet / {print $2; exit}')"
    VPN_HOST="${DEFAULT_IP:-127.0.0.1}"
  else
    echo "ERROR: set PROXY_FILTER_VPN_HOST to the public hostname (or IP)" >&2
    echo "       devices will use to dial the VPN." >&2
    echo "       e.g.  PROXY_FILTER_VPN_HOST=filter.poel.ai $0" >&2
    exit 2
  fi
else
  VPN_HOST="$PROXY_FILTER_VPN_HOST"
fi

# Optional secondary SAN — useful when you have BOTH a hostname and a
# raw IP and want either one to work as RemoteAddress in the .mobileconfig.
SECONDARY_SAN="${PROXY_FILTER_VPN_HOST_2:-}"

if [[ ! -f "$CA_CRT" || ! -f "$CA_KEY" ]]; then
  echo "ERROR: CA missing at $CA_CRT / $CA_KEY" >&2
  echo "Run: cd ssl && ./generate-ca.sh" >&2
  exit 1
fi

echo "Minting VPN server cert for: $VPN_HOST"

# 1. Server private key
openssl genrsa -out "$OUT_KEY" 2048 2>/dev/null
chmod 600 "$OUT_KEY"

# 2. CSR + extensions config
TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_CONF" "$TMP_CONF.csr" "$TMP_CONF.srl"' EXIT

cat > "$TMP_CONF" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = $VPN_HOST

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, 1.3.6.1.5.5.8.2.2
subjectAltName = @san

[san]
$(
ip_count=0; dns_count=0
add_san() {
  local v="$1"
  if [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    ip_count=$((ip_count+1)); echo "IP.$ip_count = $v"
  else
    dns_count=$((dns_count+1)); echo "DNS.$dns_count = $v"
  fi
}
add_san "$VPN_HOST"
[[ -n "$SECONDARY_SAN" && "$SECONDARY_SAN" != "$VPN_HOST" ]] && add_san "$SECONDARY_SAN"
)
EOF

# 3. CSR
openssl req -new -key "$OUT_KEY" -out "$TMP_CONF.csr" -config "$TMP_CONF" 2>/dev/null

# 4. Sign with our CA
openssl x509 -req -in "$TMP_CONF.csr" \
  -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$OUT_CRT" \
  -days 1825 \
  -extfile "$TMP_CONF" -extensions v3_req \
  -sha256 2>/dev/null

# 5. Verify
sz() { wc -c < "$1" | tr -d ' '; }
echo
echo "✓ wrote:"
echo "    $OUT_KEY  ($(sz "$OUT_KEY") bytes, mode 600)"
echo "    $OUT_CRT  ($(sz "$OUT_CRT") bytes)"
echo
echo "--- cert summary ---"
openssl x509 -in "$OUT_CRT" -noout -subject -issuer -dates
echo
echo "--- SANs ---"
openssl x509 -in "$OUT_CRT" -noout -ext subjectAltName | tail -n +2
echo
echo "--- EKU (must include 1.3.6.1.5.5.8.2.2 for Apple IKEv2) ---"
openssl x509 -in "$OUT_CRT" -noout -ext extendedKeyUsage | tail -n +2
