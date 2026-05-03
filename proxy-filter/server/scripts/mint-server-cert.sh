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

# Default: bind cert to the Mac's default-route IP. Override via env var.
DEFAULT_IFACE="$(route -n get default 2>/dev/null | awk '/interface:/ {print $2}')"
DEFAULT_IP="$(ifconfig "$DEFAULT_IFACE" 2>/dev/null | awk '/inet / {print $2; exit}')"
VPN_HOST="${PROXY_FILTER_VPN_HOST:-${DEFAULT_IP:-127.0.0.1}}"

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
$(if [[ "$VPN_HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "IP.1 = $VPN_HOST"
  echo "DNS.1 = vpn.proxyfilter.local"
else
  echo "DNS.1 = $VPN_HOST"
  [[ -n "$DEFAULT_IP" ]] && echo "IP.1 = $DEFAULT_IP"
fi)
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
echo
echo "✓ wrote:"
echo "    $OUT_KEY  ($(stat -f '%z' "$OUT_KEY") bytes, mode 600)"
echo "    $OUT_CRT  ($(stat -f '%z' "$OUT_CRT") bytes)"
echo
echo "--- cert summary ---"
openssl x509 -in "$OUT_CRT" -noout -subject -issuer -dates
echo
echo "--- SANs ---"
openssl x509 -in "$OUT_CRT" -noout -ext subjectAltName | tail -n +2
echo
echo "--- EKU (must include 1.3.6.1.5.5.8.2.2 for Apple IKEv2) ---"
openssl x509 -in "$OUT_CRT" -noout -ext extendedKeyUsage | tail -n +2
