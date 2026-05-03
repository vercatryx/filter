#!/usr/bin/env bash
# Mint a per-device IKEv2 client certificate signed by our CA, plus
# the PKCS#12 bundle that gets embedded in the device's .mobileconfig.
#
# Usage:
#   ./mint-device-cert.sh <user_id> <p12-password> [outdir]
#
# Outputs (under outdir, default ../profiles/<user_id>/):
#   <user_id>.key   — client private key
#   <user_id>.crt   — client cert signed by our CA
#   <user_id>.p12   — PKCS#12 bundle (key + cert + CA chain), encrypted
#                      with <p12-password>; this is what the dashboard
#                      embeds in the .mobileconfig
#
# The dashboard calls this once per profile creation. The PKCS#12 password
# is also stored in the DB so the dashboard can re-emit the .mobileconfig
# with the same password later (re-download).

set -euo pipefail
cd "$(dirname "$0")/.."

USER_ID="${1:?Usage: $0 <user_id> <p12-password> [outdir]}"
P12_PASS="${2:?Usage: $0 <user_id> <p12-password> [outdir]}"
OUT_DIR="${3:-profiles/$USER_ID}"

if [[ ! "$USER_ID" =~ ^[a-zA-Z0-9_-]{1,64}$ ]]; then
  echo "ERROR: user_id must be alphanumeric/-/_, 1–64 chars" >&2
  exit 2
fi

CA_CRT="ssl/ca.crt"
CA_KEY="ssl/ca.key"

if [[ ! -f "$CA_CRT" || ! -f "$CA_KEY" ]]; then
  echo "ERROR: CA missing. Run ssl/generate-ca.sh first." >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
KEY="$OUT_DIR/$USER_ID.key"
CRT="$OUT_DIR/$USER_ID.crt"
P12="$OUT_DIR/$USER_ID.p12"

# 1. Client private key
openssl genrsa -out "$KEY" 2048 2>/dev/null
chmod 600 "$KEY"

# 2. CSR + extension config
TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_CONF" "$TMP_CONF.csr" "$TMP_CONF.srl"' EXIT

cat > "$TMP_CONF" <<EOF
[req]
distinguished_name = dn
req_extensions = v3_req
prompt = no

[dn]
CN = $USER_ID

[v3_req]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth, 1.3.6.1.5.5.8.2.2
subjectAltName = DNS:$USER_ID
EOF

# 3. CSR
openssl req -new -key "$KEY" -out "$TMP_CONF.csr" -config "$TMP_CONF" 2>/dev/null

# 4. Sign
openssl x509 -req -in "$TMP_CONF.csr" \
  -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CRT" \
  -days 1825 \
  -extfile "$TMP_CONF" -extensions v3_req \
  -sha256 2>/dev/null

# 5. PKCS#12 bundle (3DES — iOS PKCS#12 import is happiest with 3DES;
#    AES bundles import on macOS but iOS sometimes balks).
openssl pkcs12 -export \
  -inkey "$KEY" \
  -in "$CRT" \
  -certfile "$CA_CRT" \
  -name "$USER_ID" \
  -passout "pass:$P12_PASS" \
  -out "$P12" \
  -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES \
  -macalg sha1 2>/dev/null

chmod 600 "$P12"

# 6. Output the on-disk path so the caller (dashboard) can read the P12
echo "OK $P12"
