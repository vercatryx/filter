#!/usr/bin/env bash
# Part of proxy-filter module — see /proxy-filter/README.md
#
# Generates a self-signed Certificate Authority used by Squid to sign
# per-host certificates during SSL inspection. The resulting ca.crt must be
# installed as a trusted root on every device that connects through the
# proxy (the .mobileconfig profile does this for macOS/iOS).
#
# WARNING: ca.key is the master key for inspecting all traffic. Anyone who
# has it can issue certs trusted by every device the proxy serves. Keep it
# offline, never commit it, restrict file permissions.

set -euo pipefail

cd "$(dirname "$0")"

if [[ -f ca.crt || -f ca.key ]]; then
  echo "ca.crt or ca.key already exists in $(pwd)."
  echo "Refusing to overwrite — delete them manually if you really want to regenerate."
  exit 1
fi

echo "Generating 4096-bit RSA private key (ca.key)..."
openssl genrsa -out ca.key 4096

echo "Generating self-signed CA certificate (ca.crt) valid for 3650 days..."
openssl req -x509 -new -nodes \
  -key ca.key \
  -sha256 -days 3650 \
  -out ca.crt \
  -subj "/CN=Proxy Filter CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

chmod 600 ca.key
chmod 644 ca.crt

echo
echo "✓ Done. Files written:"
echo "    $(pwd)/ca.crt   (install this as a trusted root on devices)"
echo "    $(pwd)/ca.key   (KEEP SECRET — never commit, never share)"
echo
echo "Next steps:"
echo "  1. cd ../ && docker-compose up -d   # start Squid"
echo "  2. Use generate-profile.js to embed ca.crt into a .mobileconfig"
