#!/usr/bin/env bash
# Regenerate /opt/homebrew/etc/ipsec.conf with one `conn` block per
# profile, copy each device's PKCS#12-companion key/cert into
# strongSwan's directories, and reload charon. Called by the dashboard
# after profile create / delete.
#
# Reads:
#   server/profiles/*/      — directories named by user_id
#                              each containing <user_id>.{key,crt,p12}
#   server/vpn-allocations.json   — { "<user_id>": "10.10.10.7", ... }
#
# Writes:
#   /opt/homebrew/etc/ipsec.conf  (rewrites the whole file)
#   /opt/homebrew/etc/ipsec.d/certs/<user_id>.crt  (so charon can verify)
#   server/rules.json   — { "10.10.10.7": {user_id, blocklist, allowlist}, ... }
#
# This script is invoked WITHOUT sudo by the dashboard but the final
# `ipsec rereadall` requires sudo. We rely on a NOPASSWD sudoers entry
# for that one command (installed by setup-server-mac.sh).

set -euo pipefail
cd "$(dirname "$0")/.."   # into server/

REAL_USER="${SUDO_USER:-$USER}"
BREW_PREFIX="$(brew --prefix 2>/dev/null || echo /opt/homebrew)"
ETC="$BREW_PREFIX/etc"
ALLOC_FILE="vpn-allocations.json"
RULES_FILE="rules.json"

# ----- Build ipsec.conf -----
# Start with the head template then append per-device conn blocks.
TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_CONF"' EXIT

cp ipsec/ipsec.conf.head "$TMP_CONF"

# allocations.json maps user_id -> ip
ALLOCS="${ALLOC_FILE}"
[[ -f "$ALLOCS" ]] || echo "{}" > "$ALLOCS"

python3 - "$ALLOCS" "$TMP_CONF" "$(pwd)/profiles" <<'PY'
import json, os, sys
allocs_path, conf_path, profiles_dir = sys.argv[1], sys.argv[2], sys.argv[3]
allocs = json.load(open(allocs_path))
with open(conf_path, "a") as f:
    for user_id, ip in sorted(allocs.items()):
        crt = os.path.join(profiles_dir, user_id, f"{user_id}.crt")
        if not os.path.exists(crt):
            continue
        f.write(f"\nconn {user_id}\n")
        f.write(f"    rightid = \"CN={user_id}\"\n")
        f.write(f"    rightsourceip = {ip}/32\n")
PY

# ----- Install certs into ipsec.d/certs/ so charon can find them -----
# (Each per-device cert needs to be there for path validation.)
mkdir -p "$ETC/ipsec.d/certs"
for d in profiles/*/; do
  uid="$(basename "$d")"
  if [[ -f "$d$uid.crt" ]]; then
    cp -f "$d$uid.crt" "$ETC/ipsec.d/certs/$uid.crt"
  fi
done

# ----- Atomically swap into place -----
sudo install -m 644 "$TMP_CONF" "$ETC/ipsec.conf"

# ----- Reload charon (NOPASSWD sudoers entry installed by setup script) -----
sudo /opt/homebrew/sbin/ipsec rereadall 2>/dev/null || true
sudo /opt/homebrew/sbin/ipsec reload 2>/dev/null || true

# ----- Build rules.json (consumed by mitmproxy filter_addon.py) -----
python3 - "$ALLOCS" "$RULES_FILE" "$(pwd)" <<'PY'
import json, os, sys
allocs_path, rules_path, server_dir = sys.argv[1], sys.argv[2], sys.argv[3]
allocs = json.load(open(allocs_path))

def read_list(path):
    if not os.path.exists(path):
        return []
    out = []
    for line in open(path):
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out

rules = {}
for user_id, ip in allocs.items():
    pdir = os.path.join(server_dir, "profiles", user_id)
    rules[ip] = {
        "user_id": user_id,
        "blocklist": read_list(os.path.join(pdir, "blocklist.txt")),
        "allowlist": read_list(os.path.join(pdir, "allowlist.txt")),
    }
with open(rules_path, "w") as f:
    json.dump(rules, f, indent=2)
PY

echo "✓ reloaded — $(python3 -c "import json; print(len(json.load(open('$ALLOC_FILE'))))" 2>/dev/null) profile(s) configured"
