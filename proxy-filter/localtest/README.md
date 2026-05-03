# proxy-filter — local test (single Mac, no server, no domain)

This collapses the "VPN + transparent MITM + your CA" architecture onto
one Mac so you can verify it works before investing in a VPS.
mitmproxy plays both roles: WireGuard tunnel endpoint AND the SSL
inspector. Your Mac connects to mitmproxy over a local WireGuard
tunnel, all your traffic flows through it, and it filters using rules
from the existing dashboard.

```
Your Mac            local WireGuard          mitmdump (one process)
┌─────────────┐    127.0.0.1:51820  ┌──────────────────────────────┐
│ all apps    │ ─────────────────── │  WireGuard endpoint          │
│ all browsers│                     │      ↓                       │
│ all UDP+TCP │                     │  decrypt + per-host MITM     │
│             │                     │  (using server/ssl/ca.crt)   │
│             │                     │      ↓                       │
│             │                     │  filter_addon.py             │
│             │                     │   reads server/profiles/*    │
│             │                     │   reads server/blocklists/*  │
│             │                     │      ↓                       │
│             │                     │  ALLOW → out to internet     │
│             │                     │  BLOCK → 🛡️ block page (HTTPS) │
│             │                     │  PINNED → tunnel through     │
└─────────────┘                     └──────────────────────────────┘
```

The CA is reused as-is — same `proxy-filter/server/ssl/ca.crt` we
generated at the start of this project. The rule files
(`server/blocklists/adult.txt`, `server/profiles/<id>/blocklist.txt`,
`server/profiles/<id>/allowlist.txt`) are reused as-is. The dashboard
keeps managing them. The only new thing is the proxy engine.

---

## One-time install

```bash
brew install mitmproxy           # the proxy
brew install wireguard-tools     # gives us 'wg pubkey' and 'wg-quick' CLI
```

The CLI alone is enough; you don't need a GUI app.

If you want the GUI WireGuard app for nicer toggling, install it from the
**Mac App Store** (search "WireGuard" — published by *WireGuard Development
Team*). **Do NOT run `brew install --cask wireguard`** — that name doesn't
exist in Homebrew and `brew` will fuzzy-match to "Wirecast", which is
unrelated streaming software. The Mac App Store is the only legit GUI source.

You also need `proxy-filter/server/ssl/ca.crt` and `ca.key` to exist.
If they don't:

```bash
cd proxy-filter/server/ssl && ./generate-ca.sh
```

---

## Run it (profile install — recommended)

This is the same pattern as the production deployment: install a
`.mobileconfig` once, the system handles VPN, CA trust, settings
lockdown, and removal protection.

### One-time install

Install **WireGuard** from the **Mac App Store** (free, published by
*WireGuard Development Team*). The .mobileconfig delegates the VPN to
this app via Apple's standard Network Extension provider. **Do not
`brew install --cask wireguard`** — that name doesn't exist in
Homebrew, and `brew` will fuzzy-match to "Wirecast" (a different
unrelated product).

### Start the proxy + generate the profile

```bash
cd proxy-filter/localtest
./start.sh                 # starts mitmproxy on UDP/51820
node generate-profile.mjs  # writes wg/localtest.mobileconfig
```

`generate-profile.mjs` prints a removal password to the terminal —
**save it**. You'll need it to uninstall the profile later.

### Install the profile

```bash
open wg/localtest.mobileconfig
```

macOS opens **System Settings → Privacy & Security → Profiles**. Click
the profile, click **Install**, enter your Mac admin password.

The profile installs four payloads in one click:
- The CA cert (auto-trusted at System scope — no Keychain dance).
- A WireGuard VPN configured to point at mitmproxy on `127.0.0.1`.
- A System Settings lockdown (Network/Profiles/Security panes).
- The removal password.

The VPN auto-connects within a few seconds (look for the WireGuard
icon in the menu bar, "filter-localtest" should be on).

### To uninstall

System Settings → Privacy & Security → Profiles → click *proxy-filter
(local test)* → **Remove** → enter the removal password from earlier.
Everything reverses cleanly: VPN gone, CA untrusted, settings unlocked.

---

## Alternative: CLI install (for quick poking, not recommended for real test)

If you don't want to install WireGuard.app, the start script also
writes `wg/import.conf` for use with the CLI `wg-quick` tool that
came with `wireguard-tools`. **Heads-up: this route bypasses CA trust
(you'd need to manually trust in Keychain Access), bypasses settings
lockdown, and bypasses removal protection.** Only use it for a quick
"does this even work" sanity check.

```bash
sudo wg-quick up   "$(pwd)/proxy-filter/localtest/wg/import.conf"
sudo wg-quick down "$(pwd)/proxy-filter/localtest/wg/import.conf"
```

If this version breaks your internet (DNS issue, etc.), recover with:
```bash
sudo wg-quick down "$(pwd)/proxy-filter/localtest/wg/import.conf"
```

When the tunnel is up, you can verify with:
```bash
ifconfig | grep -A1 utun
# you'll see a utun interface bound to 10.0.0.1
```

---

## Try it

In another terminal, watch the proxy log:
```bash
tail -f /tmp/proxy-filter-localtest.log
```

In a browser (or curl), visit some sites. Each request should print
in the log as either `[ALLOW] sarah <method> <host><path>` or
`[BLOCK] sarah <method> <host><path>`.

```bash
# allowed — full URL incl. query string visible in the log
curl https://example.com/foo?bar=1

# blocked by default blocklist (proxy-filter/server/blocklists/adult.txt)
curl https://777.com   # → 403 with our 🛡️ block page
```

To add a new blocked domain:

1. Open the dashboard at http://localhost:5173
2. Sidebar → Proxy → Proxy Profiles → **sarah** → Settings
3. In **Blocked Domains**, type a domain → **Add**
4. Within ~1 second the filter picks up the change (no restart needed)
5. Visit that domain in a fresh tab → 🛡️ block page

To add an exception:

- **Allowed Domains** in the same Settings page overrides everything
  (per-profile blocklist + default blocklist).
- The cert-pinning **exclusions list** at
  `proxy-filter/localtest/exclusions.txt` says "don't try to MITM
  this — just tunnel". Edit + save and the addon re-reads it.

---

## What you should see working

- ✅ TCP and UDP traffic from any app on this Mac flows through
  mitmproxy (because it's a real VPN tunnel, not an HTTP proxy).
- ✅ Full URL/path/query-string visible to the filter — not just
  hostname (proven in Spike B; same machinery here).
- ✅ Blocked HTTPS sites get a real branded block page from a cert
  signed by your CA, no browser warning.
- ✅ Cert-pinned apps (banks, Apple services) keep working because
  they're in `exclusions.txt` and the proxy tunnels them through
  without decrypting.
- ✅ Rules edited in the dashboard take effect within ~1s.

Things this local test deliberately doesn't prove (those need a real
VPS or a real iPhone):
- Cross-platform (only your Mac for now)
- Always-on enforcement that survives reboots / can't be turned off
  by a regular user (the .mobileconfig handles that — local test
  doesn't install one)
- Captive portal + cellular behavior on iOS

---

## Troubleshooting

**`./start.sh` says `wg: command not found`** —
`brew install wireguard-tools`.

**WireGuard.app says it can't import the config** —
make sure mitmdump generated `wg/import.conf`. Re-run `./start.sh`. If
the file exists but is invalid, run
`grep -E '^(PrivateKey|Endpoint)' wg/import.conf` to sanity-check.

**Tunnel turns on but everything times out** —
check that mitmdump is actually running:
`cat /tmp/proxy-filter-localtest.pid` then `ps -p <that pid>`. If not,
re-run `./start.sh`. If yes, check `tail /tmp/proxy-filter-localtest.log`
for crashes in the addon.

**Browser shows "this connection isn't private" for a blocked site** —
the CA isn't trusted in your Keychain. Re-do the "Trust the CA" step.

**Browser loads YouTube/Google/etc. but nothing appears in the
proxy log** — those sites are using HTTP/3 (QUIC over UDP). The local
test forwards UDP through the WireGuard tunnel, but mitmproxy doesn't
intercept QUIC. Browsers fall back to TCP after a few seconds.
For aggressive testing, disable QUIC:
- Chrome: `chrome://flags` → search "QUIC" → Disabled → relaunch
- Safari: Develop menu → Feature Flags → uncheck "HTTP/3"

**Some app stops working completely** — it's probably cert-pinning.
Add its domain to `exclusions.txt` and the proxy will tunnel it
through without trying to decrypt. The app will see the real cert
chain again.

**You want to take a fresh start** — re-run `./start.sh`. To
regenerate the WireGuard keys, delete `wg/wireguard.conf` first.

---

## Stop

```bash
cd proxy-filter/localtest
./stop.sh
```

Then toggle the WireGuard tunnel off (or `sudo wg-quick down ...`),
otherwise your Mac keeps trying to route through the now-stopped
proxy and loses internet.

---

## What this is testing vs. the production plan

The production plan from spike C is:

```
device → IKEv2 .mobileconfig VPN → strongSwan on a VPS → mitmproxy → internet
```

The localtest is:

```
this Mac → WireGuard manual install → mitmproxy (same Mac) → internet
```

What's identical:
- mitmproxy doing the SSL inspection with our existing CA — same code
  paths, same per-host cert minting
- The filter addon, exclusions list, rule files — moved to the server
  unchanged
- The block-page rendering, allow/block decision logic

What's different (and what we'd test on a real VPS later):
- WireGuard → IKEv2 (so iPhone works without an app)
- 127.0.0.1 → real VPS hostname (so traffic from other devices reaches it)
- Per-device source IP → per-device profile lookup (we hardcode profile
  to one user here; on the VPS, source IP after VPN decryption identifies
  which profile)

The hard parts (cert handling, per-flow rules, cert pinning, custom
HTTPS block pages) are exactly the same. If those work here, they
work in production.
