# Deploy guide — get to install-via-profile

Everything is built. Two `sudo` commands away from a real working
filter. This guide tracks `PLAN.md` Phases 1+2+3.

---

## State of play (already done by me, no action needed)

✅ strongSwan installed (`brew install strongswan`)
✅ mitmproxy installed (`brew install mitmproxy`)
✅ Server cert minted (`server/ipsec/vpn-server.{crt,key}`) — signed by your existing CA
✅ All config files written (strongSwan, pf, mitmproxy addon, exclusions list)
✅ LaunchDaemon plists written (strongSwan + mitmproxy)
✅ Dashboard wired up to mint per-device certs, allocate VPN IPs, and serve the IKEv2 `.mobileconfig`
✅ Smoke-tested: profile creation works end-to-end, profile XML lints clean

What's left: one `sudo` command to install/start the system services,
then one click in the dashboard to download a profile, then install it
on the target device.

---

## Step 1 — run the server-setup script (one time, sudo)

```bash
cd "/Users/david/Vercatryx Projects/Filter/proxy-filter/server"
sudo ./scripts/setup-server-mac.sh
```

What it does:
1. Symlinks the cert + key + ipsec.conf + ipsec.secrets + strongswan.conf into `/opt/homebrew/etc/`.
2. Enables IPv4 forwarding (`sysctl net.inet.ip.forwarding=1`).
3. Loads the pf rules from `server/pf/pf.conf` (auto-substituting your default-route interface, which is `en0`).
4. Installs LaunchDaemons at `/Library/LaunchDaemons/com.proxyfilter.{strongswan,mitm}.plist`.
5. Loads both daemons, so strongSwan + mitmproxy are running and survive reboot.

At the end it prints status and tells you where logs go.

Verify after running:
```bash
# Should show strongSwan listening on UDP/500 + UDP/4500 and mitmproxy on TCP/8080
sudo lsof -nP -iUDP:500 -iUDP:4500 -iTCP:8080 -sTCP:LISTEN

# Should show "ESTABLISHED" connections eventually as devices connect
sudo ipsec statusall
```

---

## Step 2 — boot the dashboard with PROXY_HOST set

The dashboard needs to know the host string to put in the
`.mobileconfig` (`RemoteAddress` for the IKEv2 client). For local dev,
that's your Mac's LAN IP — `10.2.19.97` based on what I saw earlier.

```bash
cd "/Users/david/Vercatryx Projects/Filter/backend"
PROXY_HOST="10.2.19.97" npm start
```

(Already running in the background from the smoke test — restart
manually if needed.)

In another terminal serve the static dashboard:
```bash
cd "/Users/david/Vercatryx Projects/Filter/admin"
python3 -m http.server 5173
```

Open http://localhost:5173 → sign in (or sign up if it's a fresh DB).

---

## Step 3 — create a profile in the dashboard

1. Sidebar → **Proxy → Proxy Profiles → New Proxy Profile**
2. Enter a User ID (alphanumeric, no spaces — e.g. `sarah`) and a
   Display Name.
3. Hit **Create**. The backend:
   - Allocates the next free VPN-internal IP (10.10.10.2 etc.)
   - Calls `mint-device-cert.sh` to issue a per-device cert signed by your CA
   - Writes the per-device PKCS#12 to `server/profiles/sarah/sarah.p12`
   - Updates `server/vpn-allocations.json`
   - Calls `reload-config.sh` which regenerates `/opt/homebrew/etc/ipsec.conf` with a per-device `conn` block and reloads strongSwan
4. Click **Settings** on the new row → optionally add a domain to
   **Blocked Domains** (e.g. `reddit.com`) so you have something to test
   against.
5. Click **Download** on the row → saves `sarah-filter.mobileconfig`.

---

## Step 4 — install the profile on the target Mac

The target Mac can be:
- Your Mac (the same one running the server). Works because the IKEv2
  client treats the server endpoint specially in the routing table. *Note: same-machine setups are inherently weirder than cross-machine — see "If something breaks" below.*
- A second Mac on your LAN.
- An iPhone on your Wi-Fi (Phase 5 from PLAN.md).

On the target:

```bash
open ~/Downloads/sarah-filter.mobileconfig
```

System Settings opens at **Privacy & Security → Profiles**. Click the
profile → **Install** → enter the target Mac's admin password.

After install:
- Look at the menu bar — there's no special icon (IKEv2 is built into
  macOS; no third-party app). VPN status is in System Settings →
  Network. The "Filter VPN" entry should say "Connected".
- All TCP/UDP traffic now flows through the tunnel to your server,
  where strongSwan decrypts, pf redirects HTTP/HTTPS into mitmproxy,
  mitmproxy applies your blocklist/allowlist.

---

## Step 5 — verify it's filtering

On the target device:

```bash
# Should ALLOW (and the URL — including path — appears in mitmproxy log)
curl https://example.com/

# Should BLOCK with our 🛡️ block page over HTTPS, no warning
curl -v https://reddit.com/   # if you added reddit.com to sarah's blocklist

# Should ALLOW (banks pinned cert; mitmproxy passes through)
curl -I https://chase.com/    # → from real chase.com, not our cert
```

On your Mac (the server), watch what's happening:

```bash
tail -f /tmp/proxyfilter-mitm.log
# Lines look like:
#   [ALLOW] sarah GET https://example.com/
#   [BLOCK] sarah GET https://reddit.com/
#   [passthrough] SNI=chase.com
```

---

## Step 6 — uninstall

System Settings → Privacy & Security → Profiles → click *Network
Filter* → **Remove** → enter the **removal password** (from the
dashboard: Sarah → Settings → Reveal Credentials → Removal Password).

Without that password, macOS refuses to remove it. That's the
"can't be removed without admin's permission" requirement.

---

## If something breaks

### Profile install fails with "VPN configuration could not be installed"

Likely the strongSwan server isn't listening yet. Check:

```bash
sudo lsof -nP -iUDP:500 -iUDP:4500 -sTCP:LISTEN
sudo cat /tmp/proxyfilter-strongswan.log
```

### VPN connects, but nothing loads on the target

mitmproxy may not be listening, or pf rules didn't load. Check:

```bash
sudo lsof -nP -iTCP:8080 -sTCP:LISTEN          # mitmproxy
sudo pfctl -s rules                            # should show our rdr/nat rules
sudo cat /tmp/proxyfilter-mitm.log
sudo sysctl net.inet.ip.forwarding              # must be 1
```

### Same-machine install (target = server)

Possible but tricky: when the VPN client (your Mac) dials the VPN
server (also your Mac), macOS adds a host route to the endpoint to
prevent loops. Should work but if you see weird behavior, install on a
different machine for a clean test. For real deployments the server is
always on a different host (eventually a VPS).

### Block page shows TLS warning

The CA isn't trusted on the target. Open System Settings →
Privacy & Security → Profiles → click the profile → it should list
"Filter Inspection CA" as installed. If not, the profile install was
incomplete; remove it and reinstall.

### Apps that pin certs (Signal, banking, Apple services) keep working

Confirm by visiting one and checking the mitmproxy log shows
`[passthrough] SNI=...` for that domain. The default exclusions list
covers Apple, Google, major banks, E2E messengers, etc. If something
isn't on the list, add its domain to
`proxy-filter/server/mitm/exclusions.txt` and the addon picks up the
change within a second.

---

## Moving to a VPS (Phase 4)

`setup-server-vps.sh` is the Linux variant of the Mac setup. Tested
target: Ubuntu 24.04 on a small VPS. Same architecture, just `apt`
instead of `brew`, `nftables` instead of `pf`, and `systemd` instead
of `launchd`.

### One-time on the VPS

```bash
# As root on the VPS (89.167.100.228 / filter.poel.ai)
git clone https://github.com/vercatryx/filter.git /opt/filter
cd /opt/filter

# IMPORTANT — bring the existing CA over (or skip this for a brand-new
# CA on the VPS). If you skip it, target devices already trusting your
# Mac's CA will need re-issued profiles.
# From your Mac:
#   scp proxy-filter/server/ssl/ca.{crt,key} root@89.167.100.228:/opt/filter/proxy-filter/server/ssl/

# Run the setup
PROXY_FILTER_VPN_HOST=filter.poel.ai \
PROXY_FILTER_VPN_HOST_2=89.167.100.228 \
  sudo -E bash proxy-filter/server/scripts/setup-server-vps.sh
```

What this does:
1. `apt install strongswan + nftables`, installs Node.js 22, installs
   mitmproxy via `pipx`.
2. Creates a `proxyfilter` system user (mitmproxy + dashboard backend
   run as this, not root).
3. Mints a server cert with both `filter.poel.ai` (DNS SAN) and
   `89.167.100.228` (IP SAN), so devices can dial either while DNS is
   still propagating.
4. Wires `/etc/ipsec.conf`, `/etc/ipsec.secrets`, `/etc/ipsec.d/{cacerts,certs,private}/`.
5. Enables IPv4 forwarding via `/etc/sysctl.d/`.
6. Loads our `nftables.conf` ruleset (NAT 10.10.10.0/24 → public IP,
   redirect TCP/80,443 → `127.0.0.1:8080`, drop UDP/443 to kill QUIC).
7. Opens UFW for UDP/500, UDP/4500, and the dashboard port (default 5173).
8. Installs `/etc/sudoers.d/proxyfilter` for the dashboard's reload calls.
9. Installs systemd units `proxyfilter-mitm.service` and
   `proxyfilter-backend.service`; enables `strongswan-starter.service`.
10. Boots everything.

After it finishes, ports listening:
- UDP/500 + UDP/4500 → strongSwan
- TCP/8080 → mitmproxy (loopback only)
- TCP/5173 → dashboard backend

Dashboard reachable at `http://89.167.100.228:5173/` (or
`http://filter.poel.ai:5173/` once DNS is set). **It's unencrypted
HTTP for now — fine while it's just you, but put Caddy or nginx in
front with Let's Encrypt before sharing the URL.**

### Then on a target device

Sign in to the dashboard, create a profile (e.g. `david`), click
**Download** to grab `david-filter.mobileconfig`. The profile will
have `RemoteAddress = filter.poel.ai`. Install it on your Mac/iPhone.
Done — you're filtered.

### DNS

Point `filter.poel.ai` at `89.167.100.228` (A record). The cert SAN
already covers both, so devices can dial either. Once DNS is live,
prefer the hostname (so you can move to a new IP without re-issuing
profiles).

---

## What's running where, summary

| Component                  | Where                                    | Survives reboot |
|----------------------------|------------------------------------------|-----------------|
| strongSwan IKEv2 server    | LaunchDaemon (your Mac)                  | ✅ |
| mitmproxy in transparent   | LaunchDaemon (your Mac)                  | ✅ |
| pf rules                   | Loaded by setup-server-mac.sh into pf    | ⚠️ re-run setup script after reboot, or add a launchd item |
| Dashboard backend          | `npm start` in your terminal             | ❌ — manual |
| Dashboard static UI        | `python3 -m http.server` in another tab  | ❌ — manual |
| Per-device cert + p12      | `proxy-filter/server/profiles/<id>/`     | ✅ on disk |
| VPN IP allocations         | `proxy-filter/server/vpn-allocations.json` | ✅ on disk |
| Per-profile rules          | `proxy-filter/server/profiles/<id>/{block,allow}list.txt` | ✅ on disk |
| Default blocklist          | `proxy-filter/server/blocklists/adult.txt` | ✅ on disk |
| Cert-pinning exclusions    | `proxy-filter/server/mitm/exclusions.txt` | ✅ on disk |
