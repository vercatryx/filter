# Spike C — server-side stack that would actually run on a Linux VPS

Target: Ubuntu 24.04 LTS on a tiny VPS (1 vCPU / 1 GB RAM is enough for
a small number of devices). All commands run as root unless noted.

## 1. strongSwan IKEv2 (per-device cert auth)

This is the VPN endpoint. macOS and iOS speak IKEv2 natively — no app
needed on the device. Each profile authenticates with its own client
certificate signed by our existing CA at
`/etc/ipsec.d/cacerts/ca.crt`.

```bash
apt-get update
apt-get install -y strongswan strongswan-pki libcharon-extra-plugins
```

### `/etc/ipsec.conf`

```conf
config setup
    charondebug = "ike 1, knl 1, cfg 0"
    uniqueids = no

conn %default
    keyexchange = ikev2
    ike = aes256gcm16-sha256-modp4096!
    esp = aes256gcm16-modp4096!
    dpdaction = clear
    dpddelay = 30s

conn ikev2-clients
    auto = add
    fragmentation = yes
    forceencaps = yes
    rekey = no

    # --- left = us, the VPN server ---
    left = %defaultroute4
    leftid = @vpn.yourdomain.com   # match VPNRemoteIdentifier in the .mobileconfig
    leftcert = vpn-server.crt
    leftsendcert = always
    leftsubnet = 0.0.0.0/0,::/0
    leftauth = pubkey

    # --- right = each connecting device ---
    right = %any
    rightid = %any
    rightauth = pubkey
    rightsourceip = 10.10.10.0/24            # internal VPN subnet
    rightdns = 10.10.10.1                    # we serve DNS too (optional)
    rightca = "CN=Proxy Filter CA"           # require certs signed by our CA
```

### `/etc/ipsec.secrets`

```
: RSA vpn-server.key
```

The VPN server's own cert (`vpn-server.crt`/`.key` in `/etc/ipsec.d/`)
is also signed by our CA. The device verifies the server cert against
that CA — same CA already trusted via the `.mobileconfig`'s
`com.apple.security.root` payload.

### Per-device cert generation (called by the dashboard at profile create)

```bash
# spike-c-make-device-cert.sh — what the dashboard would shell out to
DEVICE_ID="$1"   # e.g. "sarah"
CA_DIR="/etc/ipsec.d"

# 1. private key
ipsec pki --gen --type rsa --size 2048 \
    --outform pem > "$CA_DIR/private/$DEVICE_ID.key"

# 2. cert request signed by our CA
ipsec pki --pub --in "$CA_DIR/private/$DEVICE_ID.key" \
  | ipsec pki --issue \
        --cacert "$CA_DIR/cacerts/ca.crt" \
        --cakey  "$CA_DIR/private/ca.key" \
        --dn "CN=$DEVICE_ID" \
        --san "$DEVICE_ID" \
        --flag clientAuth \
        --lifetime 3650 \
        --outform pem > "$CA_DIR/certs/$DEVICE_ID.crt"

# 3. PKCS#12 bundle (this is what goes into the .mobileconfig)
openssl pkcs12 -export \
    -inkey "$CA_DIR/private/$DEVICE_ID.key" \
    -in    "$CA_DIR/certs/$DEVICE_ID.crt" \
    -certfile "$CA_DIR/cacerts/ca.crt" \
    -name "$DEVICE_ID" \
    -passout "pass:$2" \
    -out "/var/lib/filter/profiles/$DEVICE_ID.p12"
```

After this:
- VPN server's strongSwan auto-trusts any device whose cert is signed
  by our CA.
- `rightsourceip = 10.10.10.0/24` hands each device a stable internal
  IP. mitmproxy will see this IP as the "source" and look up the
  corresponding profile.
- Mapping `<internal-IP> → <device-id>` lives in the dashboard DB and
  in a small JSON file mitmproxy reads (next section).

---

## 2. Kernel forwarding + transparent intercept

```bash
# Permanent
cat > /etc/sysctl.d/99-vpn-filter.conf <<'EOF'
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
# Reverse-path filtering off on VPN ifaces (xfrm interfaces)
net.ipv4.conf.all.rp_filter = 2
EOF
sysctl --system
```

### nftables ruleset (`/etc/nftables.conf`)

```nft
flush ruleset

table inet filter {
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Allow established/related
        ct state established,related accept

        # VPN traffic going outbound to the internet
        iifname "ipsec0" oifname "eth0" accept

        # Return path
        iifname "eth0" oifname "ipsec0" ct state established,related accept
    }
}

table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;

        # Steal HTTP/HTTPS from VPN clients into mitmproxy
        iifname "ipsec0" tcp dport 443 redirect to :8080
        iifname "ipsec0" tcp dport  80 redirect to :8080
    }

    chain output {
        type nat hook output priority -100;
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        # NAT egress so packets going from VPN clients to internet
        # leave with the server's IP
        oifname "eth0" masquerade
    }
}

# Drop UDP/443 (QUIC) so browsers fall back to TCP/443 (which we MITM).
# Drop, not reject — silence is faster fallback than ICMP unreach.
table inet quic-block {
    chain forward {
        type filter hook forward priority -10; policy accept;
        iifname "ipsec0" udp dport 443 drop
    }
}
```

After `systemctl enable --now nftables`, the picture is:

- VPN clients land on `ipsec0` (created by strongSwan/charon-NM via xfrm).
- TCP/80 and TCP/443 from clients gets REDIRECTed to localhost:8080 where
  mitmproxy is listening.
- mitmproxy reads the original destination via `SO_ORIGINAL_DST`,
  inspects, and forwards.
- Everything else (DNS, etc.) NATs straight out.
- UDP/443 dies silently → browser falls back to TCP/443 within seconds.

---

## 3. mitmproxy in transparent mode

### `/etc/systemd/system/mitm-filter.service`

```ini
[Unit]
Description=mitmproxy filter
After=network.target strongswan-starter.service

[Service]
ExecStart=/usr/local/bin/mitmdump \
    --mode transparent \
    --listen-port 8080 \
    --showhost \
    --set confdir=/etc/mitm/conf \
    --set block_global=false \
    -s /etc/mitm/filter_addon.py
Restart=always
RestartSec=2
# Needed for SO_ORIGINAL_DST + binding 80/443 indirectly
AmbientCapabilities=CAP_NET_RAW CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/var/lib/filter /var/log/filter
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`/etc/mitm/conf/mitmproxy-ca.pem` is just our existing
`proxy-filter/server/ssl/{ca.crt,ca.key}` concatenated (exactly what we
proved works in Spike B).

### `/etc/mitm/filter_addon.py` — rule lookup + block decision

```python
# Per-flow filter. Pulls per-device rules from a JSON file the dashboard
# writes (same idea as ports.json today). On block, returns a custom
# 403 page. On allow, lets the flow through to the upstream.

import json, os, time, ipaddress
from mitmproxy import http, ctx

RULES_PATH = "/var/lib/filter/rules.json"
EXCLUSIONS_PATH = "/var/lib/filter/exclusions.txt"

# rules.json format:
# {
#   "10.10.10.7": {
#       "user_id": "sarah",
#       "blocklist": ["twitter.com", "reddit.com"],
#       "allowlist": ["news.example.com"]
#   },
#   ...
# }

class Filter:
    def __init__(self):
        self.rules = {}
        self.rules_mtime = 0
        self.exclusions = set()
        self.exclusions_mtime = 0
        self.default_blocklist = set()  # filled from a separate file

    def reload_if_needed(self):
        try:
            m = os.path.getmtime(RULES_PATH)
            if m != self.rules_mtime:
                with open(RULES_PATH) as f:
                    self.rules = json.load(f)
                self.rules_mtime = m
        except FileNotFoundError:
            self.rules = {}
        try:
            m = os.path.getmtime(EXCLUSIONS_PATH)
            if m != self.exclusions_mtime:
                with open(EXCLUSIONS_PATH) as f:
                    self.exclusions = {
                        line.strip().lower()
                        for line in f if line.strip() and not line.startswith("#")
                    }
                self.exclusions_mtime = m
        except FileNotFoundError:
            self.exclusions = set()

    def matches(self, host, patterns):
        host = host.lower()
        for p in patterns:
            if host == p or host.endswith("." + p):
                return True
        return False

    def lookup_profile(self, source_ip):
        return self.rules.get(source_ip)

    # --- mitmproxy hooks ---

    def tls_clienthello(self, data):
        """Called as soon as we see the TLS Client Hello with SNI.
        Decide whether to MITM or pass through (cert pinning exclusions)."""
        self.reload_if_needed()
        sni = data.client_hello.sni or ""
        if self.matches(sni, self.exclusions):
            data.ignore_connection = True   # mitmproxy passes the bytes through
                                            # without decrypting. We get nothing.
                                            # That's the price of a pinned app.

    def request(self, flow: http.HTTPFlow) -> None:
        """Once we've decrypted, this gets every HTTP request."""
        self.reload_if_needed()
        client_ip = flow.client_conn.peername[0]
        host = flow.request.pretty_host
        path = flow.request.path

        profile = self.lookup_profile(client_ip)
        if profile is None:
            # No rule for this IP — default deny? Or default allow?
            # For now, allow but log so we notice.
            ctx.log.info(f"[unknown-ip] {client_ip} -> {host}{path}")
            return

        user_id = profile["user_id"]
        block = set(profile.get("blocklist", []))
        allow = set(profile.get("allowlist", []))

        if self.matches(host, allow):
            ctx.log.info(f"[ALLOW http] {user_id} {host}{path}")
            return
        if self.matches(host, block) or self.matches(host, self.default_blocklist):
            ctx.log.info(f"[BLOCK http] {user_id} {host}{path}")
            flow.response = http.Response.make(
                403,
                f"<!DOCTYPE html><html><body style='font-family:sans-serif'>"
                f"<h1>🛡️ Blocked</h1>"
                f"<p>Access to <code>{host}</code> is restricted.</p>"
                f"<small>Profile: {user_id}</small>"
                f"</body></html>",
                {"Content-Type": "text/html; charset=utf-8"},
            )
            return
        ctx.log.info(f"[ALLOW http] {user_id} {host}{path}")

addons = [Filter()]
```

That `tls_clienthello` hook is the cert-pinning escape valve — for any
host in the exclusions file, we set `ignore_connection = True` and
mitmproxy stops trying to MITM that flow, just tunnels the bytes
straight to the upstream. The user sees the real cert, app is happy,
we get no URL visibility for that host (only the SNI we already saw).

---

## 4. Where the dashboard fits

The dashboard (existing Node + SQLite app) writes two files
periodically (or on rule change):

- `/var/lib/filter/rules.json` — keyed by VPN-internal IP, value is
  `{user_id, blocklist, allowlist}`. Generated from the proxy_users +
  per-profile blocklist/allowlist tables we already have.
- `/var/lib/filter/exclusions.txt` — managed via a new Dashboard tab.
  Default content shipped from the codebase (Apple services etc.).

The Node profile generator:
- Calls `spike-c-make-device-cert.sh <user_id> <p12-password>` over SSH
  when a profile is created.
- Reads back the resulting `.p12` and embeds it in the .mobileconfig
  (already proved in Spike A).
- VPN-internal IP is written into rules.json at the same time.

Total moving pieces on the server: strongSwan, mitmproxy, nftables.
All standard packages, all systemd units.

---

## 5. What this stack delivers vs. the four pain points the user named

| Pain point                                      | Fix                                                                 |
|-------------------------------------------------|---------------------------------------------------------------------|
| IP literal bypass                               | All traffic goes through VPN at L3; no DNS bypass possible          |
| QUIC bypass                                     | nftables drops UDP/443; browsers fall back to TCP/443 (mitm'd)      |
| Electron / non-cooperating apps                 | They have no choice — VPN intercepts at L3, before any app logic    |
| Per-port-per-user not scalable                  | Single VPN port (UDP/500 + UDP/4500); identification by source IP   |
| Real network inspection (URLs, not just hostname) | mitmproxy + our CA gives full URL/headers/body visibility           |
| Custom block page over HTTPS                    | Same — mitmproxy injects a 403 with our cert; clean UX              |
| Cert pinning apps need to keep working          | exclusions.txt → `ignore_connection = True` per SNI; flow tunnels   |
| Cross-platform (Mac + iPhone)                   | IKEv2 is built into both; same .mobileconfig works on both          |

---

## 6. What I'm still NOT certain about until tested on real hardware

- iOS specifically accepting the full payload combo (Spike A proves
  the structure parses; only a real iPhone proves it installs cleanly).
- Captive portal behavior on a public WiFi hotspot — strongSwan plus
  iOS's `EvaluateConnection` rules works in docs, in practice depends
  on the hotspot.
- Battery impact of always-on IKEv2 on iPhone — anecdotally fine but
  varies by iOS version.
- Performance under real load with 5-10 devices on one $5 VPS. Should
  be fine but not measured.
- Specific Apple services that may break despite exclusions
  (TV+, FaceTime, iMessage all have private protocols beyond just TLS).
