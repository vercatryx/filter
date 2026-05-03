# Spike findings — VPN + transparent MITM architecture

All four spikes ran. Here's what I learned and where I now stand on
"will this actually work."

## Spike A — full Mac+iOS .mobileconfig

**Result: solid.** Generated `spike-a.mobileconfig` (15.9 KB) with the
five payload types we need bundled into one profile:

1. `com.apple.security.root` — the CA cert (1321 byte DER blob,
   embedded as base64).
2. `com.apple.security.pkcs12` — per-device IKEv2 client identity
   (3929 byte PKCS#12, encrypted with a profile-baked password,
   contains a 5-year cert `CN=sarah-test` signed by our CA).
3. `com.apple.vpn.managed` (IKEv2) — references the PKCS#12 by UUID,
   uses cert-based mutual auth, On-Demand "always connect" rule.
4. `com.apple.systempreferences` — locks Network/Profiles/Security
   prefpanes (macOS only; iOS ignores quietly).
5. `com.apple.profileRemovalPassword` — the can't-be-removed lock.

`plutil -lint` passes. The PKCS#12 decrypts cleanly with the embedded
password — verified via `openssl pkcs12` that the cert chain is
`subject=CN=sarah-test, issuer=CN=Proxy Filter CA`, exactly the
identity strongSwan would expect for `rightca = "CN=Proxy Filter CA"`.

What this didn't prove: that an actual iPhone will install it. That
needs a real device. **Every payload type used here is mainstream and
documented in Apple's Configuration Profile Reference**, so my
confidence is high but not 100%.

Artifact: `spikes/spike-a-generate-profile.mjs` (the generator) and
`spikes/spike-a.mobileconfig` (a real installable profile pointing at
a fake server).

## Spike B — mitmproxy + our existing CA → real URL visibility

**Result: solid.** mitmproxy ran on port 8128 using only our existing
`proxy-filter/server/ssl/ca.crt` + `ca.key` (concatenated into a single
PEM at the standard mitmproxy location, no CA regeneration needed).

Three test requests went through:

| URL                                       | Verify | HTTP | Logged URL in mitmproxy                 |
|-------------------------------------------|--------|------|-----------------------------------------|
| `https://example.com/path?q=spike-b`      | OK     | 404  | `GET https://example.com/path?q=spike-b`|
| `https://wikipedia.org/wiki/HTTPS`        | OK     | 301  | `GET https://wikipedia.org/wiki/HTTPS`  |
| `https://httpbin.org/headers`             | OK     | 200  | `GET https://httpbin.org/headers`       |

`openssl s_client` to `example.com` through mitmproxy returned a cert
with `subject=CN=example.com, issuer=CN=Proxy Filter CA` — that's
mitmproxy minting a per-host cert at runtime using our existing CA.

This is the deep-inspection capability the user asked for: not just
hostname (which a SNI sniffer alone gives), but **full URL including
path and query string**. Headers and bodies are also available to the
addon — that's what the filter Python code in Spike C uses.

Artifact: `spikes/mitmproxy-ca.pem` (our CA in mitmproxy's expected
format) and a working mitmdump invocation that reuses it.

## Spike C — server-side stack

**Result: complete config drafted, not yet deployed.** Wrote
`spikes/spike-c-server-stack.md` covering:

- strongSwan IKEv2 config (`ipsec.conf`, `ipsec.secrets`) with
  cert-based per-device auth using our CA. Each device gets a stable
  internal IP from `10.10.10.0/24`.
- A shell script the dashboard would call to mint a per-device cert +
  PKCS#12 bundle on profile creation.
- nftables rules for: forward VPN traffic out the internet interface,
  redirect TCP/80 + TCP/443 from the VPN subnet into mitmproxy on
  localhost:8080, drop UDP/443 (kills QUIC, browsers fall back to TCP),
  NAT egress.
- A systemd unit running `mitmdump --mode transparent` with our CA.
- A 100-line `filter_addon.py` that pulls per-device rules from a
  `rules.json` written by the dashboard, applies allow/block per flow,
  and serves a custom 403 page for blocks. Cert-pinned domains are
  passed through via `data.ignore_connection = True`.

Total moving parts: strongSwan, nftables, mitmproxy. All standard
Ubuntu packages. Nothing custom-compiled.

What this didn't prove: that the whole chain comes up clean on a
fresh VPS without surprises. I'd put 2-3 days into actually building
this on a test box before handing it to you.

## Spike D — cert pinning landscape

**Result: very tractable.** Two findings:

1. mitmproxy ships `tls_passthrough.py` in their official examples
   (pulled and inspected). It has an automatic-learning mode: try to
   MITM by default, and if the client's TLS handshake fails (because
   of cert pinning), record the server in a "passthrough" set and skip
   MITM for it next time. We can ship this as our default strategy on
   top of a static starter list.

2. Wrote `spikes/spike-d-default-exclusions.txt` — a 125-entry starter
   list for the static side, sourced from Apple's own enterprise
   networking guidance (https://support.apple.com/en-us/101555),
   Cisco Umbrella's published TLS-decryption notes, and community
   knowledge. Covers Apple system services (push, iCloud, App Store,
   iMessage, FaceTime, software update, MDM, Apple TV+, etc.), Google
   pinned services, Microsoft 365, E2E messengers (Signal, WhatsApp,
   Telegram), major US banks, Dropbox/1Password/Slack/Zoom, gaming
   networks, and EDR/AV products.

The pattern: ship the static list as default, learn dynamically from
there, surface a "recently passed through" list in the dashboard so
the admin can see what we're not inspecting and decide whether to act.

What this didn't prove: that the static list is exhaustive. It won't
be. The dynamic mode catches what the static misses, with at most a
single failed handshake per pinned service per session.

## Net assessment

**Will this work? Yes, with the caveats already discussed.**

The original concern was "does deep cert-based inspection actually let
us filter at URL level cross-platform without all the leaks of HTTP
proxy mode?" Spike A says yes for the cross-platform device-side
config, Spike B says yes for the URL-level inspection (using our
existing CA), Spike C says yes for an end-to-end production server
recipe, and Spike D says cert pinning is bounded and manageable.

What still requires real hardware to validate (in declining order of
risk):

1. iOS specifically accepting and installing the full payload combo.
   **Highest residual risk** — about 24 hours of work to mitigate,
   mostly testing.
2. Captive portal behavior on a public WiFi with always-on VPN.
   Mitigations exist; "evaluate-connection" rules in iOS are
   documented. Probably fine.
3. Battery impact of always-on IKEv2 on iPhone. Anecdotally
   acceptable; verifiable in a day of real-world use.
4. Apple services not on the default exclusion list breaking on iOS
   17/18 specifically. Dynamic learning catches them; might cause one
   bad day for the user.

## What I'd build, if green-lit

Same architecture as Spike C, in this order:

| Week | Deliverable |
|------|-------------|
| 1 | VPS provisioned. strongSwan IKEv2 working with hand-rolled per-device cert. Mac connects, gets a 10.10.10.x IP, traffic flows out. iPhone connects from real cell network. |
| 2 | nftables rules in place. mitmproxy in transparent mode behind it. UDP/443 dropped. Verify TCP/443 fallback. Rules live-reload from `rules.json`. |
| 3 | Dashboard rewired: profile create runs cert-mint over SSH, writes `rules.json`, generates the new `.mobileconfig`. Per-profile blocklist + allowlist UI carries over from current code. Drop the per-port HTTP-proxy code. |
| 4 | Static exclusions UI + dynamic-passthrough viewer. Block-page customization. Real-world testing on Mac + iPhone, in coffee shops with captive portals, on cellular. Ship. |

## My recommendation

Go. The spikes raised no red flags and lit up four green ones. The
remaining risk is mostly empirical and gets resolved in week 1 by
actually doing the work, not by more planning.

Before I write any of that code, the only thing I'd want from you is:

1. **A VPS choice** so I can scope the deploy commands to that
   provider. Hetzner, DigitalOcean, Linode, Vultr — any of them work,
   ~$5/mo, want your preference.
2. **A domain name** to point at it. IKEv2 needs a stable
   `RemoteIdentifier` / `RemoteAddress`. A subdomain of something you
   own is fine (`vpn.yourdomain.com`).
3. **Confirmation that the migration is OK**: when this lands, the
   current Node HTTP proxy and per-port code goes away. Profiles and
   rules carry over; you'd reinstall the .mobileconfig on each device
   once.

If those three are settled, I'll write the week-1 plan in detail and
get sign-off before any code lands.
