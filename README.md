# Filter

A network-level content filter for Apple devices (Mac + iPhone) that an
admin can install via a configuration profile and that **a non-admin
user on the target device cannot disable or remove**.

## What this is

You run a small server (your own VPS, or for development on your own
Mac). The dashboard generates one `.mobileconfig` per device you want
to filter. Installing that profile on a Mac or iPhone:

- adds a CA root cert that lets the server inspect HTTPS,
- configures an always-on IKEv2 VPN to your server,
- locks the System Settings panes that would let a regular user undo
  any of this,
- and is removable only with an admin-issued password.

Once installed, every byte of internet traffic from the target device
flows through your server. The server runs **strongSwan** (the IKEv2
endpoint) and **mitmproxy** in transparent mode (the HTTPS inspector,
using the CA bundled in the same profile). Per-profile rules
(blocklist + allowlist + a shared default blocklist) decide what
gets through and what gets a custom block page.

There is **nothing on the target device that isn't in the
.mobileconfig.** No app to install. The IKEv2 client is built into
macOS and iOS.

## Why not just NextDNS / a cooperative HTTP proxy?

We tried both. They leak — apps that ignore the system proxy
(Electron, anything with hardcoded DNS), QUIC traffic over UDP/443,
and IP-literal connections all bypass DNS-only or HTTP-proxy
filtering. The VPN catches every byte. mitmproxy plus our trusted CA
gives URL-level visibility (path + query, not just hostname) and
serves a real custom block page over HTTPS without browser warnings.

Cert-pinning apps (banks, Apple system services, Signal, WhatsApp)
are handled via a 125-entry static exclusion list plus mitmproxy's
dynamic learning — those flows are tunneled through without
interception.

## Read these next

- **[PLAN.md](./PLAN.md)** — full architecture, the 17 hard
  requirements with mappings to components, the threat model
  (what the removal-password lock does and doesn't stop), and the
  build plan in phases.
- **[DEPLOY.md](./DEPLOY.md)** — the practical "run these commands"
  deploy guide. Has a section for local development on your Mac and
  a section for production on a Linux VPS.
- **[spikes/SPIKE-FINDINGS.md](./spikes/SPIKE-FINDINGS.md)** —
  the four validation spikes we ran before committing to this
  architecture: profile generation, mitmproxy with our CA,
  server-stack outline, cert-pinning landscape.

## Layout

```
PLAN.md                         architecture + requirements
DEPLOY.md                       step-by-step deploy

admin/                          dashboard frontend (plain HTML/JS)
backend/                        Node + SQLite API; serves admin/ statically too
block-page/                     legacy v1 block page (kept for reference)

proxy-filter/                   the filter module
├── server/
│   ├── ssl/                    CA (private key gitignored)
│   ├── ipsec/                  strongSwan templates + service unit
│   ├── pf/                     macOS pf.conf + Linux nftables.conf
│   ├── mitm/                   mitmproxy filter_addon.py + exclusions list
│   ├── scripts/
│   │   ├── setup-server-mac.sh setup on your local Mac
│   │   ├── setup-server-vps.sh setup on Ubuntu/Debian VPS
│   │   ├── mint-server-cert.sh one-time, signs server cert with our CA
│   │   ├── mint-device-cert.sh per-profile, called by the dashboard
│   │   └── reload-config.sh    regenerates ipsec.conf from DB + reloads
│   ├── blocklists/             default blocklist (shared across profiles)
│   └── profiles/               per-device certs + rules (gitignored)
├── admin/                      backend bits — db, router, vpnOps
├── profile-generator/          builds the .mobileconfig
└── localtest/                  WireGuard-based local test (legacy)

spikes/                         validation work that informed the design
```

## Status

Phases 1+2+3 of `PLAN.md` are built and smoke-tested:
- ✅ strongSwan + mitmproxy + nftables/pf installed and configured by
      one script (Mac variant `setup-server-mac.sh`, Linux variant
      `setup-server-vps.sh`)
- ✅ Per-device cert minting via dashboard
- ✅ IKEv2 `.mobileconfig` generator producing valid profiles that
      `plutil -lint` and contain the full payload set (CA root +
      PKCS#12 identity + IKEv2 VPN + Settings lockdown + removal
      password)
- ✅ Production deploy live at `filter.poel.ai`
      (89.167.100.228, behind Caddy with Let's Encrypt)

Currently in: **device-side install testing** (Phase 5).
