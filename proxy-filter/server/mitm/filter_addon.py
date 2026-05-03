# Mitmproxy transparent-mode addon.
#
# After strongSwan decrypts an IKEv2 packet, the source IP becomes the
# device's stable VPN-internal IP (e.g. 10.10.10.7). pf redirects TCP/80
# and TCP/443 into mitmproxy. mitmproxy reads SO_ORIGINAL_DST to learn
# the real destination, peeks at SNI, optionally MITMs (skipping
# cert-pinning hosts), and applies per-profile rules.
#
# Files this addon reads (all written by the dashboard, watched by mtime):
#
#   server/rules.json
#       { "10.10.10.7": {
#             "user_id": "sarah",
#             "blocklist": ["twitter.com", "reddit.com"],
#             "allowlist": ["news.example.com"]
#         },
#         ...
#       }
#
#   server/blocklists/adult.txt
#       Default (shared) blocklist applied to every profile.
#
#   server/mitm/exclusions.txt
#       SNI domains we MUST NOT MITM (banks, Apple services, E2E
#       messengers, etc.). For these, we tunnel raw bytes through.
#
# Decision precedence per (profile, host):
#   if SNI ∈ exclusions          → tunnel through (no decryption)
#   if host ∈ profile.allowlist  → ALLOW
#   if host ∈ profile.blocklist  → BLOCK (with HTTPS block page)
#   if host ∈ default blocklist  → BLOCK
#   otherwise                    → ALLOW

import json
import logging
import os
from pathlib import Path

from mitmproxy import ctx, http, tls

HERE = Path(__file__).resolve().parent
SERVER_DIR = HERE.parent
RULES_PATH = SERVER_DIR / "rules.json"
DEFAULT_BLOCKLIST = SERVER_DIR / "blocklists" / "adult.txt"
EXCLUSIONS = HERE / "exclusions.txt"


def _read_domain_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out: set[str] = set()
    for line in path.read_text().splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        out.add(s)
    return out


class _Cache:
    def __init__(self):
        self._mtime: dict[Path, float] = {}
        self._data: dict[Path, object] = {}

    def get(self, path: Path, loader):
        try:
            m = path.stat().st_mtime
        except FileNotFoundError:
            self._data[path] = loader(None)
            self._mtime[path] = 0
            return self._data[path]
        if self._mtime.get(path) != m:
            self._data[path] = loader(path)
            self._mtime[path] = m
        return self._data[path]


class Filter:
    def __init__(self):
        self._cache = _Cache()

    # ------- file loaders -------

    def _load_rules(self, path):
        if path is None:
            return {}
        try:
            return json.loads(Path(path).read_text())
        except Exception as e:
            logging.error(f"[filter_addon] rules.json parse error: {e}")
            return {}

    def _load_set(self, path):
        return _read_domain_file(Path(path)) if path else set()

    # ------- accessors -------

    @property
    def rules(self) -> dict:
        return self._cache.get(RULES_PATH, self._load_rules)

    @property
    def default_block(self) -> set[str]:
        return self._cache.get(DEFAULT_BLOCKLIST, self._load_set)

    @property
    def exclusions(self) -> set[str]:
        return self._cache.get(EXCLUSIONS, self._load_set)

    # ------- domain matching -------

    @staticmethod
    def matches(host: str, patterns) -> bool:
        if not host or not patterns:
            return False
        host = host.lower()
        for p in patterns:
            if host == p or host.endswith("." + p):
                return True
        return False

    # ------- mitmproxy hooks -------

    def load(self, loader):
        ctx.log.info(f"[filter_addon] rules:      {RULES_PATH}")
        ctx.log.info(f"[filter_addon] default:    {DEFAULT_BLOCKLIST}")
        ctx.log.info(f"[filter_addon] exclusions: {EXCLUSIONS}")

    def tls_clienthello(self, data: tls.ClientHelloData):
        sni = (data.client_hello.sni or "").lower()
        if self.matches(sni, self.exclusions):
            ctx.log.info(f"[passthrough] SNI={sni}")
            data.ignore_connection = True

    def request(self, flow: http.HTTPFlow):
        # In transparent mode the device's VPN-internal IP is on the
        # client connection.
        client_ip = flow.client_conn.peername[0] if flow.client_conn.peername else None
        host = flow.request.pretty_host
        path = flow.request.path

        profile = self.rules.get(client_ip)
        if profile is None:
            # No rule for this source IP. Default to allow + log so we
            # can debug strongSwan/IP allocation issues.
            ctx.log.info(f"[ALLOW unknown] ip={client_ip} {flow.request.method} {host}{path}")
            return

        user_id = profile.get("user_id", "?")
        block = profile.get("blocklist", []) or []
        allow = profile.get("allowlist", []) or []

        if self.matches(host, allow):
            ctx.log.info(f"[ALLOW] {user_id} {flow.request.method} {host}{path}")
            return

        if self.matches(host, block) or self.matches(host, self.default_block):
            ctx.log.info(f"[BLOCK] {user_id} {flow.request.method} {host}{path}")
            html = (
                "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                "<title>Site Blocked</title><style>"
                "body{margin:0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;"
                "background:#0f1115;color:#e8eaed;min-height:100vh;display:flex;"
                "align-items:center;justify-content:center;padding:24px;}"
                ".card{background:#1f2230;border:1px solid #2a2e3f;border-radius:16px;"
                "max-width:520px;padding:40px;}"
                "h1{margin:0 0 8px;font-size:24px;}"
                "p{margin:0 0 16px;color:#9aa0b4;line-height:1.5;}"
                "code{background:#14161e;border:1px solid #2a2e3f;border-radius:6px;"
                "padding:4px 8px;font-family:ui-monospace,monospace;font-size:13px;}"
                ".meta{font-size:12px;color:#6b7290;margin-top:24px;}"
                "</style></head><body><div class='card'>"
                "<h1>🛡️ This site is blocked</h1>"
                f"<p>Access to <code>{host}</code> is restricted by your network policy.</p>"
                "<p>If you need access for a legitimate reason, contact your administrator.</p>"
                f"<div class='meta'>Profile: {user_id}</div>"
                "</div></body></html>"
            )
            flow.response = http.Response.make(
                403, html, {"Content-Type": "text/html; charset=utf-8"},
            )
            return

        ctx.log.info(f"[ALLOW] {user_id} {flow.request.method} {host}{path}")


addons = [Filter()]
