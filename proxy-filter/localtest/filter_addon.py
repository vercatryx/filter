# Part of proxy-filter localtest — see ./README.md
#
# Mitmproxy addon. Reuses the SAME on-disk rule files the existing
# dashboard already manages:
#
#   server/blocklists/adult.txt                  shared default blocklist
#   server/profiles/<user_id>/blocklist.txt      this profile's blocklist
#   server/profiles/<user_id>/allowlist.txt      this profile's allowlist
#   localtest/exclusions.txt                     domains to never MITM
#
# Decision per (host):
#   if SNI ∈ exclusions          → tunnel through (don't decrypt)
#   if host ∈ profile.allowlist  → ALLOW (override)
#   if host ∈ profile.blocklist  → BLOCK (this profile only)
#   if host ∈ default blocklist  → BLOCK
#   otherwise                    → ALLOW
#
# In a single-Mac local test there's just one profile (set via env var
# LOCALTEST_PROFILE, defaults to 'sarah'). The point is to verify the
# architecture, not multi-tenant logic.

import os
import time
from pathlib import Path

from mitmproxy import ctx, http, tls

PROFILE = os.environ.get("LOCALTEST_PROFILE", "sarah")

HERE = Path(__file__).resolve().parent
SERVER_DIR = HERE.parent / "server"
DEFAULT_BLOCKLIST = SERVER_DIR / "blocklists" / "adult.txt"
PROFILE_BLOCK = SERVER_DIR / "profiles" / PROFILE / "blocklist.txt"
PROFILE_ALLOW = SERVER_DIR / "profiles" / PROFILE / "allowlist.txt"
EXCLUSIONS = HERE / "exclusions.txt"


def _read_domain_file(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text().splitlines():
        s = line.strip().lower()
        if not s or s.startswith("#"):
            continue
        out.add(s)
    return out


class Filter:
    def __init__(self):
        self._cache = {}    # path -> (mtime, set)
        self.profile = PROFILE

    def _get(self, path: Path) -> set[str]:
        try:
            m = path.stat().st_mtime
        except FileNotFoundError:
            self._cache[path] = (0, set())
            return set()
        cached = self._cache.get(path)
        if cached and cached[0] == m:
            return cached[1]
        s = _read_domain_file(path)
        self._cache[path] = (m, s)
        return s

    @property
    def exclusions(self) -> set[str]:
        return self._get(EXCLUSIONS)

    @property
    def default_block(self) -> set[str]:
        return self._get(DEFAULT_BLOCKLIST)

    @property
    def profile_block(self) -> set[str]:
        return self._get(PROFILE_BLOCK)

    @property
    def profile_allow(self) -> set[str]:
        return self._get(PROFILE_ALLOW)

    @staticmethod
    def matches(host: str, patterns: set[str]) -> bool:
        if not host or not patterns:
            return False
        host = host.lower()
        for p in patterns:
            if host == p or host.endswith("." + p):
                return True
        return False

    # --- mitmproxy hooks ---

    def load(self, loader):
        ctx.log.info(f"[localtest] profile={self.profile}")
        ctx.log.info(f"[localtest] default-blocklist: {DEFAULT_BLOCKLIST}")
        ctx.log.info(f"[localtest] profile dir: {SERVER_DIR / 'profiles' / self.profile}")
        ctx.log.info(f"[localtest] exclusions: {EXCLUSIONS}")

    def tls_clienthello(self, data: tls.ClientHelloData):
        """Run before TLS interception. If the SNI is in the exclusions
        list (cert-pinning apps, banking, etc.), we tunnel the bytes
        through without decrypting — sees nothing, but the app keeps
        working."""
        sni = (data.client_hello.sni or "").lower()
        if self.matches(sni, self.exclusions):
            ctx.log.info(f"[passthrough] SNI={sni} (in exclusions)")
            data.ignore_connection = True

    def request(self, flow: http.HTTPFlow):
        host = flow.request.pretty_host
        path = flow.request.path

        if self.matches(host, self.profile_allow):
            ctx.log.info(f"[ALLOW] {self.profile} {flow.request.method} {host}{path}")
            return

        if self.matches(host, self.profile_block) or self.matches(host, self.default_block):
            ctx.log.info(f"[BLOCK] {self.profile} {flow.request.method} {host}{path}")
            html = (
                "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                "<title>Site Blocked</title>"
                "<style>"
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
                f"<div class='meta'>Profile: {self.profile}</div>"
                "</div></body></html>"
            )
            flow.response = http.Response.make(
                403,
                html,
                {"Content-Type": "text/html; charset=utf-8"},
            )
            return

        ctx.log.info(f"[ALLOW] {self.profile} {flow.request.method} {host}{path}")


addons = [Filter()]
