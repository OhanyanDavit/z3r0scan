"""Web probing.

Uses httpx (projectdiscovery) when available for fast, rich probing.
Otherwise falls back to Python requests: checks http/https, records status,
title, server banner, and flags a few common security-header gaps.
"""

from __future__ import annotations

import json
import re

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, normalize_host, run
from .base import ScanModule

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set (allows protocol downgrade)",
    "content-security-policy": "No CSP (weaker XSS mitigation)",
    "x-frame-options": "No X-Frame-Options (clickjacking risk)",
    "x-content-type-options": "No X-Content-Type-Options (MIME sniffing)",
}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class WebProbeModule(ScanModule):
    name = "web_probe"
    description = "HTTP(S) probe: status, title, server, security headers (httpx fallback)"
    optional_tools = ("httpx",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        host = normalize_host(target)

        if have_tool("httpx"):
            self._httpx(host, result)
            return self._finish(result, "ok", "httpx")
        if requests is None:
            return self._finish(result, "skipped", "no httpx and requests not installed")
        self._requests_probe(host, result)
        return self._finish(result, "ok", "pure-python fallback")

    def _httpx(self, host: str, result: ModuleResult) -> None:
        code, out, _ = run(
            ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect", "-u", host],
            timeout=120,
        )
        if code != 0:
            if requests is not None:
                self._requests_probe(host, result)
            return
        for line in out.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            url = data.get("url", host)
            status = data.get("status_code") or data.get("status-code")
            title = data.get("title", "")
            tech = ", ".join(data.get("tech", []) or [])
            result.add(
                Finding(
                    title=f"{url} [{status}] {title}".strip(),
                    severity=Severity.INFO,
                    description=f"Live web service. Tech: {tech}" if tech else "Live web service.",
                    evidence={"url": url, "status": status, "title": title, "tech": tech},
                )
            )

    def _requests_probe(self, host: str, result: ModuleResult) -> None:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = requests.get(
                    url,
                    timeout=self.config.timeout + 5,
                    allow_redirects=True,
                    headers={"User-Agent": "z3r0scan"},
                    verify=False,
                )
            except requests.RequestException:
                continue

            title_m = TITLE_RE.search(resp.text or "")
            title = title_m.group(1).strip()[:120] if title_m else ""
            server = resp.headers.get("Server", "")
            result.add(
                Finding(
                    title=f"{url} [{resp.status_code}] {title}".strip(),
                    severity=Severity.INFO,
                    description=f"Live web service. Server: {server}" if server else "Live web service.",
                    evidence={
                        "url": resp.url,
                        "status": resp.status_code,
                        "title": title,
                        "server": server,
                    },
                )
            )

            # Only evaluate security headers on the HTTPS endpoint.
            if scheme == "https":
                lower = {k.lower(): v for k, v in resp.headers.items()}
                for header, note in SECURITY_HEADERS.items():
                    if header not in lower:
                        result.add(
                            Finding(
                                title=f"Missing header: {header}",
                                severity=Severity.LOW,
                                description=note,
                                evidence={"url": resp.url, "header": header},
                            )
                        )
            # Found a live scheme; stop (prefer https result).
            break
