"""Web probing (enhanced).

Live-service detection via httpx when available, else Python requests. On top of
that it always runs safe, non-intrusive checks:
  * security-header analysis
  * TLS certificate inspection (issuer, expiry)
  * common sensitive-path exposure (/.git/config, /.env, /robots.txt, ...)
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from datetime import datetime, timezone

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, normalize_host, run
from .base import ScanModule

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:  # pragma: no cover
    requests = None

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS not set (allows protocol downgrade)",
    "content-security-policy": "No CSP (weaker XSS mitigation)",
    "x-frame-options": "No X-Frame-Options (clickjacking risk)",
    "x-content-type-options": "No X-Content-Type-Options (MIME sniffing)",
}
# path -> (severity if present, why it matters)
SENSITIVE_PATHS = {
    "/.git/config": (Severity.HIGH, "Exposed git config — source code disclosure risk"),
    "/.env": (Severity.HIGH, "Exposed .env — may leak secrets/credentials"),
    "/.well-known/security.txt": (Severity.INFO, "security.txt present"),
    "/robots.txt": (Severity.INFO, "robots.txt present (may reveal hidden paths)"),
    "/admin": (Severity.LOW, "Admin path responds"),
    "/server-status": (Severity.MEDIUM, "Apache server-status may be exposed"),
}
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class WebProbeModule(ScanModule):
    name = "web_probe"
    description = "HTTP(S) probe: status, title, headers, TLS, sensitive paths"
    optional_tools = ("httpx",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        host = normalize_host(target)

        live = False
        if have_tool("httpx"):
            live = self._httpx(host, result)
        if not live and requests is not None:
            live = self._requests_probe(host, result)

        if requests is not None:
            self._tls_info(host, result)
            self._sensitive_paths(host, result)

        if not live and requests is None:
            return self._finish(result, "skipped", "no httpx and requests not installed")
        return self._finish(result, "ok", "httpx" if have_tool("httpx") else "pure-python")

    def _httpx(self, host: str, result: ModuleResult) -> bool:
        code, out, _ = run(
            ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect", "-u", host],
            timeout=120,
        )
        if code != 0:
            return False
        found = False
        for line in out.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            found = True
            url = data.get("url", host)
            status = data.get("status_code") or data.get("status-code")
            title = data.get("title", "")
            tech = ", ".join(data.get("tech", []) or [])
            result.add(
                Finding(
                    title=f"{url} [{status}] {title}".strip(),
                    severity=Severity.INFO,
                    description=f"Live web service. Tech: {tech}" if tech else "Live web service.",
                    evidence={"url": url, "status": status, "title": title, "tech": tech, "kind": "live"},
                )
            )
        return found

    def _requests_probe(self, host: str, result: ModuleResult) -> bool:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = requests.get(
                    url, timeout=self.config.timeout + 5, allow_redirects=True,
                    headers={"User-Agent": "z3r0scan"}, verify=False,
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
                    evidence={"url": resp.url, "status": resp.status_code, "title": title,
                              "server": server, "kind": "live"},
                )
            )
            if scheme == "https":
                lower = {k.lower(): v for k, v in resp.headers.items()}
                for header, note in SECURITY_HEADERS.items():
                    if header not in lower:
                        result.add(
                            Finding(
                                title=f"Missing header: {header}",
                                severity=Severity.LOW,
                                description=note,
                                evidence={"url": resp.url, "header": header, "kind": "header"},
                            )
                        )
            return True
        return False

    def _tls_info(self, host: str, result: ModuleResult) -> None:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, 443), timeout=self.config.timeout) as sock, \
                    ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                proto = tls.version()
        except (OSError, ssl.SSLError, socket.timeout):
            return

        issuer = ""
        not_after = ""
        expired = False
        days_left = None
        if cert:
            issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "")
            not_after = cert.get("notAfter", "")
            try:
                exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                days_left = (exp - datetime.now(timezone.utc)).days
                expired = days_left < 0
            except ValueError:
                pass

        sev = Severity.HIGH if expired else Severity.INFO
        detail = f"TLS {proto}"
        if issuer:
            detail += f", issuer {issuer}"
        if not_after:
            detail += f", expires {not_after}"
        if days_left is not None:
            detail += f" ({days_left} days left)"
        result.add(
            Finding(
                title="TLS certificate " + ("EXPIRED" if expired else "OK"),
                severity=sev,
                description=detail,
                evidence={"protocol": proto, "issuer": issuer, "not_after": not_after,
                          "days_left": days_left, "kind": "tls"},
            )
        )
        # Flag legacy protocols.
        if proto and proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            result.add(
                Finding(
                    title=f"Weak TLS protocol supported: {proto}",
                    severity=Severity.MEDIUM,
                    description="Legacy TLS/SSL versions are deprecated and insecure.",
                    evidence={"protocol": proto, "kind": "tls"},
                )
            )

    def _sensitive_paths(self, host: str, result: ModuleResult) -> None:
        base = f"https://{host}"
        for path, (sev, note) in SENSITIVE_PATHS.items():
            try:
                resp = requests.get(
                    base + path, timeout=self.config.timeout + 2, allow_redirects=False,
                    headers={"User-Agent": "z3r0scan"}, verify=False,
                )
            except requests.RequestException:
                continue
            if resp.status_code == 200 and resp.text.strip():
                # For high-value files, require content that looks real, not a
                # generic 200 catch-all / SPA index.
                body = resp.text.lower()
                if path == "/.git/config" and "[core]" not in body:
                    continue
                if path == "/.env" and "=" not in resp.text:
                    continue
                result.add(
                    Finding(
                        title=f"Path exposed: {path} [{resp.status_code}]",
                        severity=sev,
                        description=note,
                        evidence={"url": base + path, "status": resp.status_code, "kind": "path"},
                    )
                )
