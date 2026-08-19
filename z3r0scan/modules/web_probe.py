"""Web probing (enhanced).

Live-service detection via httpx when available, else Python requests. On top of
that it always runs safe, non-intrusive checks:
  * security-header analysis
  * TLS certificate inspection (issuer, expiry)
  * common sensitive-path exposure (/.git/config, /.env, /robots.txt, ...)

Honors an explicit scheme and/or port in the target (e.g. ``http://host:8080``),
so local labs on non-standard ports work.
"""

from __future__ import annotations

import json
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, is_ipv6, run
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

# A browser-like UA reduces trivial bot blocks. Real WAF challenges (JS/CAPTCHA)
# still can't be solved by an HTTP client — those are reported, not bypassed.
BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)
# Markers that a response is a WAF/bot challenge rather than the real site.
CHALLENGE_MARKERS = ("just a moment", "attention required", "cf-chl", "cf-mitigated",
                     "checking your browser", "captcha", "access denied")
HTTPS_PORTS = {"443", "8443"}


def candidate_urls(target: str) -> list[str]:
    """Turn a raw target into ordered candidate base URLs, honoring any explicit
    scheme/port. ``http://h:8080`` -> [that]; ``h:8080`` -> [http(s)://h:8080];
    bare host -> [https://h, http://h]."""
    t = target.strip()
    if t.startswith(("http://", "https://")):
        return [t.rstrip("/")]
    # host:port (but not bare IPv6)
    if t.count(":") == 1 and not is_ipv6(t):
        _host, port = t.split(":")
        if port.isdigit():
            scheme = "https" if port in HTTPS_PORTS else "http"
            return [f"{scheme}://{t}"]
    return [f"https://{t}", f"http://{t}"]


class WebProbeModule(ScanModule):
    name = "web_probe"
    description = "HTTP(S) probe: status, title, headers, TLS, sensitive paths"
    optional_tools = ("httpx",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)

        if requests is None and not have_tool("httpx"):
            return self._finish(result, "skipped", "no httpx and requests not installed")

        base_url = None
        if have_tool("httpx"):
            base_url = self._httpx(target, result)
        if base_url is None and requests is not None:
            base_url = self._requests_probe(target, result)

        if requests is not None and base_url:
            self._tls_info(base_url, result)
            self._sensitive_paths(base_url, result)

        # Don't go silent: if nothing on the web layer responded, say why.
        if base_url is None:
            result.add(
                Finding(
                    title="No usable HTTP response",
                    severity=Severity.INFO,
                    description=(
                        "No web service returned content. The target may not serve HTTP, "
                        "or a WAF/CDN is blocking automated scanners (common with Cloudflare "
                        "Bot Management). Try a browser to confirm, or test the origin directly."
                    ),
                    evidence={"kind": "live", "responded": False},
                )
            )
        tool = "httpx" if have_tool("httpx") else "pure-python"
        return self._finish(
            result, "ok", tool if base_url else f"{tool} — no HTTP response (possible WAF block)"
        )

    def _httpx(self, target: str, result: ModuleResult) -> str | None:
        code, out, _ = run(
            ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect",
             "-follow-redirects", "-H", f"User-Agent: {BROWSER_UA}", "-u", target],
            timeout=120,
        )
        if code != 0:
            return None
        base_url = None
        for line in out.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            url = data.get("url", target)
            base_url = base_url or url
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
        return base_url

    def _requests_probe(self, target: str, result: ModuleResult) -> str | None:
        for url in candidate_urls(target):
            try:
                resp = requests.get(
                    url, timeout=self.config.timeout + 7, allow_redirects=True,
                    headers={"User-Agent": BROWSER_UA}, verify=False,
                )
            except requests.RequestException:
                continue

            title_m = TITLE_RE.search(resp.text or "")
            title = title_m.group(1).strip()[:120] if title_m else ""
            server = resp.headers.get("Server", "")
            body = (resp.text or "").lower()
            challenged = resp.status_code in (403, 429, 503) and any(
                m in body or m in str(resp.headers).lower() for m in CHALLENGE_MARKERS
            )
            if challenged:
                result.add(
                    Finding(
                        title=f"{url} [{resp.status_code}] WAF/bot challenge",
                        severity=Severity.INFO,
                        description=(
                            f"A web server is present but a WAF is challenging scanners "
                            f"(Server: {server or 'unknown'}). Real content is gated behind a "
                            "JS/CAPTCHA challenge that HTTP clients can't solve."
                        ),
                        evidence={"url": resp.url, "status": resp.status_code, "server": server,
                                  "waf_challenge": True, "kind": "live"},
                    )
                )
            else:
                result.add(
                    Finding(
                        title=f"{url} [{resp.status_code}] {title}".strip(),
                        severity=Severity.INFO,
                        description=f"Live web service. Server: {server}" if server else "Live web service.",
                        evidence={"url": resp.url, "status": resp.status_code, "title": title,
                                  "server": server, "kind": "live"},
                    )
                )
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
            return url
        return None

    def _tls_info(self, base_url: str, result: ModuleResult) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https":
            return  # nothing to inspect on plain HTTP
        host = parts.hostname
        port = parts.port or 443
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock, \
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
        if proto and proto in ("TLSv1", "TLSv1.1", "SSLv3"):
            result.add(
                Finding(
                    title=f"Weak TLS protocol supported: {proto}",
                    severity=Severity.MEDIUM,
                    description="Legacy TLS/SSL versions are deprecated and insecure.",
                    evidence={"protocol": proto, "kind": "tls"},
                )
            )

    def _sensitive_paths(self, base_url: str, result: ModuleResult) -> None:
        base = base_url.rstrip("/")
        for path, (sev, note) in SENSITIVE_PATHS.items():
            try:
                resp = requests.get(
                    base + path, timeout=self.config.timeout + 2, allow_redirects=False,
                    headers={"User-Agent": BROWSER_UA}, verify=False,
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
