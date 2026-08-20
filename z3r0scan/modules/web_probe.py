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

from ..models import Confidence, Finding, ModuleResult, Severity
from ..utils import have_tool, is_ipv6, run
from .base import ScanModule

# Cap how much of any response body we pull into memory — a sensitive-path probe
# should never download a multi-gigabyte file.
MAX_BODY_BYTES = 64 * 1024


def _describe_cert(der: bytes | None) -> str:
    """Best-effort human description of a DER cert (issuer/expiry).

    Uses ``cryptography`` if installed; returns an empty string otherwise so the
    TLS check still works without the optional dependency.
    """
    if not der:
        return ""
    try:
        from cryptography import x509
    except ImportError:
        return ""
    try:
        cert = x509.load_der_x509_certificate(der)
        issuer = cert.issuer.rfc4514_string()
        not_after = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        self_signed = cert.issuer == cert.subject
        tag = " (self-signed)" if self_signed else ""
        return f"Presented cert: issuer {issuer}, expires {not_after}{tag}."
    except Exception:  # noqa: BLE001
        return ""

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
            # Header analysis runs for BOTH probe paths (httpx and requests) so
            # the "enhanced scan" the README promises is always applied.
            self._header_check(base_url, result)
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
            return url
        return None

    def _header_check(self, base_url: str, result: ModuleResult) -> None:
        """Security-header analysis for the confirmed base URL (both probe paths).

        Header presence depends on scheme and content type, so we don't blindly
        flag every header everywhere: HSTS is only relevant over HTTPS, and CSP /
        X-Frame-Options matter for HTML responses, not JSON APIs.
        """
        try:
            resp = requests.get(
                base_url, timeout=self.config.timeout + 5, allow_redirects=True,
                headers={"User-Agent": BROWSER_UA}, verify=False,
            )
        except requests.RequestException:
            return
        scheme = urlsplit(resp.url).scheme
        ctype = resp.headers.get("Content-Type", "").lower()
        is_html = "text/html" in ctype or ctype == ""
        lower = {k.lower(): v for k, v in resp.headers.items()}
        for header, note in SECURITY_HEADERS.items():
            if header in lower:
                continue
            if header == "strict-transport-security" and scheme != "https":
                continue  # HSTS is meaningless over plain HTTP
            if header in ("content-security-policy", "x-frame-options") and not is_html:
                continue  # framing/XSS headers apply to HTML documents
            result.add(
                Finding(
                    title=f"Missing header: {header}",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description=note,
                    evidence={"url": resp.url, "header": header, "kind": "header"},
                )
            )

    def _tls_info(self, base_url: str, result: ModuleResult) -> None:
        parts = urlsplit(base_url)
        if parts.scheme != "https":
            return  # nothing to inspect on plain HTTP
        host = parts.hostname
        port = parts.port or 443

        # 1) Try a FULLY VERIFIED handshake — hostname + chain + expiry checked.
        try:
            vctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock, \
                    vctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                proto = tls.version()
            self._record_valid_cert(result, cert, proto)
            return
        except ssl.SSLCertVerificationError as exc:
            reason = getattr(exc, "verify_message", "") or str(exc)
        except (OSError, ssl.SSLError, socket.timeout) as exc:
            result.add(
                Finding(
                    title="TLS connection failed",
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description=f"Could not complete a TLS handshake: {type(exc).__name__}",
                    evidence={"kind": "tls", "error": type(exc).__name__},
                )
            )
            return

        # 2) Verification FAILED — report it accurately (never "OK"). Reconnect
        #    without verification only to extract descriptive cert details.
        proto = None
        details = ""
        try:
            uctx = ssl.create_default_context()
            uctx.check_hostname = False
            uctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock, \
                    uctx.wrap_socket(sock, server_hostname=host) as tls:
                proto = tls.version()
                der = tls.getpeercert(binary_form=True)
            details = _describe_cert(der)
        except (OSError, ssl.SSLError, socket.timeout):
            pass

        sev = Severity.HIGH if "expired" in reason.lower() else Severity.MEDIUM
        result.add(
            Finding(
                title="TLS certificate validation failed",
                severity=sev,
                confidence=Confidence.HIGH,
                description=f"{reason}." + (f" {details}" if details else ""),
                evidence={"kind": "tls", "protocol": proto, "verify_error": reason},
            )
        )

    def _record_valid_cert(self, result: ModuleResult, cert: dict, proto: str | None) -> None:
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "") if cert else ""
        not_after = cert.get("notAfter", "") if cert else ""
        days_left = None
        try:
            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (exp - datetime.now(timezone.utc)).days
        except ValueError:
            pass
        detail = f"Verified TLS {proto}"
        if issuer:
            detail += f", issuer {issuer}"
        if not_after:
            detail += f", expires {not_after}"
        if days_left is not None:
            detail += f" ({days_left} days left)"
        # A verified cert nearing expiry is worth a low-severity nudge.
        sev = Severity.LOW if (days_left is not None and days_left < 15) else Severity.INFO
        result.add(
            Finding(
                title="TLS certificate valid",
                severity=sev,
                confidence=Confidence.VERIFIED,
                description=detail,
                evidence={"protocol": proto, "issuer": issuer, "not_after": not_after,
                          "days_left": days_left, "kind": "tls", "verified": True},
            )
        )

    def _sensitive_paths(self, base_url: str, result: ModuleResult) -> None:
        base = base_url.rstrip("/")
        # Baseline: a random path that shouldn't exist. If the server answers it
        # with 200 + a body, it has an SPA/catch-all handler and a 200 on a
        # sensitive path proves nothing — so we skip generic matches.
        baseline = self._fetch(base + "/z3r0scan-nonexistent-" + "a1b2c3d4")
        catch_all = bool(baseline and baseline[0] == 200 and baseline[1].strip())
        baseline_body = baseline[1] if baseline else ""

        for path, (sev, note) in SENSITIVE_PATHS.items():
            fetched = self._fetch(base + path)
            if not fetched:
                continue
            status, body = fetched
            if status != 200 or not body.strip():
                continue
            low = body.lower()
            # Reject responses that look like the catch-all page.
            if catch_all and body.strip() == baseline_body.strip():
                continue
            # Path-specific signatures — a bare 200 is never enough.
            if path == "/.git/config" and "[core]" not in low:
                continue
            if path == "/.env" and ("<html" in low or low.count("=") < 2):
                continue
            if path == "/server-status" and "apache" not in low and "server uptime" not in low:
                continue
            if path == "/admin" and catch_all:
                continue  # generic 200 on /admin behind an SPA is noise
            result.add(
                Finding(
                    title=f"Path exposed: {path} [{status}]",
                    severity=sev,
                    confidence=Confidence.MEDIUM,
                    description=note,
                    evidence={"url": base + path, "status": status, "kind": "path"},
                )
            )

    def _fetch(self, url: str) -> tuple[int, str] | None:
        """GET a URL with a bounded body read. Returns (status, body) or None."""
        try:
            resp = requests.get(
                url, timeout=self.config.timeout + 2, allow_redirects=False,
                headers={"User-Agent": BROWSER_UA}, verify=False, stream=True,
            )
        except requests.RequestException:
            return None
        try:
            raw = resp.raw.read(MAX_BODY_BYTES, decode_content=True) or b""
        except Exception:  # noqa: BLE001 - fall back to whatever requests buffered
            raw = (resp.content or b"")[:MAX_BODY_BYTES]
        finally:
            resp.close()
        return resp.status_code, raw.decode("utf-8", "replace")
