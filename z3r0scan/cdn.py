"""CDN / WAF detection.

When a target sits behind a CDN or reverse proxy (Cloudflare, Fastly, Akamai,
...), a port scan hits the *edge*, not the origin. Many proxies answer the TCP
handshake on a wide range of ports, which makes a naive scan report dozens of
"open" ports that don't correspond to any real service. Detecting this lets the
scanner label those results as edge artifacts instead of crying wolf.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .utils import resolve

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# Well-known published CDN network ranges (subset — enough to catch the common
# case reliably; header checks below cover the rest).
CDN_RANGES: dict[str, list[str]] = {
    "Cloudflare": [
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
        "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
        "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    ],
    "Fastly": ["151.101.0.0/16", "199.232.0.0/16"],
    "Amazon CloudFront": ["13.32.0.0/15", "13.224.0.0/14", "143.204.0.0/16", "99.84.0.0/16"],
}

# Header / value signatures for proxies we can't pin down by IP alone.
HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("server", "cloudflare", "Cloudflare"),
    ("cf-ray", "", "Cloudflare"),
    ("server", "akamaighost", "Akamai"),
    ("x-akamai-transformed", "", "Akamai"),
    ("server", "ecacc", "Akamai"),
    ("x-served-by", "cache-", "Fastly"),
    ("x-fastly-request-id", "", "Fastly"),
    ("server", "cloudfront", "Amazon CloudFront"),
    ("x-amz-cf-id", "", "Amazon CloudFront"),
    ("server", "vercel", "Vercel"),
    ("x-vercel-id", "", "Vercel"),
    ("x-sucuri-id", "", "Sucuri WAF"),
    ("server", "imperva", "Imperva/Incapsula"),
    ("x-cdn", "incapsula", "Imperva/Incapsula"),
]


@dataclass
class CDNResult:
    detected: bool
    provider: str | None = None
    method: str = ""  # "ip-range" or "http-header"
    ip: str | None = None

    @property
    def note(self) -> str:
        if not self.detected:
            return ""
        return (
            f"Target is behind {self.provider} (detected via {self.method}). "
            "Port-scan results reflect the CDN/proxy edge, not the origin server — "
            "treat open ports as unconfirmed."
        )


def _match_ip(ip: str) -> tuple[str, str] | None:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for provider, cidrs in CDN_RANGES.items():
        for cidr in cidrs:
            if addr in ipaddress.ip_network(cidr):
                return provider, "ip-range"
    return None


def _match_headers(host: str, timeout: float) -> tuple[str, str] | None:
    if requests is None:
        return None
    for scheme in ("https", "http"):
        try:
            resp = requests.head(
                f"{scheme}://{host}",
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "z3r0scan"},
                verify=False,
            )
        except requests.RequestException:
            continue
        lower = {k.lower(): str(v).lower() for k, v in resp.headers.items()}
        for header, needle, provider in HEADER_SIGNATURES:
            if header in lower and (needle == "" or needle in lower[header]):
                return provider, "http-header"
        break  # got a response; no need to try the other scheme
    return None


def detect_cdn(host: str, timeout: float = 5.0) -> CDNResult:
    """Best-effort CDN/WAF detection by IP range first, then HTTP headers."""
    ip = resolve(host)
    if ip:
        hit = _match_ip(ip)
        if hit:
            return CDNResult(True, provider=hit[0], method=hit[1], ip=ip)

    hit = _match_headers(host, timeout)
    if hit:
        return CDNResult(True, provider=hit[0], method=hit[1], ip=ip)

    return CDNResult(False, ip=ip)
