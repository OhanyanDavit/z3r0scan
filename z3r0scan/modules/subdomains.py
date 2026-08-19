"""Passive subdomain enumeration.

Queries multiple passive sources and merges the results, so a single slow or
empty source never zeroes out the run:
  * subfinder (if installed) — many sources, optionally API-key powered
  * crt.sh    — Certificate Transparency logs, free, no key

If subfinder times out or returns nothing, crt.sh results are still reported.
"""

from __future__ import annotations

import json

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, is_ip, normalize_host, run
from .base import ScanModule

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# Cap how many individual subdomains we list as findings (the total is always
# reported in the detail line regardless).
MAX_LISTED = 150


class SubdomainModule(ScanModule):
    name = "subdomains"
    description = "Passive subdomain enumeration (subfinder + crt.sh, merged)"
    optional_tools = ("subfinder",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        host = normalize_host(target)
        if is_ip(host):
            return self._finish(result, "skipped", "target is an IP; no subdomains to enumerate")

        found: dict[str, set[str]] = {}  # subdomain -> set of sources
        used_sources: list[str] = []

        if have_tool("subfinder"):
            subs = self._subfinder(host)
            if subs:
                used_sources.append(f"subfinder({len(subs)})")
            for s in subs:
                found.setdefault(s, set()).add("subfinder")

        if requests is not None:
            subs = self._crtsh(host)
            if subs:
                used_sources.append(f"crt.sh({len(subs)})")
            for s in subs:
                found.setdefault(s, set()).add("crt.sh")

        if not have_tool("subfinder") and requests is None:
            return self._finish(result, "skipped", "no subfinder and requests not installed")

        for sub in sorted(found)[:MAX_LISTED]:
            sources = ", ".join(sorted(found[sub]))
            result.add(
                Finding(
                    title=sub,
                    severity=Severity.INFO,
                    description=f"Subdomain discovered via {sources}",
                    evidence={"host": sub, "sources": sorted(found[sub]), "kind": "subdomain"},
                )
            )

        total = len(found)
        detail = f"{total} unique subdomains"
        if used_sources:
            detail += " via " + " + ".join(used_sources)
        if total > MAX_LISTED:
            detail += f" (listing first {MAX_LISTED})"
        if total == 0:
            detail = "no subdomains found (sources returned nothing or timed out)"
        return self._finish(result, "ok", detail)

    def _subfinder(self, host: str) -> set[str]:
        # Generous timeout — large domains have many sources; on timeout we
        # still return whatever crt.sh gives us.
        code, out, _ = run(["subfinder", "-silent", "-all", "-d", host], timeout=300)
        if code != 0 and not out:
            return set()
        return {line.strip().lower() for line in out.splitlines() if line.strip()}

    def _crtsh(self, host: str) -> set[str]:
        found: set[str] = set()
        try:
            resp = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{host}", "output": "json"},
                timeout=self.config.timeout + 20,
                headers={"User-Agent": "z3r0scan"},
            )
            if resp.status_code != 200:
                return found
            for entry in json.loads(resp.text or "[]"):
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if name.endswith(host):
                        found.add(name)
        except (requests.RequestException, ValueError):
            pass
        return found
