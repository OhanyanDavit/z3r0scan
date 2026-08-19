"""Passive subdomain enumeration.

Uses subfinder when available. Otherwise queries crt.sh (Certificate
Transparency logs) over HTTPS — free, no API key, fully passive.
Skips cleanly when the target is a bare IP.
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


class SubdomainModule(ScanModule):
    name = "subdomains"
    description = "Passive subdomain enumeration (subfinder / crt.sh)"
    optional_tools = ("subfinder",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        host = normalize_host(target)
        if is_ip(host):
            return self._finish(result, "skipped", "target is an IP; no subdomains to enumerate")

        subs: set[str] = set()
        source = ""
        if have_tool("subfinder"):
            subs = self._subfinder(host)
            source = "subfinder"
        elif requests is not None:
            subs = self._crtsh(host)
            source = "crt.sh"
        else:
            return self._finish(result, "skipped", "no subfinder and requests not installed")

        for sub in sorted(subs):
            result.add(
                Finding(
                    title=sub,
                    severity=Severity.INFO,
                    description=f"Subdomain discovered via {source}",
                    evidence={"host": sub, "source": source},
                )
            )
        return self._finish(result, "ok", f"{len(subs)} subdomains via {source}")

    def _subfinder(self, host: str) -> set[str]:
        code, out, _ = run(["subfinder", "-silent", "-d", host], timeout=180)
        if code != 0:
            return set()
        return {line.strip() for line in out.splitlines() if line.strip()}

    def _crtsh(self, host: str) -> set[str]:
        found: set[str] = set()
        try:
            resp = requests.get(
                "https://crt.sh/",
                params={"q": f"%.{host}", "output": "json"},
                timeout=self.config.timeout + 10,
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
