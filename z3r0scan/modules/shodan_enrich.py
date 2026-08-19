"""Passive enrichment via the Shodan API.

This is the "just give it an API token" path: with SHODAN_API_KEY set, the
module pulls Shodan's existing view of the host (open ports, detected
products, known CVEs) with zero packets sent to the target.
"""

from __future__ import annotations

from ..models import Finding, ModuleResult, Severity
from ..utils import is_ip, normalize_host, resolve
from .base import ScanModule

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None


class ShodanModule(ScanModule):
    name = "shodan"
    description = "Passive host enrichment via Shodan API (needs SHODAN_API_KEY)"

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        if not self.config.shodan_api_key:
            return self._finish(result, "skipped", "no SHODAN_API_KEY configured")
        if requests is None:
            return self._finish(result, "skipped", "requests not installed")

        host = normalize_host(target)
        ip = host if is_ip(host) else resolve(host)
        if not ip:
            return self._finish(result, "error", "could not resolve target to an IP")

        try:
            resp = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.config.shodan_api_key},
                timeout=self.config.timeout + 10,
            )
        except requests.RequestException as exc:
            return self._finish(result, "error", f"shodan request failed: {exc}")

        if resp.status_code == 404:
            return self._finish(result, "ok", "no Shodan records for this host")
        if resp.status_code == 401:
            return self._finish(result, "error", "invalid Shodan API key")
        if resp.status_code != 200:
            return self._finish(result, "error", f"shodan returned HTTP {resp.status_code}")

        data = resp.json()
        ports = data.get("ports", [])
        if ports:
            result.add(
                Finding(
                    title=f"Shodan sees {len(ports)} open port(s)",
                    severity=Severity.INFO,
                    description=f"Ports: {', '.join(map(str, sorted(ports)))}",
                    evidence={"ip": ip, "ports": sorted(ports)},
                )
            )
        for cve in sorted(data.get("vulns", []) or []):
            result.add(
                Finding(
                    title=cve,
                    severity=Severity.HIGH,
                    description="CVE reported by Shodan for a service on this host.",
                    evidence={"ip": ip, "cve": cve},
                )
            )
        for item in data.get("data", []):
            product = item.get("product")
            if product:
                result.add(
                    Finding(
                        title=f"{product} on port {item.get('port')}",
                        severity=Severity.INFO,
                        description=(item.get("version") and f"Version {item['version']}") or "Detected by Shodan.",
                        evidence={"port": item.get("port"), "product": product, "version": item.get("version")},
                    )
                )
        return self._finish(result, "ok", f"{len(result.findings)} enrichment items")
