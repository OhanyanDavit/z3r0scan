"""Passive subdomain enumeration — a real recon pipeline.

Enumerating from passive sources (subfinder, crt.sh) returns a lot of noise:
names that appeared in a certificate once and no longer exist. This module
does what a hunter actually does — it **resolves** every candidate and reports
only the ones that still exist in DNS, with their IP addresses:

    enumerate (subfinder + crt.sh)  ->  resolve (dnsx / DNS)  ->  live subdomains

That turns tens of thousands of junk names into a short, real attack surface.
"""

from __future__ import annotations

import json
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, is_ip, normalize_host, run
from .base import ScanModule

try:
    import requests
except ImportError:  # pragma: no cover
    requests = None

# Cap how many resolving subdomains we list as findings (total is always in the
# detail line). Also cap how many candidates we resolve in the Python fallback.
MAX_LISTED = 200
MAX_PY_RESOLVE = 4000


class SubdomainModule(ScanModule):
    name = "subdomains"
    description = "Subdomain recon: enumerate (subfinder+crt.sh) → resolve → live only"
    optional_tools = ("subfinder", "dnsx")

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        host = normalize_host(target)
        if is_ip(host):
            return self._finish(result, "skipped", "target is an IP; no subdomains to enumerate")

        # 1) Enumerate candidates from passive sources.
        candidates: set[str] = set()
        sources: list[str] = []
        if have_tool("subfinder"):
            subs = self._subfinder(host)
            if subs:
                sources.append(f"subfinder({len(subs)})")
            candidates |= subs
        if requests is not None:
            subs = self._crtsh(host)
            if subs:
                sources.append(f"crt.sh({len(subs)})")
            candidates |= subs

        if not candidates:
            if not have_tool("subfinder") and requests is None:
                return self._finish(result, "skipped", "no subfinder and requests not installed")
            return self._finish(result, "ok", "no candidate subdomains found")

        # 2) Resolve — keep only names that still exist in DNS.
        resolved, resolver = self._resolve(candidates)

        # 3) Report the real, resolving subdomains.
        for sub in sorted(resolved)[:MAX_LISTED]:
            ips = resolved[sub]
            result.add(
                Finding(
                    title=f"{sub} → {', '.join(ips[:3])}",
                    severity=Severity.INFO,
                    description=f"Resolving subdomain ({len(ips)} IP(s))",
                    evidence={"host": sub, "ips": ips, "kind": "subdomain"},
                )
            )

        detail = (
            f"{len(resolved)} resolving of {len(candidates)} discovered "
            f"[{' + '.join(sources)}; resolved via {resolver}]"
        )
        if len(resolved) > MAX_LISTED:
            detail += f" (listing first {MAX_LISTED})"
        if not resolved:
            detail = f"0 of {len(candidates)} candidates resolve [{' + '.join(sources)}]"
        return self._finish(result, "ok", detail)

    # -- enumeration -------------------------------------------------------
    @staticmethod
    def _in_scope(name: str, host: str) -> bool:
        """True only if ``name`` is the apex or a real subdomain of ``host``.

        A plain ``endswith(host)`` check wrongly accepts ``notexample.com`` for
        ``example.com`` — the match must land on a label (dot) boundary.
        """
        return name == host or name.endswith("." + host)

    def _subfinder(self, host: str) -> set[str]:
        code, out, _ = run(["subfinder", "-silent", "-all", "-d", host], timeout=300)
        if code != 0 and not out:
            return set()
        names = (ln.strip().lower() for ln in out.splitlines() if ln.strip())
        return {n for n in names if self._in_scope(n, host)}

    def _crtsh(self, host: str) -> set[str]:
        found: set[str] = set()
        try:
            resp = requests.get(
                "https://crt.sh/", params={"q": f"%.{host}", "output": "json"},
                timeout=self.config.timeout + 20, headers={"User-Agent": "z3r0scan"},
            )
            if resp.status_code != 200:
                return found
            for entry in json.loads(resp.text or "[]"):
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.").lower()
                    if self._in_scope(name, host):
                        found.add(name)
        except (requests.RequestException, ValueError):
            pass
        return found

    # -- resolution --------------------------------------------------------
    def _resolve(self, candidates: set[str]) -> tuple[dict[str, list[str]], str]:
        """Return {subdomain: [ips]} for names that resolve, and the resolver used."""
        if have_tool("dnsx"):
            resolved = self._dnsx(candidates)
            if resolved:
                return resolved, "dnsx"
        return self._python_resolve(candidates), "DNS"

    def _dnsx(self, candidates: set[str]) -> dict[str, list[str]]:
        code, out, _ = run(
            ["dnsx", "-silent", "-a", "-json"],
            timeout=300,
            input_text="\n".join(sorted(candidates)),
        )
        resolved: dict[str, list[str]] = {}
        if code != 0 and not out:
            return resolved
        for line in out.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            host = data.get("host", "").strip().lower()
            ips = data.get("a") or []
            if host and ips:
                resolved[host] = ips
        return resolved

    def _python_resolve(self, candidates: set[str]) -> dict[str, list[str]]:
        subset = sorted(candidates)[:MAX_PY_RESOLVE]
        resolved: dict[str, list[str]] = {}
        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(self._lookup, h): h for h in subset}
            for fut in as_completed(futures):
                host = futures[fut]
                ips = fut.result()
                if ips:
                    resolved[host] = ips
        return resolved

    def _lookup(self, host: str) -> list[str]:
        try:
            _, _, ips = socket.gethostbyname_ex(host)
            return ips
        except (socket.gaierror, socket.herror, OSError):
            return []
