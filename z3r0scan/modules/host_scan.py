"""Host / port scanning.

Uses nmap when available (service + version detection). Falls back to a
threaded pure-Python TCP connect scan over the configured port list.

False-positive controls:
  * Severity for "notable" ports is only escalated when the service is
    **confirmed** — nmap returned a real service name (not ``tcpwrapped`` and
    not a ``?``-suffixed guess). Unconfirmed hits are reported as INFO.
  * If the target is behind a CDN/WAF, the whole port list is treated as edge
    artifacts: nothing is escalated and a prominent notice is emitted.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..cdn import detect_cdn
from ..models import Confidence, Finding, ModuleResult, Severity
from ..utils import have_tool, is_ip, normalize_host, resolve, run
from .base import ScanModule

# Substrings that, if present in a TCP banner, confirm the guessed service for a
# port. A bare TCP connect proves nothing; a banner that names the wrong service
# (e.g. an SSH banner answering on 2375) must NOT confirm a Docker API — that is
# exactly how a false "critical" is manufactured.
BANNER_MARKERS: dict[int, tuple[str, ...]] = {
    21: ("ftp",),
    22: ("ssh",),
    25: ("smtp", "esmtp"),
    110: ("pop3", "+ok"),
    143: ("imap",),
    3306: ("mysql", "mariadb"),
    5432: ("postgres",),
    6379: ("redis",),
}

# Ports worth flagging as higher severity WHEN the service is confirmed.
NOTABLE_PORTS = {
    23: (Severity.HIGH, "Telnet — cleartext remote access"),
    21: (Severity.MEDIUM, "FTP — often anonymous / cleartext"),
    3389: (Severity.MEDIUM, "RDP — common brute-force target"),
    3306: (Severity.MEDIUM, "MySQL exposed to network"),
    5432: (Severity.MEDIUM, "PostgreSQL exposed to network"),
    6379: (Severity.HIGH, "Redis — frequently unauthenticated"),
    27017: (Severity.HIGH, "MongoDB — frequently unauthenticated"),
    9200: (Severity.HIGH, "Elasticsearch — frequently unauthenticated"),
    11211: (Severity.HIGH, "Memcached — UDP amplification / no auth"),
    2375: (Severity.CRITICAL, "Docker API — unauth = host takeover"),
}


class HostScanModule(ScanModule):
    name = "host_scan"
    description = "TCP port + service scan (nmap, pure-Python fallback)"
    optional_tools = ("nmap",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        host = normalize_host(target)
        if not host:
            return self._finish(result, "error", "empty or invalid target")
        # An unresolvable hostname is an error, not a clean "0 findings" result.
        if not is_ip(host) and resolve(host) is None:
            return self._finish(result, "error", f"could not resolve target: {host}")

        # Detect CDN/WAF up front so we can flag edge artifacts.
        cdn = detect_cdn(host, timeout=self.config.timeout + 2)
        self._edge = cdn.detected
        if cdn.detected:
            result.add(
                Finding(
                    title=f"⚠ Behind {cdn.provider} — open ports reflect the CDN edge, not the origin",
                    severity=Severity.INFO,
                    description=cdn.note,
                    evidence={"cdn": cdn.provider, "method": cdn.method, "ip": cdn.ip},
                )
            )

        if have_tool("nmap"):
            self._nmap_scan(host, result)
            detail = "nmap"
        else:
            self._python_scan(host, result)
            detail = "pure-python fallback (install nmap for service/version detection)"
        if self._edge:
            detail += f" · behind {cdn.provider}: port results are edge artifacts"
        return self._finish(result, "ok", detail)

    # -- nmap path ---------------------------------------------------------
    def _nmap_scan(self, host: str, result: ModuleResult) -> None:
        ports = ",".join(str(p) for p in self.config.ports)
        code, out, _err = run(
            ["nmap", "-Pn", "-sV", "--open", "-p", ports, "-T4", host],
            timeout=300,
        )
        if code != 0 and not out:
            self._python_scan(host, result)
            return
        # Lines like: "80/tcp open  http    nginx 1.25.3"  or  "2375/tcp open docker?"
        for line in out.splitlines():
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
            if not m:
                continue
            port = int(m.group(1))
            raw_service = m.group(2)
            version = m.group(3).strip()
            # A trailing '?' or 'tcpwrapped' means nmap could NOT confirm it.
            confirmed = not raw_service.endswith("?") and raw_service != "tcpwrapped"
            service = raw_service.rstrip("?")
            self._record_port(result, port, service, version, confirmed)

    # -- pure-python path --------------------------------------------------
    def _python_scan(self, host: str, result: ModuleResult) -> None:
        open_ports: list[int] = []
        with ThreadPoolExecutor(max_workers=self.config.threads) as pool:
            futures = {pool.submit(self._probe, host, p): p for p in self.config.ports}
            for fut in as_completed(futures):
                port = futures[fut]
                if fut.result():
                    open_ports.append(port)
        for port in sorted(open_ports):
            # A bare TCP connect cannot confirm the service — attempt a light
            # banner grab; only then treat a notable port as confirmed.
            banner = self._grab_banner(host, port)
            confirmed = self._banner_confirms(port, banner)
            self._record_port(result, port, self._guess_service(port), banner[:60], confirmed)

    def _probe(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=self.config.timeout):
                return True
        except (OSError, socket.timeout):
            return False

    def _grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=self.config.timeout) as sock:
                sock.settimeout(self.config.timeout)
                data = sock.recv(128)
                return data.decode("latin-1", "replace").strip()
        except (OSError, socket.timeout):
            return ""

    @staticmethod
    def _banner_confirms(port: int, banner: str) -> bool:
        """Confirm a service only if the banner actually names it.

        An empty banner, or a banner that matches a *different* service, does not
        confirm the port's guessed service. Ports whose real service emits no
        useful banner (HTTP-based APIs like Docker's 2375) can never be confirmed
        this way and stay unescalated — which is the safe default.
        """
        markers = BANNER_MARKERS.get(port)
        if not markers or not banner:
            return False
        low = banner.lower()
        return any(m in low for m in markers)

    def _record_port(
        self, result: ModuleResult, port: int, service: str, version: str, confirmed: bool
    ) -> None:
        notable = NOTABLE_PORTS.get(port)
        edge = getattr(self, "_edge", False)
        trustworthy = confirmed and not edge

        if notable and trustworthy:
            sev, note = notable
            tag = ""
            confidence = Confidence.HIGH
        elif notable:
            # Notable port but we can't trust it — report as an observation, not
            # a vulnerability, and say what a human still needs to verify.
            sev = Severity.INFO
            note = notable[1]
            confidence = Confidence.LOW
            tag = (
                " (unconfirmed — behind CDN)" if edge
                else " (unconfirmed — port open but service not verified)"
            )
        else:
            sev, note, tag = Severity.INFO, "", ""
            confidence = Confidence.HIGH if trustworthy else Confidence.LOW

        title = f"{port}/tcp open — {service or 'unknown'}{tag}"
        desc = f"Open TCP port {port} ({service or 'unknown'})"
        if version:
            desc += f" — {version}"
        if note:
            desc += f" · {note}"
        if tag:
            desc += f" · {tag.strip()}"

        result.add(
            Finding(
                title=title,
                severity=sev,
                description=desc,
                confidence=confidence,
                evidence={
                    "port": port,
                    "service": service,
                    "version": version,
                    "confirmed": trustworthy,
                    "edge": edge,
                },
            )
        )

    @staticmethod
    def _guess_service(port: int) -> str:
        common = {
            21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
            80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
            3306: "mysql", 3389: "rdp", 5432: "postgresql", 6379: "redis",
            8080: "http-alt", 8443: "https-alt", 27017: "mongodb", 9200: "elasticsearch",
        }
        return common.get(port, "")
