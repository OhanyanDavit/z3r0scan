"""Host / port scanning.

Uses nmap when available (service + version detection). Falls back to a
threaded pure-Python TCP connect scan over the configured port list so the
tool still produces useful output on a machine without nmap installed.
"""

from __future__ import annotations

import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, normalize_host, resolve, run
from .base import ScanModule

# A few ports worth flagging as higher severity when exposed.
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
        ip = resolve(host)
        if ip is None and not host:
            return self._finish(result, "error", "could not resolve target")

        if have_tool("nmap"):
            self._nmap_scan(host, result)
            detail = "nmap"
        else:
            self._python_scan(host, result)
            detail = "pure-python fallback (install nmap for service/version detection)"
        return self._finish(result, "ok", detail)

    # -- nmap path ---------------------------------------------------------
    def _nmap_scan(self, host: str, result: ModuleResult) -> None:
        ports = ",".join(str(p) for p in self.config.ports)
        code, out, _err = run(
            ["nmap", "-Pn", "-sV", "--open", "-p", ports, "-T4", host],
            timeout=300,
        )
        if code != 0 and not out:
            # nmap failed (permissions, etc.) — degrade to python scan.
            self._python_scan(host, result)
            return
        # Lines like: "80/tcp open  http    nginx 1.25.3"
        for line in out.splitlines():
            m = re.match(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)$", line.strip())
            if not m:
                continue
            port = int(m.group(1))
            service = m.group(2)
            version = m.group(3).strip()
            self._record_port(result, port, service, version)

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
            self._record_port(result, port, self._guess_service(port), "")

    def _probe(self, host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=self.config.timeout):
                return True
        except (OSError, socket.timeout):
            return False

    def _record_port(self, result: ModuleResult, port: int, service: str, version: str) -> None:
        sev, note = NOTABLE_PORTS.get(port, (Severity.INFO, ""))
        desc = f"Open TCP port {port} ({service or 'unknown'})"
        if version:
            desc += f" — {version}"
        if note:
            desc += f" · {note}"
        result.add(
            Finding(
                title=f"{port}/tcp open — {service or 'unknown'}",
                severity=sev,
                description=desc,
                evidence={"port": port, "service": service, "version": version},
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
