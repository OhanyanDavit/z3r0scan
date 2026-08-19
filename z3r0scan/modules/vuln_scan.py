"""Template-based vulnerability scanning via nuclei ("deep" web scan).

nuclei ships thousands of community templates covering CVEs, exposures,
misconfigurations, default creds, and more. This module runs it against the
target's web endpoint with sensible, non-destructive defaults and maps its
findings into the shared severity model.

nuclei has no reasonable pure-Python equivalent, so the module skips cleanly
when the binary is absent and tells the user how to install it.
"""

from __future__ import annotations

import json

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, normalize_host, run
from .base import ScanModule

SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}

BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"
)


class VulnScanModule(ScanModule):
    name = "vuln_scan"
    description = "Deep template-based vulnerability scan (nuclei)"
    optional_tools = ("nuclei",)

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)
        if not have_tool("nuclei"):
            return self._finish(
                result,
                "skipped",
                "nuclei not installed — see https://github.com/projectdiscovery/nuclei",
            )

        host = normalize_host(target)
        url = host if host.startswith("http") else f"https://{host}"
        cmd = [
            "nuclei",
            "-u", url,
            "-jsonl",
            "-silent",
            "-no-color",
            "-disable-update-check",
            "-follow-redirects",
            "-severity", "low,medium,high,critical",  # skip info-level noise
            "-rate-limit", "150",
            "-timeout", "10",
            "-retries", "1",
            "-H", f"User-Agent: {BROWSER_UA}",
        ]
        # Give nuclei plenty of time; a broad template run is slow.
        code, out, err = run(cmd, timeout=900)
        if code == -1 and not out:
            return self._finish(result, "error", err or "nuclei failed to run")

        counts: dict[str, int] = {}
        for line in out.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            info = data.get("info", {})
            sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            counts[sev.value] = counts.get(sev.value, 0) + 1
            result.add(
                Finding(
                    title=info.get("name", data.get("template-id", "nuclei finding")),
                    severity=sev,
                    description=info.get("description", "") or data.get("matched-at", ""),
                    evidence={
                        "template": data.get("template-id"),
                        "matched_at": data.get("matched-at"),
                        "type": data.get("type"),
                        "reference": info.get("reference"),
                        "kind": "vuln",
                    },
                )
            )

        if not result.findings:
            return self._finish(result, "ok", "0 nuclei findings (target clean or WAF-blocked)")
        summary = ", ".join(f"{k}:{v}" for k, v in counts.items())
        return self._finish(result, "ok", f"{len(result.findings)} nuclei findings ({summary})")
