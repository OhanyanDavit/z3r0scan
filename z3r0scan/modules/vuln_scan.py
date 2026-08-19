"""Template-based vulnerability scanning via nuclei.

nuclei has no reasonable pure-Python equivalent, so this module skips cleanly
when the binary is absent and tells the user how to enable it.
"""

from __future__ import annotations

import json

from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, normalize_host, run
from .base import ScanModule

# Map nuclei severity strings onto our Severity enum.
SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class VulnScanModule(ScanModule):
    name = "vuln_scan"
    description = "Template-based vulnerability scan (nuclei)"
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
        code, out, err = run(
            ["nuclei", "-silent", "-jsonl", "-u", url],
            timeout=600,
        )
        if code == -1:
            return self._finish(result, "error", err or "nuclei failed to run")

        count = 0
        for line in out.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            info = data.get("info", {})
            sev = SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            result.add(
                Finding(
                    title=info.get("name", data.get("template-id", "nuclei finding")),
                    severity=sev,
                    description=info.get("description", "") or data.get("matched-at", ""),
                    evidence={
                        "template": data.get("template-id"),
                        "matched_at": data.get("matched-at"),
                        "type": data.get("type"),
                    },
                )
            )
            count += 1
        return self._finish(result, "ok", f"{count} nuclei findings")
