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

from ..cdn import detect_cdn
from ..models import Finding, ModuleResult, Severity
from ..utils import have_tool, normalize_host, run
from .base import ScanModule
from .web_probe import candidate_urls

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

        # Preserve any explicit scheme/port the user gave (http://host:8080),
        # so local labs on non-standard ports (DVWA, Juice Shop) actually get
        # scanned instead of being rewritten to https://host.
        url = candidate_urls(target)[0]
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
        code, out, err = run(cmd, timeout=900, cancel_event=self.config.cancel_event)
        # -1 is our sentinel for "could not run / timed out"; any other nonzero
        # exit with no parseable output is also a failure, not a clean result.
        if code != 0 and not out.strip():
            reason = err.strip() or f"nuclei exited {code} with no output"
            return self._finish(result, "error", reason)

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
            # No findings is NOT proof the target is clean — nuclei may have been
            # blocked, rate-limited, or served a challenge. State only what we know.
            # A CDN/WAF in front of the target is the most common reason a template
            # run comes back empty, so call it out explicitly when detected.
            detail = f"no findings returned by nuclei for {url}"
            cdn = detect_cdn(normalize_host(target))
            if cdn.detected:
                note = (
                    f"target is behind {cdn.provider} (via {cdn.method}) — nuclei is "
                    "hitting the CDN/WAF edge, which blocks most templates; an empty "
                    "result here does not mean the origin is clean. Test the origin "
                    "directly if you can reach it."
                )
                detail += f" · {note}"
                result.add(
                    Finding(
                        title="nuclei blind behind CDN/WAF",
                        severity=Severity.INFO,
                        description=note,
                        evidence={"kind": "vuln", "cdn": cdn.provider, "method": cdn.method},
                    )
                )
                return self._finish(result, "ok", detail)
            return self._finish(result, "ok", detail)
        summary = ", ".join(f"{k}:{v}" for k, v in counts.items())
        return self._finish(result, "ok", f"{len(result.findings)} nuclei findings ({summary})")
