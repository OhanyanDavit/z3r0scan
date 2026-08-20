"""Shared plumbing for the AI analysis layer.

An :class:`AIProvider` wraps one LLM backend (Claude, GPT, ...). Providers are
deliberately thin: they take a system prompt + user prompt and return text.
Everything security-specific — how findings are turned into a prompt, how the
result is packaged — lives here so providers stay swappable.

Design mirrors the scanner modules: a provider that is unavailable (SDK missing
or no key) degrades gracefully instead of raising, so the AI step can never
crash a scan.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from ..models import ScanReport, Severity

# Keep the prompt bounded — a huge scan shouldn't blow the context window or the
# user's token budget. We send the most severe findings first and cap the count.
MAX_FINDINGS_IN_PROMPT = 120

SYSTEM_PROMPT = (
    "You are a senior offensive security analyst assisting with an AUTHORIZED "
    "penetration test / bug bounty engagement. You are given the raw output of "
    "an automated recon and scanning run. Your job is to turn that noisy output "
    "into a sharp, human-readable analysis for the tester.\n\n"
    "Rules:\n"
    "- Only reason about the target described in the findings; assume the "
    "engagement is authorized and in-scope.\n"
    "- Be concrete and skeptical. Automated scanners produce false positives; "
    "call out which findings are likely noise (CDN edge artifacts, generic "
    "missing-header warnings, unconfirmed ports) and which are worth a human's "
    "time.\n"
    "- Prioritize by real-world exploitability and impact, not by the scanner's "
    "raw severity label.\n"
    "- Suggest concrete, non-destructive next verification steps a tester would "
    "take. Do not provide instructions for indiscriminate mass exploitation.\n\n"
    "Respond in GitHub-flavored Markdown with these sections, in order:\n"
    "## Executive summary  (2-4 sentences)\n"
    "## Prioritized findings  (a ranked list; for each: what it is, why it "
    "matters or why it's likely noise, and a confidence level)\n"
    "## Likely false positives\n"
    "## Recommended next steps  (concrete, authorized verification actions)\n"
    "Keep it tight. No preamble, no restating these instructions."
)


@dataclass
class AIAnalysis:
    """The result of an AI pass over a scan report."""

    provider: str
    model: str
    status: str = "ok"  # "ok" | "skipped" | "error"
    detail: str = ""
    summary: str = ""  # Markdown produced by the model.
    usage: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AIProvider(ABC):
    """One LLM backend. Subclasses wrap a specific SDK."""

    #: Stable identifier used in config/CLI/UI (e.g. "anthropic", "openai").
    name: str = "base"
    #: Human label shown in the UI.
    label: str = "Base"
    #: Default model if the user doesn't pick one.
    default_model: str = ""

    def __init__(self, api_key: str, model: str | None = None):
        self.api_key = api_key
        self.model = model or self.default_model

    @classmethod
    @abstractmethod
    def sdk_installed(cls) -> bool:
        """True if the provider's SDK can be imported."""

    @abstractmethod
    def complete(self, system: str, user: str) -> tuple[str, dict[str, Any]]:
        """Return (text, usage_dict). May raise; callers handle failures."""


def build_prompt(report: ScanReport) -> str:
    """Serialize a scan report into a compact, severity-ordered prompt body."""
    findings = sorted(
        report.all_findings,
        key=lambda f: f.severity.rank,
        reverse=True,
    )
    total = len(findings)
    shown = findings[:MAX_FINDINGS_IN_PROMPT]

    counts = report.severity_counts()
    lines = [
        f"# Scan of `{report.target}`",
        "",
        "Severity counts: "
        + ", ".join(f"{s}={counts[s]}" for s in ("critical", "high", "medium", "low", "info")),
        f"Total findings: {total}"
        + (f" (showing top {len(shown)} by severity)" if total > len(shown) else ""),
        "",
        "## Modules run",
    ]
    for m in report.modules:
        lines.append(f"- **{m.module}** — status={m.status}; {m.detail or 'no detail'}")
    lines.append("")
    lines.append("## Findings")
    for f in shown:
        sev = f.severity.value.upper() if isinstance(f.severity, Severity) else str(f.severity)
        line = f"- [{sev}] {f.title}"
        if f.description:
            line += f" — {f.description}"
        lines.append(line)
    if not shown:
        lines.append("- (no findings were produced)")
    return "\n".join(lines)
