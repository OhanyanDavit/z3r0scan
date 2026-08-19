"""Shared data models used across scanner modules and reporting.

Every module produces a :class:`ModuleResult`; the orchestrator collects them
into a single :class:`ScanReport` that the reporter renders.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity levels. String-valued so they serialize cleanly to JSON."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


@dataclass
class Finding:
    """A single observation: an open port, a live host, a vulnerability, etc."""

    title: str
    severity: Severity = Severity.INFO
    description: str = ""
    # Free-form structured evidence (port number, URL, CVE id, banner, ...).
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class ModuleResult:
    """The output of one scanner module for one target."""

    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    # "ok", "skipped" (tool missing / not applicable), or "error".
    status: str = "ok"
    detail: str = ""
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None

    @property
    def duration(self) -> float:
        return (self.ended_at or time.time()) - self.started_at

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "detail": self.detail,
            "duration": round(self.duration, 2),
            "findings": [f.to_dict() for f in self.findings],
        }


@dataclass
class ScanReport:
    """The aggregate of every module result for a single scan run."""

    target: str
    modules: list[ModuleResult] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    ended_at: float | None = None

    @property
    def all_findings(self) -> list[Finding]:
        return [f for m in self.modules for f in m.findings]

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] += 1
        return counts

    @property
    def top_severity(self) -> Severity:
        findings = self.all_findings
        if not findings:
            return Severity.INFO
        return max((f.severity for f in findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration": round((self.ended_at or time.time()) - self.started_at, 2),
            "severity_counts": self.severity_counts(),
            "top_severity": self.top_severity.value,
            "modules": [m.to_dict() for m in self.modules],
        }
