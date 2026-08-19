"""Base class every scanner module inherits from.

A module takes a target + shared :class:`Config`, does its work, and returns a
:class:`ModuleResult`. Modules must be self-contained and must degrade
gracefully: if a required external tool is missing, mark the result "skipped"
rather than raising.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from ..config import Config
from ..models import ModuleResult


class ScanModule(ABC):
    #: Stable identifier used in config, CLI selection, and reports.
    name: str = "base"
    #: Human-readable one-liner shown in the CLI.
    description: str = ""
    #: External binaries this module can use (empty = pure Python).
    optional_tools: tuple[str, ...] = ()

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def run(self, target: str) -> ModuleResult:
        """Execute the scan against ``target`` and return a result."""
        raise NotImplementedError

    def _result(self, target: str) -> ModuleResult:
        return ModuleResult(module=self.name, target=target, started_at=time.time())

    def _finish(self, result: ModuleResult, status: str = "ok", detail: str = "") -> ModuleResult:
        result.status = status
        if detail:
            result.detail = detail
        result.ended_at = time.time()
        return result
