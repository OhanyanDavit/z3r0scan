"""Drives a scan: runs each requested module against the target in order and
collects the results into a single :class:`ScanReport`.

A callback hook lets the CLI render live progress without the orchestrator
depending on any particular UI library.
"""

from __future__ import annotations

import time
from typing import Callable, Optional

from .config import Config
from .models import ModuleResult, ScanReport
from .modules import REGISTRY

# Runtime type alias (evaluated eagerly, so `from __future__` doesn't apply):
# use typing.Optional for Python 3.9 compatibility.
ProgressCallback = Callable[[str, Optional[ModuleResult]], None]


class Orchestrator:
    def __init__(self, config: Config):
        self.config = config

    def scan(self, target: str, on_progress: ProgressCallback | None = None) -> ScanReport:
        report = ScanReport(target=target, started_at=time.time())

        for module_name in self.config.modules:
            module_cls = REGISTRY.get(module_name)
            if module_cls is None:
                continue
            if on_progress:
                on_progress(module_name, None)  # signal "starting"

            module = module_cls(self.config)
            try:
                result = module.run(target)
            except Exception as exc:  # noqa: BLE001 - a broken module must not kill the run
                result = ModuleResult(module=module_name, target=target)
                result.status = "error"
                result.detail = f"unhandled error: {exc}"
                result.ended_at = time.time()

            report.modules.append(result)
            if on_progress:
                on_progress(module_name, result)  # signal "done"

        # Optional AI triage of everything the modules produced.
        if self.config.ai_enabled:
            if on_progress:
                on_progress("ai_analysis", None)
            from .ai import run_ai_analysis  # local import: AI layer is optional

            analysis = run_ai_analysis(report, self.config)
            report.ai = analysis.to_dict()
            if on_progress:
                # Reuse the module-done signal with a synthetic result so UIs can
                # render progress without a special case.
                done = ModuleResult(module="ai_analysis", target=target)
                done.status = analysis.status
                done.detail = analysis.detail
                done.ended_at = time.time()
                on_progress("ai_analysis", done)

        report.ended_at = time.time()
        return report
