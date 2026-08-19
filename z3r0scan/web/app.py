"""FastAPI backend for the z3r0scan dashboard.

A scan runs in a background thread; the browser polls ``/api/scan/{id}`` for
live progress. Findings are returned already grouped so the frontend stays thin.

Run with:  z3r0scan-web        (then open http://127.0.0.1:8000)
"""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

from ..config import Config
from ..models import ScanReport
from ..modules import REGISTRY
from ..orchestrator import Orchestrator

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse
    from pydantic import BaseModel
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The web dashboard needs extra deps. Install them with:\n"
        "    pip install -e '.[web]'\n"
        f"(missing: {exc.name})"
    ) from exc

app = FastAPI(title="z3r0scan", docs_url=None, redoc_url=None)

# In-memory job store. Fine for a single-user local dashboard.
_JOBS: dict[str, dict[str, Any]] = {}
_LOCK = threading.Lock()


class ScanRequest(BaseModel):
    target: str
    modules: list[str] | None = None


def _serialize(report: ScanReport, current: str | None, done: bool) -> dict[str, Any]:
    d = report.to_dict()
    d["current_module"] = current
    d["done"] = done
    return d


def _run_scan(job_id: str, target: str, modules: list[str]) -> None:
    config = Config.load(modules=modules, authorized=True)
    orch = Orchestrator(config)
    report = ScanReport(target=target)

    def on_progress(name: str, result) -> None:
        with _LOCK:
            if result is None:
                _JOBS[job_id]["current"] = name
            else:
                report.modules.append(result)
                _JOBS[job_id]["report"] = report

    with _LOCK:
        _JOBS[job_id] = {"report": report, "current": None, "done": False, "target": target}
    try:
        final = orch.scan(target, on_progress=on_progress)
        with _LOCK:
            _JOBS[job_id]["report"] = final
    finally:
        with _LOCK:
            _JOBS[job_id]["done"] = True
            _JOBS[job_id]["current"] = None


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> dict[str, str]:
    target = req.target.strip()
    if not target:
        raise HTTPException(400, "target is required")
    modules = [m for m in (req.modules or list(REGISTRY)) if m in REGISTRY]
    job_id = uuid.uuid4().hex[:12]
    thread = threading.Thread(target=_run_scan, args=(job_id, target, modules), daemon=True)
    thread.start()
    return {"job_id": job_id}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return _serialize(job["report"], job["current"], job["done"])


@app.get("/api/modules")
def list_modules() -> list[dict[str, str]]:
    return [{"name": n, "description": c.description} for n, c in REGISTRY.items()]


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (Path(__file__).parent / "index.html").read_text(encoding="utf-8")


def main() -> None:
    """Console-script entry point: launch uvicorn."""
    import uvicorn

    print("z3r0scan dashboard  ->  http://127.0.0.1:8000")
    print("Authorized testing only. Scan systems you own or may test.")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="warning")


if __name__ == "__main__":
    main()
