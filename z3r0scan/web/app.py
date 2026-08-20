"""FastAPI backend for the z3r0scan dashboard.

A scan runs in a background thread; the browser polls ``/api/scan/{id}`` for
live progress. Findings are returned already grouped so the frontend stays thin.

Run with:  z3r0scan-web        (then open http://127.0.0.1:8000)
"""

from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

from ..config import Config
from ..models import ScanReport
from ..modules import REGISTRY
from ..orchestrator import Orchestrator
from ..utils import TargetError, validate_target

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
# Bounded worker pool so a burst of requests can't spawn unlimited threads.
_MAX_WORKERS = 4
_EXECUTOR = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="z3r0scan")
_JOB_TTL = 3600.0  # seconds a finished job is retained before cleanup
_MAX_JOBS = 200


class ScanRequest(BaseModel):
    target: str
    modules: list[str] | None = None


def _serialize(job: dict[str, Any]) -> dict[str, Any]:
    d = job["report"].to_dict()
    d["current_module"] = job["current"]
    d["done"] = job["done"]
    d["error"] = job["error"]
    return d


def _reap_old_jobs() -> None:
    """Drop finished jobs past their TTL so the store can't grow unbounded."""
    now = time.monotonic()
    stale = [
        jid for jid, j in _JOBS.items()
        if j["done"] and (now - j["created_at"]) > _JOB_TTL
    ]
    for jid in stale:
        _JOBS.pop(jid, None)


def _run_scan(job_id: str, target: str, modules: list[str]) -> None:
    job = _JOBS[job_id]
    report = job["report"]  # created synchronously in start_scan

    def on_progress(name: str, result) -> None:
        with _LOCK:
            if result is None:
                job["current"] = name
            else:
                report.modules.append(result)

    try:
        config = Config.load(modules=modules, authorized=True)
        final = Orchestrator(config).scan(target, on_progress=on_progress)
        with _LOCK:
            job["report"] = final
    except Exception as exc:  # noqa: BLE001 - surface a clear error state, don't hang
        with _LOCK:
            job["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        with _LOCK:
            job["done"] = True
            job["current"] = None


@app.post("/api/scan")
def start_scan(req: ScanRequest) -> dict[str, str]:
    try:
        target = validate_target(req.target)
    except TargetError as exc:
        raise HTTPException(400, f"invalid target: {exc}") from exc

    modules = [m for m in (req.modules or list(REGISTRY)) if m in REGISTRY]
    job_id = uuid.uuid4().hex[:12]
    with _LOCK:
        _reap_old_jobs()
        if sum(1 for j in _JOBS.values() if not j["done"]) >= _MAX_JOBS:
            raise HTTPException(429, "too many scans in progress; try again shortly")
        # Initialize the job BEFORE submitting work, so an immediate status poll
        # can never 404 on a job that "exists" but whose worker hasn't run yet.
        _JOBS[job_id] = {
            "report": ScanReport(target=target),
            "current": None,
            "done": False,
            "error": None,
            "created_at": time.monotonic(),
        }
    _EXECUTOR.submit(_run_scan, job_id, target, modules)
    return {"job_id": job_id}


@app.get("/api/scan/{job_id}")
def scan_status(job_id: str) -> dict[str, Any]:
    with _LOCK:
        job = _JOBS.get(job_id)
        if not job:
            raise HTTPException(404, "unknown job")
        return _serialize(job)


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
