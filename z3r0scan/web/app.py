"""FastAPI backend for the z3r0scan dashboard.

A scan runs in a background thread; the browser polls ``/api/scan/{id}`` for
live progress. Findings are returned already grouped so the frontend stays thin.

API keys (Anthropic / OpenAI / Shodan) can be entered in the dashboard's
settings panel and are sent per-scan. They are held only in the in-memory job
config for the duration of the run and never written to disk. Environment
variables still work as a fallback. The server binds to 127.0.0.1 only.

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


class AISettings(BaseModel):
    enabled: bool = False
    provider: str = "auto"  # auto | anthropic | openai
    model: str | None = None
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None


class ScanRequest(BaseModel):
    target: str
    modules: list[str] | None = None
    shodan_api_key: str | None = None
    ai: AISettings | None = None


class KeyTestRequest(BaseModel):
    provider: str
    api_key: str
    model: str | None = None


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


def _run_scan(job_id: str, target: str, modules: list[str], req: ScanRequest) -> None:
    job = _JOBS[job_id]
    report = job["report"]  # created synchronously in start_scan
    ai = req.ai or AISettings()

    def on_progress(name: str, result) -> None:
        with _LOCK:
            if result is None:
                job["current"] = name
            elif result.module == "ai_analysis":
                # AI is not a scanner module — don't add it to the module panels.
                # Its full result arrives with the final report (report.ai).
                job["current"] = name
            else:
                report.modules.append(result)

    try:
        config = Config.load(
            modules=modules,
            authorized=True,
            shodan_api_key=req.shodan_api_key or None,
            ai_enabled=ai.enabled or None,
            ai_provider=ai.provider,
            ai_model=ai.model or None,
            anthropic_api_key=ai.anthropic_api_key or None,
            openai_api_key=ai.openai_api_key or None,
        )
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
    _EXECUTOR.submit(_run_scan, job_id, target, modules, req)
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


@app.get("/api/ai/providers")
def ai_providers() -> list[dict[str, Any]]:
    """Report which AI providers have their SDK installed (for the settings UI)."""
    from ..ai import provider_status

    return provider_status()


@app.post("/api/ai/test")
def ai_test(req: KeyTestRequest) -> dict[str, Any]:
    """Validate an API key with a tiny live call so users can verify a key."""
    from ..ai import PROVIDERS

    cls = PROVIDERS.get(req.provider)
    if cls is None:
        raise HTTPException(400, f"unknown provider '{req.provider}'")
    if not cls.sdk_installed():
        return {"ok": False, "detail": f"{cls.label} SDK not installed — pip install z3r0scan[ai]"}
    if not req.api_key.strip():
        return {"ok": False, "detail": "empty API key"}
    provider = cls(api_key=req.api_key.strip(), model=req.model or None)
    try:
        text, _ = provider.complete(
            "You are a connectivity check. Reply with exactly: OK",
            "Reply with exactly: OK",
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "detail": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "detail": f"{cls.label} reachable ({provider.model})", "sample": text[:40]}


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
