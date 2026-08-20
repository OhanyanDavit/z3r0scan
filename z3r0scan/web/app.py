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


def _serialize(report: ScanReport, current: str | None, done: bool) -> dict[str, Any]:
    d = report.to_dict()
    d["current_module"] = current
    d["done"] = done
    return d


def _run_scan(job_id: str, target: str, modules: list[str], req: ScanRequest) -> None:
    ai = req.ai or AISettings()
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
    orch = Orchestrator(config)
    report = ScanReport(target=target)

    def on_progress(name: str, result) -> None:
        with _LOCK:
            if result is None:
                _JOBS[job_id]["current"] = name
            elif result.module == "ai_analysis":
                # AI is not a scanner module — don't add it to the module panels.
                # Its full result arrives with the final report (report.ai).
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
    thread = threading.Thread(target=_run_scan, args=(job_id, target, modules, req), daemon=True)
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
