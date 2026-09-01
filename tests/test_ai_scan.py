"""Offline tests for the AI *scan* module (z3r0scan.modules.ai_scan).

No network: the evidence-gathering step and the provider are both stubbed so
the suite stays deterministic. This module is distinct from the AI triage layer
(tests in test_ai.py) — here the LLM produces its own findings.
"""

import z3r0scan.modules.ai_scan as ai_scan_mod
from z3r0scan import ai as ai_pkg
from z3r0scan.ai.base import AIProvider
from z3r0scan.config import Config
from z3r0scan.modules.ai_scan import AIScanModule


def _cfg(**kw):
    return Config.load(config_path="/nonexistent.yml", **kw)


def _stub_gather(monkeypatch, reachable=True):
    def fake(self, target):
        if not reachable:
            return {"reachable": False}, "https://example.com"
        ev = {
            "reachable": True, "url": "https://example.com", "status": 200,
            "headers": {"Server": "nginx/1.18.0"}, "body_snippet": "<html>hi</html>",
        }
        return ev, "https://example.com"
    monkeypatch.setattr(AIScanModule, "_gather", fake)


def _use_provider(monkeypatch, complete_fn):
    class Fake(AIProvider):
        name = "anthropic"
        label = "Fake"
        default_model = "claude-opus-5"

        @classmethod
        def sdk_installed(cls):
            return True

        def complete(self, system, user):
            return complete_fn(system, user)

    monkeypatch.setitem(ai_pkg.PROVIDERS, "anthropic", Fake)


def test_skips_without_key():
    res = AIScanModule(_cfg()).run("example.com")
    assert res.status == "skipped"
    assert "no AI API key" in res.detail


def test_parses_json_findings(monkeypatch):
    _stub_gather(monkeypatch)
    _use_provider(monkeypatch, lambda s, u: (
        '{"findings":[{"title":"Verbose server header","severity":"medium",'
        '"confidence":"high","description":"nginx/1.18.0 version disclosed"}]}', {}
    ))
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    assert res.status == "ok"
    assert len(res.findings) == 1
    f = res.findings[0]
    assert f.severity.value == "medium"
    assert f.confidence.value == "high"
    assert f.evidence["kind"] == "ai"


def test_strips_code_fence(monkeypatch):
    _stub_gather(monkeypatch)
    _use_provider(monkeypatch, lambda s, u: (
        '```json\n{"findings":[{"title":"X","severity":"low","confidence":"low"}]}\n```', {}
    ))
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    assert res.status == "ok"
    assert len(res.findings) == 1


def test_unstructured_output_surfaced(monkeypatch):
    _stub_gather(monkeypatch)
    _use_provider(monkeypatch, lambda s, u: ("just some prose, not json", {}))
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    assert res.status == "ok"
    assert len(res.findings) == 1
    assert res.findings[0].title == "AI analysis (unstructured)"


def test_empty_response_is_ok(monkeypatch):
    _stub_gather(monkeypatch)
    _use_provider(monkeypatch, lambda s, u: ("", {}))
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    assert res.status == "ok"
    assert "no analysis" in res.detail


def test_provider_error_caught(monkeypatch):
    _stub_gather(monkeypatch)

    def boom(s, u):
        raise RuntimeError("429 rate limited")

    _use_provider(monkeypatch, boom)
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    assert res.status == "error"
    assert "429 rate limited" in res.detail


def test_unreachable_target(monkeypatch):
    _stub_gather(monkeypatch, reachable=False)
    _use_provider(monkeypatch, lambda s, u: ("{}", {}))
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    assert res.status == "ok"
    assert "no HTTP response" in res.detail


def test_registered_and_default():
    from z3r0scan.modules import REGISTRY
    assert REGISTRY.get("ai_scan") is AIScanModule
    assert "ai_scan" in Config().modules


def test_extract_surface_finds_endpoints_forms_params():
    m = AIScanModule(_cfg())
    body = (
        '<a href="/login">L</a><a href="/admin?id=5">A</a>'
        '<script src="/static/app.js"></script>'
        '<form action="/search"><input name=q></form>'
        '<script>fetch("/api/user?token=abc");axios.get("/api/o?next=http://x")</script>'
        '<a href="#top">t</a><a href="mailto:a@b.com">m</a>'
    )
    endpoints, forms, params = m._extract_surface(body)
    assert "/login" in endpoints and "/admin?id=5" in endpoints
    assert "/api/user?token=abc" in endpoints          # fetch()
    assert "/api/o?next=http://x" in endpoints          # axios
    assert "#top" not in endpoints and not any("mailto" in e for e in endpoints)
    assert forms == 1
    assert params == ["id", "next", "token"]            # sorted, deduped


def test_cookie_flags_summarized():
    m = AIScanModule(_cfg())
    flags = m._cookie_flags({"Set-Cookie": "sid=abc; HttpOnly; Path=/, pref=1; Secure"})
    assert flags == ["sid [HttpOnly no-SameSite]", "pref [Secure no-SameSite]"]


def test_finding_carries_owasp_and_next_step(monkeypatch):
    _stub_gather(monkeypatch)
    _use_provider(monkeypatch, lambda s, u: (
        '{"findings":[{"title":"Verbose stack trace","severity":"medium",'
        '"confidence":"high","owasp":"A05","endpoint":"/api/user",'
        '"description":"Stack trace leaked","next_step":"Send an invalid id"}]}', {}
    ))
    res = AIScanModule(_cfg(ai_provider="anthropic", anthropic_api_key="k")).run("example.com")
    f = res.findings[0]
    assert f.title.startswith("[A05]")
    assert "Endpoint: /api/user" in f.description
    assert "Next step: Send an invalid id" in f.description
    assert f.evidence["owasp"] == "A05"
