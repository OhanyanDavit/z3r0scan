"""Offline tests for the AI analysis layer.

No network: providers are monkeypatched or exercised through the graceful
skip/error paths so the suite stays deterministic.
"""

from z3r0scan import ai as ai_pkg
from z3r0scan.ai import run_ai_analysis
from z3r0scan.ai.base import AIProvider, build_prompt
from z3r0scan.config import Config
from z3r0scan.models import Finding, ModuleResult, ScanReport, Severity


def _report():
    r = ScanReport(target="example.com")
    m = ModuleResult(module="web_probe", target="example.com")
    m.add(Finding(title="Missing header: content-security-policy", severity=Severity.LOW))
    m.add(Finding(title="/.env exposed", severity=Severity.HIGH, description="leaks secrets"))
    r.modules.append(m)
    return r


def test_env_keys_load(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-xxx")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-oai-xxx")
    cfg = Config.load(config_path="/nonexistent.yml")
    assert cfg.anthropic_api_key == "sk-ant-xxx"
    assert cfg.openai_api_key == "sk-oai-xxx"


def test_build_prompt_orders_by_severity():
    prompt = build_prompt(_report())
    # HIGH finding must appear before the LOW one.
    assert prompt.index("/.env exposed") < prompt.index("content-security-policy")
    assert "example.com" in prompt
    assert "high=1" in prompt


def test_skipped_when_no_key():
    cfg = Config.load(config_path="/nonexistent.yml", ai_enabled=True)
    res = run_ai_analysis(_report(), cfg)
    assert res.status == "skipped"
    assert "no AI API key" in res.detail


def test_unknown_provider():
    cfg = Config.load(config_path="/nonexistent.yml", ai_enabled=True,
                      ai_provider="bogus", anthropic_api_key="k")
    res = run_ai_analysis(_report(), cfg)
    assert res.status == "skipped"
    assert "unknown AI provider" in res.detail


def test_ok_with_fake_provider(monkeypatch):
    class FakeProvider(AIProvider):
        name = "anthropic"
        label = "Fake Claude"
        default_model = "claude-opus-5"

        @classmethod
        def sdk_installed(cls):
            return True

        def complete(self, system, user):
            assert "example.com" in user
            return "## Executive summary\nLooks risky.", {"input_tokens": 10, "output_tokens": 5}

    monkeypatch.setitem(ai_pkg.PROVIDERS, "anthropic", FakeProvider)
    cfg = Config.load(config_path="/nonexistent.yml", ai_enabled=True,
                      ai_provider="anthropic", anthropic_api_key="k")
    res = run_ai_analysis(_report(), cfg)
    assert res.status == "ok"
    assert res.model == "claude-opus-5"
    assert "Executive summary" in res.summary
    assert res.usage["output_tokens"] == 5


def test_provider_error_is_caught(monkeypatch):
    class BoomProvider(AIProvider):
        name = "anthropic"
        label = "Boom"
        default_model = "x"

        @classmethod
        def sdk_installed(cls):
            return True

        def complete(self, system, user):
            raise RuntimeError("429 rate limited")

    monkeypatch.setitem(ai_pkg.PROVIDERS, "anthropic", BoomProvider)
    cfg = Config.load(config_path="/nonexistent.yml", ai_enabled=True,
                      ai_provider="anthropic", anthropic_api_key="k")
    res = run_ai_analysis(_report(), cfg)
    assert res.status == "error"
    assert "429 rate limited" in res.detail


def test_report_carries_ai_dict():
    r = _report()
    r.ai = {"status": "ok", "provider": "anthropic", "model": "m", "summary": "hi"}
    assert r.to_dict()["ai"]["summary"] == "hi"


def test_md_to_html_and_report_render():
    from z3r0scan.report import md_to_html, to_html, to_markdown

    html = md_to_html("## Heading\n- **bold** item\nplain line")
    assert "<h4>Heading</h4>" in html
    assert "<strong>bold</strong>" in html
    assert "<li>" in html

    r = _report()
    r.ai = {"status": "ok", "provider": "anthropic", "model": "claude-opus-5",
            "summary": "## Executive summary\n- do the thing"}
    md = to_markdown(r)
    assert "AI analysis" in md
    assert "Executive summary" in md
    out_html = to_html(r)
    assert "AI analysis" in out_html
    assert "claude-opus-5" in out_html


def test_orchestrator_runs_ai_when_enabled(monkeypatch):
    class FakeProvider(AIProvider):
        name = "anthropic"
        label = "Fake"
        default_model = "claude-opus-5"

        @classmethod
        def sdk_installed(cls):
            return True

        def complete(self, system, user):
            return "## Executive summary\nfine", {}

    monkeypatch.setitem(ai_pkg.PROVIDERS, "anthropic", FakeProvider)
    from z3r0scan.orchestrator import Orchestrator

    cfg = Config.load(config_path="/nonexistent.yml", modules=[], authorized=True,
                      ai_enabled=True, ai_provider="anthropic", anthropic_api_key="k")
    report = Orchestrator(cfg).scan("example.com")
    assert report.ai is not None
    assert report.ai["status"] == "ok"
    assert "Executive summary" in report.ai["summary"]


def test_orchestrator_skips_ai_when_disabled():
    from z3r0scan.orchestrator import Orchestrator

    cfg = Config.load(config_path="/nonexistent.yml", modules=[], authorized=True)
    report = Orchestrator(cfg).scan("example.com")
    assert report.ai is None
