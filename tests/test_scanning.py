"""Tests for scanning logic that don't touch the network.

Host-scan probing is monkeypatched so the suite is deterministic and offline.
"""

import z3r0scan.modules.host_scan as hs
from z3r0scan.config import Config
from z3r0scan.models import Severity
from z3r0scan.modules.host_scan import HostScanModule
from z3r0scan.modules.subdomains import SubdomainModule
from z3r0scan.orchestrator import Orchestrator
from z3r0scan.report import to_html, to_json, to_markdown
from z3r0scan.utils import is_ip, normalize_host


def test_normalize_host():
    assert normalize_host("https://example.com/path") == "example.com"
    assert normalize_host("example.com:8080") == "example.com"
    assert normalize_host("  1.2.3.4  ") == "1.2.3.4"


def test_is_ip():
    assert is_ip("8.8.8.8")
    assert not is_ip("example.com")


def test_notable_port_severity_mapping():
    cfg = Config(ports=[2375])
    mod = HostScanModule(cfg)
    result = mod._result("h")
    mod._record_port(result, 2375, "docker", "")
    assert result.findings[0].severity == Severity.CRITICAL


def test_python_scan_uses_probe(monkeypatch):
    # Pretend only ports 22 and 80 are open, and nmap is absent.
    monkeypatch.setattr(hs, "have_tool", lambda name: False)
    cfg = Config(ports=[22, 80, 443])
    mod = HostScanModule(cfg)
    monkeypatch.setattr(mod, "_probe", lambda host, port: port in (22, 80))
    result = mod.run("scanme.example")
    ports = sorted(f.evidence["port"] for f in result.findings)
    assert ports == [22, 80]
    assert result.status == "ok"


def test_subdomains_skips_on_ip():
    mod = SubdomainModule(Config())
    result = mod.run("8.8.8.8")
    assert result.status == "skipped"


def test_shodan_skips_without_key():
    from z3r0scan.modules.shodan_enrich import ShodanModule
    result = ShodanModule(Config(shodan_api_key=None)).run("example.com")
    assert result.status == "skipped"


def test_orchestrator_runs_selected_modules(monkeypatch):
    monkeypatch.setattr(hs, "have_tool", lambda name: False)
    cfg = Config(modules=["host_scan"], ports=[80])
    orch = Orchestrator(cfg)
    # Force all probes closed so it's fully offline.
    monkeypatch.setattr(HostScanModule, "_probe", lambda self, h, p: False)
    report = orch.scan("example.com")
    assert len(report.modules) == 1
    assert report.modules[0].module == "host_scan"


def test_reporters_render(monkeypatch):
    monkeypatch.setattr(hs, "have_tool", lambda name: False)
    monkeypatch.setattr(HostScanModule, "_probe", lambda self, h, p: p == 80)
    cfg = Config(modules=["host_scan"], ports=[80, 443])
    report = Orchestrator(cfg).scan("example.com")

    assert '"target": "example.com"' in to_json(report)
    assert "z3r0scan report" in to_markdown(report)
    html = to_html(report)
    assert "<html" in html.lower() and "example.com" in html
