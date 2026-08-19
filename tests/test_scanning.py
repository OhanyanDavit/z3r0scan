"""Tests for scanning logic that don't touch the network.

Host-scan probing and CDN detection are monkeypatched so the suite is
deterministic and offline.
"""

import z3r0scan.modules.host_scan as hs
from z3r0scan.cdn import CDNResult
from z3r0scan.config import Config
from z3r0scan.models import Severity
from z3r0scan.modules.host_scan import HostScanModule
from z3r0scan.modules.subdomains import SubdomainModule
from z3r0scan.orchestrator import Orchestrator
from z3r0scan.report import to_html, to_json, to_markdown
from z3r0scan.utils import is_ip, normalize_host


def _no_cdn(monkeypatch):
    monkeypatch.setattr(hs, "detect_cdn", lambda host, timeout=5.0: CDNResult(False, ip="1.1.1.1"))


def test_normalize_host():
    assert normalize_host("https://example.com/path") == "example.com"
    assert normalize_host("example.com:8080") == "example.com"
    assert normalize_host("  1.2.3.4  ") == "1.2.3.4"


def test_is_ip():
    assert is_ip("8.8.8.8")
    assert not is_ip("example.com")


def test_confirmed_notable_port_is_critical():
    mod = HostScanModule(Config(ports=[2375]))
    mod._edge = False
    result = mod._result("h")
    mod._record_port(result, 2375, "docker", "", confirmed=True)
    assert result.findings[0].severity == Severity.CRITICAL


def test_unconfirmed_notable_port_is_downgraded():
    mod = HostScanModule(Config(ports=[2375]))
    mod._edge = False
    result = mod._result("h")
    mod._record_port(result, 2375, "docker", "", confirmed=False)
    assert result.findings[0].severity == Severity.INFO
    assert "unconfirmed" in result.findings[0].title


def test_edge_forces_downgrade_even_if_confirmed():
    mod = HostScanModule(Config(ports=[2375]))
    mod._edge = True
    result = mod._result("h")
    mod._record_port(result, 2375, "docker", "", confirmed=True)
    assert result.findings[0].severity == Severity.INFO
    assert "CDN" in result.findings[0].title


def test_nmap_parsing_marks_guesses_unconfirmed(monkeypatch):
    _no_cdn(monkeypatch)
    monkeypatch.setattr(hs, "have_tool", lambda name: True)
    fake_output = "\n".join([
        "22/tcp open ssh OpenSSH 8.9",       # confirmed
        "2375/tcp open docker?",              # guessed
        "3306/tcp open tcpwrapped",          # proxy artifact
    ])
    monkeypatch.setattr(hs, "run", lambda cmd, timeout=300: (0, fake_output, ""))
    result = HostScanModule(Config(ports=[22, 2375, 3306])).run("example.com")
    by_port = {f.evidence["port"]: f for f in result.findings if "port" in f.evidence}
    assert by_port[22].evidence["confirmed"] is True
    assert by_port[2375].severity == Severity.INFO      # docker? not escalated
    assert by_port[3306].evidence["confirmed"] is False  # tcpwrapped


def test_cdn_detection_adds_banner_and_downgrades(monkeypatch):
    monkeypatch.setattr(
        hs, "detect_cdn",
        lambda host, timeout=5.0: CDNResult(True, provider="Cloudflare", method="ip-range", ip="104.16.0.1"),
    )
    monkeypatch.setattr(hs, "have_tool", lambda name: True)
    monkeypatch.setattr(hs, "run", lambda cmd, timeout=300: (0, "6379/tcp open redis", ""))
    result = HostScanModule(Config(ports=[6379])).run("picsart.com")
    assert any(f.evidence.get("cdn") == "Cloudflare" for f in result.findings)
    redis = next(f for f in result.findings if f.evidence.get("port") == 6379)
    assert redis.severity == Severity.INFO  # not HIGH — it's an edge artifact


def test_python_scan_uses_probe(monkeypatch):
    _no_cdn(monkeypatch)
    monkeypatch.setattr(hs, "have_tool", lambda name: False)
    mod = HostScanModule(Config(ports=[22, 80, 443]))
    monkeypatch.setattr(mod, "_probe", lambda host, port: port in (22, 80))
    monkeypatch.setattr(mod, "_grab_banner", lambda host, port: "")
    result = mod.run("scanme.example")
    ports = sorted(f.evidence["port"] for f in result.findings if "port" in f.evidence)
    assert ports == [22, 80]
    assert result.status == "ok"


def test_subdomains_skips_on_ip():
    result = SubdomainModule(Config()).run("8.8.8.8")
    assert result.status == "skipped"


def test_shodan_skips_without_key():
    from z3r0scan.modules.shodan_enrich import ShodanModule
    result = ShodanModule(Config(shodan_api_key=None)).run("example.com")
    assert result.status == "skipped"


def test_orchestrator_runs_selected_modules(monkeypatch):
    _no_cdn(monkeypatch)
    monkeypatch.setattr(hs, "have_tool", lambda name: False)
    monkeypatch.setattr(HostScanModule, "_probe", lambda self, h, p: False)
    report = Orchestrator(Config(modules=["host_scan"], ports=[80])).scan("example.com")
    assert len(report.modules) == 1
    assert report.modules[0].module == "host_scan"


def test_reporters_render(monkeypatch):
    _no_cdn(monkeypatch)
    monkeypatch.setattr(hs, "have_tool", lambda name: False)
    monkeypatch.setattr(HostScanModule, "_probe", lambda self, h, p: p == 80)
    monkeypatch.setattr(HostScanModule, "_grab_banner", lambda self, h, p: "")
    report = Orchestrator(Config(modules=["host_scan"], ports=[80, 443])).scan("example.com")
    assert '"target": "example.com"' in to_json(report)
    assert "z3r0scan report" in to_markdown(report)
    html = to_html(report)
    assert "<html" in html.lower() and "example.com" in html
