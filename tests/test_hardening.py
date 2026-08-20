"""Regression tests for the correctness & safety hardening pass.

Every test here pins down a previously-reproduced failure so it can't come back.
All offline: subprocesses, DNS, TLS, and HTTP are monkeypatched or faked.
"""

import json
import ssl
import subprocess
import sys

import pytest

import z3r0scan.modules.host_scan as hs
import z3r0scan.modules.vuln_scan as vs
import z3r0scan.modules.web_probe as wp
from z3r0scan.cli import EXIT_MODULE_ERROR, EXIT_OK, EXIT_THRESHOLD, _exit_code
from z3r0scan.config import Config
from z3r0scan.models import Confidence, Finding, ModuleResult, ScanReport, Severity
from z3r0scan.modules.host_scan import HostScanModule
from z3r0scan.modules.subdomains import SubdomainModule
from z3r0scan.utils import TargetError, redact, resolve_all, validate_target


# ---------------------------------------------------------------- target parsing
def test_validate_target_accepts_normal():
    assert validate_target("example.com") == "example.com"
    assert validate_target("http://localhost:8080") == "http://localhost:8080"
    assert validate_target("  1.2.3.4 ") == "1.2.3.4"


@pytest.mark.parametrize("bad", ["", "   ", "-oX", "-p-", "a\r\nb", "host\x00", "bad host",
                                 "host:0", "host:99999", "host:abc"])
def test_validate_target_rejects_bad(bad):
    with pytest.raises(TargetError):
        validate_target(bad)


def test_resolve_all_ip_literal_returns_itself():
    assert resolve_all("8.8.8.8") == ["8.8.8.8"]
    assert resolve_all("::1") == ["::1"]
    assert resolve_all("") == []


# --------------------------------------------------------------------- host scan
def test_unresolvable_target_is_error(monkeypatch):
    monkeypatch.setattr(hs, "resolve", lambda host: None)
    result = HostScanModule(Config(ports=[80])).run("does-not-exist.invalid")
    assert result.status == "error"
    assert "resolve" in result.detail


def test_fallback_banner_does_not_confirm_wrong_service():
    # An SSH banner answering on the Docker port must NOT confirm Docker.
    assert HostScanModule._banner_confirms(2375, "SSH-2.0-OpenSSH_8.9") is False
    assert HostScanModule._banner_confirms(22, "SSH-2.0-OpenSSH_8.9") is True
    assert HostScanModule._banner_confirms(6379, "") is False


def test_wrong_banner_keeps_notable_port_informational():
    mod = HostScanModule(Config(ports=[2375]))
    mod._edge = False
    result = mod._result("h")
    # docker banner-grab yields nothing useful -> unconfirmed -> not critical.
    mod._record_port(result, 2375, "docker", "", confirmed=False)
    f = result.findings[0]
    assert f.severity == Severity.INFO
    assert f.confidence == Confidence.LOW


# --------------------------------------------------------------------- vuln scan
def test_nuclei_preserves_explicit_scheme_and_port(monkeypatch):
    captured = {}

    def fake_run(cmd, timeout=900):
        captured["cmd"] = cmd
        return 0, "", ""

    monkeypatch.setattr(vs, "have_tool", lambda name: True)
    monkeypatch.setattr(vs, "run", fake_run)
    vs.VulnScanModule(Config()).run("http://localhost:8080")
    cmd = captured["cmd"]
    assert "http://localhost:8080" in cmd  # not rewritten to https://localhost


def test_nuclei_nonzero_exit_is_not_clean(monkeypatch):
    monkeypatch.setattr(vs, "have_tool", lambda name: True)
    monkeypatch.setattr(vs, "run", lambda cmd, timeout=900: (1, "", "boom"))
    result = vs.VulnScanModule(Config()).run("http://localhost:8080")
    assert result.status == "error"
    assert "clean" not in result.detail.lower()


# ----------------------------------------------------------------------- web/TLS
class _FakeTLS:
    def __init__(self, verify_error):
        self._verify_error = verify_error

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def wrap_socket(self, sock, server_hostname=None):
        if self._verify_error:
            raise ssl.SSLCertVerificationError("self-signed certificate in certificate chain")
        return self


def test_self_signed_certificate_is_not_reported_ok(monkeypatch):
    # Both the verified and the descriptive reconnect raise -> report a failure.
    monkeypatch.setattr(wp.ssl, "create_default_context", lambda *a, **k: _FakeTLS(True))

    class _Sock:
        def __enter__(self): return self
        def __exit__(self, *a): return False

    monkeypatch.setattr(wp.socket, "create_connection", lambda *a, **k: _Sock())
    result = ModuleResult(module="web_probe", target="x")
    wp.WebProbeModule(Config()).__class__._tls_info(
        wp.WebProbeModule(Config()), "https://self-signed.example", result
    )
    titles = [f.title for f in result.findings]
    assert any("validation failed" in t for t in titles)
    assert not any("OK" in t or "valid" == t for t in titles)
    assert all(f.severity != Severity.INFO or "failed" not in f.title for f in result.findings)


def test_http_header_checks_do_not_flag_hsts_on_http(monkeypatch):
    class _Resp:
        url = "http://plain.example/"
        status_code = 200
        headers = {"Content-Type": "text/html"}  # noqa: RUF012

    monkeypatch.setattr(wp.requests, "get", lambda *a, **k: _Resp())
    result = ModuleResult(module="web_probe", target="x")
    wp.WebProbeModule(Config())._header_check("http://plain.example/", result)
    headers = [f.evidence.get("header") for f in result.findings]
    assert "strict-transport-security" not in headers  # meaningless over HTTP
    assert "content-security-policy" in headers        # still relevant for HTML


def test_sensitive_paths_reject_generic_spa_fallback(monkeypatch):
    mod = wp.WebProbeModule(Config())

    def fake_fetch(url):
        # Every path returns the same SPA index page (a catch-all handler).
        return 200, "<html><body>My SPA</body></html>"

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    result = ModuleResult(module="web_probe", target="x")
    mod._sensitive_paths("http://spa.example", result)
    assert result.findings == []  # nothing flagged behind an SPA catch-all


def test_real_env_file_is_flagged(monkeypatch):
    mod = wp.WebProbeModule(Config())

    def fake_fetch(url):
        if url.endswith("/.env"):
            return 200, "DATABASE_URL=postgres://u:p@h/db\nSECRET_KEY=abc123\n"
        return 404, ""  # baseline + others 404 -> no catch-all

    monkeypatch.setattr(mod, "_fetch", fake_fetch)
    result = ModuleResult(module="web_probe", target="x")
    mod._sensitive_paths("http://real.example", result)
    assert any("/.env" in f.title for f in result.findings)


# -------------------------------------------------------------------- subdomains
def test_crtsh_domain_matching_uses_label_boundary():
    assert SubdomainModule._in_scope("api.example.com", "example.com") is True
    assert SubdomainModule._in_scope("example.com", "example.com") is True
    assert SubdomainModule._in_scope("notexample.com", "example.com") is False
    assert SubdomainModule._in_scope("evil.com", "example.com") is False


# --------------------------------------------------------------------- redaction
def test_shodan_exception_redacts_api_key():
    key = "SECRETKEY12345"
    msg = redact(f"GET https://api.shodan.io/x?key={key} failed", key)
    assert key not in msg
    assert "REDACTED" in msg


def test_redact_strips_key_query_param_generically():
    assert "abc123" not in redact("http://h/api?token=abc123def")


# ---------------------------------------------------------------------- cli exit
def test_module_error_returns_nonzero_exit():
    report = ScanReport(target="x")
    m = ModuleResult(module="web_probe", target="x")
    m.status = "error"
    report.modules.append(m)
    assert _exit_code(report, "high") == EXIT_MODULE_ERROR


def test_threshold_exit_takes_precedence():
    report = ScanReport(target="x")
    m = ModuleResult(module="host_scan", target="x")
    m.add(Finding("crit", Severity.CRITICAL))
    report.modules.append(m)
    assert _exit_code(report, "high") == EXIT_THRESHOLD


def test_clean_scan_exits_ok():
    report = ScanReport(target="x")
    m = ModuleResult(module="host_scan", target="x")
    m.add(Finding("info", Severity.INFO))
    report.modules.append(m)
    assert _exit_code(report, "high") == EXIT_OK


def test_cli_stdout_is_valid_json():
    # shodan-only run needs no key and no network -> fully offline.
    proc = subprocess.run(
        [sys.executable, "-m", "z3r0scan", "example.com", "--modules", "shodan", "-y"],
        capture_output=True, text=True, check=False,
    )
    parsed = json.loads(proc.stdout)  # raises if banner/progress leaked to stdout
    assert parsed["target"] == "example.com"
