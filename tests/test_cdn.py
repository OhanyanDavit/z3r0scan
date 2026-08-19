import z3r0scan.cdn as cdn_mod
from z3r0scan.cdn import CDNResult, detect_cdn


def test_cloudflare_ip_range(monkeypatch):
    # 104.16.0.1 is inside Cloudflare's 104.16.0.0/13.
    monkeypatch.setattr(cdn_mod, "resolve", lambda host: "104.16.0.1")
    res = detect_cdn("example.com")
    assert res.detected
    assert res.provider == "Cloudflare"
    assert res.method == "ip-range"


def test_non_cdn_ip_falls_through(monkeypatch):
    monkeypatch.setattr(cdn_mod, "resolve", lambda host: "8.8.8.8")
    monkeypatch.setattr(cdn_mod, "_match_headers", lambda host, timeout: None)
    res = detect_cdn("example.com")
    assert not res.detected


def test_header_detection(monkeypatch):
    monkeypatch.setattr(cdn_mod, "resolve", lambda host: "203.0.113.5")  # not in any range
    monkeypatch.setattr(cdn_mod, "_match_headers", lambda host, timeout: ("Fastly", "http-header"))
    res = detect_cdn("example.com")
    assert res.detected and res.provider == "Fastly" and res.method == "http-header"


def test_note_text():
    res = CDNResult(True, provider="Cloudflare", method="ip-range", ip="104.16.0.1")
    assert "Cloudflare" in res.note and "edge" in res.note
    assert CDNResult(False).note == ""
