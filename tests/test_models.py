from z3r0scan.models import Finding, ModuleResult, ScanReport, Severity


def test_severity_rank_order():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank


def test_report_severity_counts_and_top():
    report = ScanReport(target="example.com")
    m = ModuleResult(module="host_scan", target="example.com")
    m.add(Finding("port 23", Severity.HIGH))
    m.add(Finding("port 80", Severity.INFO))
    m.add(Finding("docker api", Severity.CRITICAL))
    report.modules.append(m)

    counts = report.severity_counts()
    assert counts["critical"] == 1
    assert counts["high"] == 1
    assert counts["info"] == 1
    assert report.top_severity == Severity.CRITICAL


def test_empty_report_top_severity_is_info():
    assert ScanReport(target="x").top_severity == Severity.INFO


def test_finding_serialization():
    f = Finding("t", Severity.MEDIUM, "desc", {"port": 80})
    d = f.to_dict()
    assert d["severity"] == "medium"
    assert d["evidence"]["port"] == 80


def test_report_to_dict_shape():
    report = ScanReport(target="example.com")
    report.ended_at = report.started_at + 1
    d = report.to_dict()
    assert d["target"] == "example.com"
    assert "severity_counts" in d
    assert "modules" in d
