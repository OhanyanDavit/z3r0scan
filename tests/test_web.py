from z3r0scan.modules.web_probe import candidate_urls


def test_candidate_urls_bare_host():
    assert candidate_urls("example.com") == ["https://example.com", "http://example.com"]


def test_candidate_urls_explicit_scheme():
    assert candidate_urls("http://localhost:8080") == ["http://localhost:8080"]
    assert candidate_urls("https://x.io/") == ["https://x.io"]


def test_candidate_urls_host_port_guesses_scheme():
    assert candidate_urls("localhost:8080") == ["http://localhost:8080"]
    assert candidate_urls("host:443") == ["https://host:443"]
    assert candidate_urls("host:8443") == ["https://host:8443"]
