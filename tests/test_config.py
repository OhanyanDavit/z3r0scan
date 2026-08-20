
from z3r0scan.config import DEFAULT_PORTS, Config


def test_defaults():
    cfg = Config.load(config_path="/nonexistent.yml")
    assert cfg.threads == 50
    assert cfg.ports == DEFAULT_PORTS
    assert "host_scan" in cfg.modules


def test_overrides_win(tmp_path):
    cfg = Config.load(config_path=str(tmp_path / "none.yml"), threads=10, timeout=1.5)
    assert cfg.threads == 10
    assert cfg.timeout == 1.5


def test_none_override_does_not_clobber():
    cfg = Config.load(config_path="/nonexistent.yml", threads=None)
    assert cfg.threads == 50  # falls back to default, not None


def test_env_shodan_key(monkeypatch):
    monkeypatch.setenv("SHODAN_API_KEY", "abc123")
    cfg = Config.load(config_path="/nonexistent.yml")
    assert cfg.shodan_api_key == "abc123"


def test_yaml_file(tmp_path):
    p = tmp_path / "cfg.yml"
    p.write_text("threads: 5\nmodules: [host_scan, web_probe]\n")
    cfg = Config.load(config_path=str(p))
    assert cfg.threads == 5
    assert cfg.modules == ["host_scan", "web_probe"]


def test_ports_string_parsing():
    cfg = Config._from_dict({"ports": "80,443,8080"})
    assert cfg.ports == [80, 443, 8080]
