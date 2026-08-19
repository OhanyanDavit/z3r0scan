"""Runtime configuration.

Resolution order (highest priority first):
  1. Explicit CLI flags / constructor arguments
  2. Environment variables (Z3R0SCAN_*, SHODAN_API_KEY)
  3. A YAML config file (~/.z3r0scan.yml or one passed with --config)
  4. Built-in defaults
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - yaml is a declared dependency
    yaml = None

# The 100 most common TCP ports — the default "quick" scan set for the
# pure-Python fallback. nmap uses its own top-ports when available.
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 8000, 8888, 6379, 27017,
    9200, 5601, 2375, 2379, 11211, 15672, 9000, 9090, 4444, 5000, 8081,
]


@dataclass
class Config:
    """Everything a scan run needs to know."""

    # Network / behaviour
    ports: list[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    timeout: float = 3.0
    threads: int = 50
    # Which modules to run, in order.
    modules: list[str] = field(
        default_factory=lambda: ["host_scan", "subdomains", "web_probe", "vuln_scan", "shodan"]
    )
    # API tokens for enrichment modules.
    shodan_api_key: str | None = None
    # Safety: require explicit acknowledgement before active scanning.
    authorized: bool = False

    @classmethod
    def load(cls, config_path: str | os.PathLike | None = None, **overrides: Any) -> Config:
        data: dict[str, Any] = {}

        # 3. YAML file
        path = Path(config_path) if config_path else Path.home() / ".z3r0scan.yml"
        if path.exists() and yaml is not None:
            loaded = yaml.safe_load(path.read_text()) or {}
            if isinstance(loaded, dict):
                data.update(loaded)

        # 2. Environment
        env_map = {
            "shodan_api_key": os.getenv("SHODAN_API_KEY") or os.getenv("Z3R0SCAN_SHODAN_KEY"),
            "threads": os.getenv("Z3R0SCAN_THREADS"),
            "timeout": os.getenv("Z3R0SCAN_TIMEOUT"),
        }
        for key, val in env_map.items():
            if val is not None:
                data[key] = val

        # 1. Explicit overrides (drop Nones so they don't clobber lower layers)
        for key, val in overrides.items():
            if val is not None:
                data[key] = val

        return cls._from_dict(data)

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Config:
        valid = {f.name for f in fields(cls)}
        clean: dict[str, Any] = {}
        for key, val in data.items():
            if key not in valid:
                continue
            if key == "threads" and val is not None:
                val = int(val)
            elif key == "timeout" and val is not None:
                val = float(val)
            elif key == "ports" and isinstance(val, str):
                val = [int(p) for p in val.split(",") if p.strip()]
            clean[key] = val
        return cls(**clean)
