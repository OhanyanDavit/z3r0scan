# z3r0scan

**A modular security reconnaissance & scanning orchestrator.**

Point it at a target and it runs the whole recon chain — host/port scan → passive subdomain enumeration → web probing → template-based vuln scanning → Shodan enrichment — then aggregates everything into one report (JSON, Markdown, or HTML).

It drives the real tools you already use (`nmap`, `nuclei`, `subfinder`, `httpx`) when they're installed, and **falls back to pure-Python implementations when they're not**, so it produces useful output on any machine — then scales up to full power in a proper testing environment or the bundled Docker image.

[![CI](https://github.com/OhanyanDavit/z3r0scan/actions/workflows/ci.yml/badge.svg)](https://github.com/OhanyanDavit/z3r0scan/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

---

## ⚠️ Authorized use only

z3r0scan sends traffic to the targets you give it. **Only scan systems you own or have explicit written authorization to test.** Unauthorized scanning is illegal in most jurisdictions. The tool prompts for confirmation before every active scan (bypass with `-y` once you've confirmed scope).

---

## Why it exists

Real recon means juggling a dozen tools, remembering each one's flags, and stitching their output together by hand. z3r0scan makes that a single command with a consistent, machine-readable result — the kind of glue a security engineer writes once and reuses on every engagement. It's also a clean example of a **plugin architecture**: each scanner is an isolated, testable module behind one interface.

## Features

- **One command, full chain** — host scan, subdomains, web probe, vuln scan, enrichment
- **Real tools + graceful fallback** — uses `nmap`/`nuclei`/`subfinder`/`httpx` if present; native Python otherwise
- **"Just give it an API key"** — set `SHODAN_API_KEY` and it pulls Shodan's view of the host with zero packets sent to the target
- **Severity-ranked findings** — flags risky exposures (Redis, Docker API, MongoDB, missing security headers…)
- **Reports in JSON / Markdown / HTML** — pipeline-friendly JSON by default, a polished dark-theme HTML report on request
- **Pluggable** — add a scanner by dropping one class in `z3r0scan/modules/`
- **Safe by default** — authorization prompt, non-root Docker user, no destructive actions

## Install

```bash
git clone https://github.com/OhanyanDavit/z3r0scan.git
cd z3r0scan
pip install -e .
```

Or run fully self-contained with the bundled tools:

```bash
docker build -t z3r0scan .
docker run --rm z3r0scan scan example.com -y --md /dev/stdout
```

## Usage

```bash
# Full chain, interactive authorization prompt, JSON to stdout
z3r0scan example.com

# Pick modules, write an HTML report, skip the prompt (scope already confirmed)
z3r0scan example.com --modules host_scan,web_probe --html report.html -y

# Passive only — enrich from Shodan with an API key, no active packets
export SHODAN_API_KEY=xxxxxxxx
z3r0scan 1.2.3.4 --modules shodan -y

# Custom port set for the host scan
z3r0scan target.local --ports 22,80,443,8080 --html out.html -y

# List available modules
z3r0scan --list-modules
```

### Example output

```console
$ z3r0scan scanme.nmap.org -y --html report.html
[*] running host_scan ...
    [->] ok: 4 finding(s) in 2.1s  pure-python fallback
[*] running subdomains ...
    [->] ok: 3 finding(s) in 1.4s  3 subdomains via crt.sh
[*] running web_probe ...
    [->] ok: 5 finding(s) in 0.9s  pure-python fallback
[*] running vuln_scan ...
    [->] skipped: 0 finding(s)  nuclei not installed
[*] running shodan ...
    [->] skipped: 0 finding(s)  no SHODAN_API_KEY configured

  Findings by severity
  HIGH      1
  LOW       4
  INFO      7
[+] HTML  -> report.html
```

A real scan of `scanme.nmap.org` (nmap's public, authorized test host) is checked in as a sample: [HTML report](docs/sample-report.html) · [Markdown report](docs/sample-report.md).

## How it works

```
            ┌──────────────┐
target ───▶ │ Orchestrator │ ──▶ runs each module in order, collects results
            └──────┬───────┘
                   │
   ┌───────────────┼────────────────┬─────────────┬──────────────┐
   ▼               ▼                ▼             ▼              ▼
host_scan     subdomains        web_probe    vuln_scan       shodan
(nmap /       (subfinder /      (httpx /     (nuclei)        (Shodan API,
 socket)       crt.sh)           requests)                    passive)
                   │
                   ▼
            ┌──────────────┐
            │   Reporter   │ ──▶ JSON · Markdown · HTML
            └──────────────┘
```

Each module implements a single `run(target) -> ModuleResult` method (see `z3r0scan/modules/base.py`). A broken or missing tool downgrades to `skipped`/`error` and never crashes the run.

## Configuration

Precedence: **CLI flags → environment variables → `~/.z3r0scan.yml` → defaults.**

```yaml
# ~/.z3r0scan.yml
threads: 100
timeout: 2.5
modules: [host_scan, subdomains, web_probe, vuln_scan, shodan]
shodan_api_key: "your-key-here"   # or use the SHODAN_API_KEY env var
```

## Extending it

Add a new scanner in three steps:

```python
# z3r0scan/modules/my_scanner.py
from .base import ScanModule
from ..models import Finding, Severity

class MyScanner(ScanModule):
    name = "my_scanner"
    description = "what it does"

    def run(self, target):
        result = self._result(target)
        # ... do work, result.add(Finding(...)) ...
        return self._finish(result, "ok")
```

Register it in `z3r0scan/modules/__init__.py` and it's immediately selectable via `--modules`.

## Development

```bash
pip install -e ".[dev]"
pytest -q          # run the offline test suite
ruff check z3r0scan
```

Tests are fully offline (network calls are monkeypatched), so CI is deterministic.

## Roadmap

- [ ] Async orchestration for concurrent module execution
- [ ] More enrichment sources (Censys, VirusTotal, SecurityTrails)
- [ ] Diff mode — compare two scans and alert on new exposures
- [ ] Optional FastAPI server + web dashboard

## License

MIT — see [LICENSE](LICENSE). Built by [Davit Ohanyan (z3r0_r3t)](https://github.com/OhanyanDavit).
