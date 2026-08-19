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

- **Web dashboard** — a local browser UI: type a target, click Scan, watch live progress, and read findings grouped into a Host-scan panel and a Web-scan panel with severity chips (`z3r0scan-web`)
- **One command, full chain** — host scan, subdomains, web probe, vuln scan, enrichment
- **Real tools + graceful fallback** — uses `nmap`/`nuclei`/`subfinder`/`httpx` if present; native Python otherwise
- **False-positive controls** — severity is only escalated for **confirmed** services; `tcpwrapped`/guessed ports are downgraded and tagged, and **CDN/WAF fronting (Cloudflare, Fastly, Akamai…) is detected** so proxied ports are labelled edge artifacts instead of fake criticals
- **Enhanced web scan** — status/title/tech, security-header analysis, TLS certificate inspection (issuer/expiry/weak protocols), sensitive-path checks (`/.git/config`, `/.env`, …), WAF/bot-challenge detection, and honors explicit scheme/port (`http://host:8080`) so local labs work
- **Deep vuln scanning** — nuclei with thousands of community templates, severity filtering, rate limiting, and redirect following
- **Merged subdomain enumeration** — subfinder **and** crt.sh combined and de-duplicated, so a slow/empty source never zeroes out the run
- **Built-in practice lab** — `lab/docker-compose.yml` spins up DVWA + OWASP Juice Shop locally so you always have a legal target to scan
- **"Just give it an API key"** — set `SHODAN_API_KEY` and it pulls Shodan's view of the host with zero packets sent to the target
- **Reports in JSON / Markdown / HTML** — pipeline-friendly JSON by default, a polished dark-theme HTML report on request
- **Pluggable** — add a scanner by dropping one class in `z3r0scan/modules/`
- **Safe by default** — authorization prompt, non-root Docker user, no destructive actions

## Web dashboard

```bash
pip install -e ".[web]"     # install FastAPI + uvicorn
z3r0scan-web                # open http://127.0.0.1:8000
```

Enter a target, choose which modules to run, and hit **Scan** — progress streams live and findings land in two panels (Host / port scan and Web scan). If the target is behind a CDN, a warning banner explains why the port results reflect the edge and not the origin.

## Install

```bash
git clone https://github.com/OhanyanDavit/z3r0scan.git
cd z3r0scan
python3 -m venv .venv && source .venv/bin/activate   # recommended (esp. on macOS)
python -m pip install -e .          # add ".[web]" for the dashboard
```

> On macOS `pip` alone is often not on PATH — use `python3 -m pip …`, and once
> the venv is activated you can use plain `pip`/`python`/`z3r0scan`.

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
