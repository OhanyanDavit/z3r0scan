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

- **AI finding triage (bring your own key)** — after a scan, send the findings to **Claude (Anthropic)** or **GPT (OpenAI)** for an instant, prioritized analysis: executive summary, ranked findings with confidence, likely false positives, and concrete next steps. Enter your API token in the dashboard's settings panel or via `--ai` on the CLI. No key configured? The tool works exactly as before — AI is purely additive.
- **Web dashboard (redesigned)** — a polished local browser UI: type a target, click Scan, watch live progress, and read findings in Host-scan / Web-scan panels with severity stat tiles. A **⚙️ Settings panel** holds your Claude / OpenAI / Shodan tokens (kept in your browser, sent only to your local instance), a provider/model picker, a light/dark theme toggle, and a one-click **Test key** button (`z3r0scan-web`).
- **One command, full chain** — host scan, subdomains, web probe, vuln scan, enrichment
- **Real tools + graceful fallback** — uses `nmap`/`nuclei`/`subfinder`/`httpx` if present; native Python otherwise
- **False-positive controls** — severity is only escalated for **confirmed** services; `tcpwrapped`/guessed ports are downgraded and tagged, and **CDN/WAF fronting (Cloudflare, Fastly, Akamai…) is detected** so proxied ports are labelled edge artifacts instead of fake criticals
- **Enhanced web scan** — status/title/tech, security-header analysis, TLS certificate inspection (issuer/expiry/weak protocols), sensitive-path checks (`/.git/config`, `/.env`, …), WAF/bot-challenge detection, and honors explicit scheme/port (`http://host:8080`) so local labs work
- **Deep vuln scanning** — nuclei with thousands of community templates, severity filtering, rate limiting, and redirect following
- **Subdomain recon pipeline** — enumerate (subfinder + crt.sh) → **resolve via dnsx/DNS** → report only subdomains that actually exist, with their IPs. Turns tens of thousands of dead cert names into a short, real attack surface
- **Built-in practice lab** — `lab/docker-compose.yml` spins up DVWA + OWASP Juice Shop locally so you always have a legal target to scan
- **"Just give it an API key"** — set `SHODAN_API_KEY` and it pulls Shodan's view of the host with zero packets sent to the target
- **Reports in JSON / Markdown / HTML** — pipeline-friendly JSON by default, a polished dark-theme HTML report on request
- **Pluggable** — add a scanner by dropping one class in `z3r0scan/modules/`
- **Safe by default** — authorization prompt, non-root Docker user, no destructive actions

## Web dashboard

```bash
pip install -e ".[all]"     # FastAPI + uvicorn + AI SDKs (or ".[web]" for no AI)
z3r0scan-web                # open http://127.0.0.1:8000
```

Enter a target, choose which modules to run, and hit **Scan** — progress streams live and findings land in two panels (Host / port scan and Web scan). If the target is behind a CDN, a warning banner explains why the port results reflect the edge and not the origin.

Open **⚙️ Settings** to paste your API tokens (Claude, OpenAI, Shodan), pick an AI provider/model, and toggle AI analysis. Keys are stored in your browser's `localStorage` and sent only to your local `127.0.0.1` instance — never persisted server-side or to disk. Flip on the **🤖 AI analysis** pill and every scan ends with an AI-written triage panel.

## AI analysis — bring your own key

z3r0scan can hand the raw scan output to an LLM and get back a hunter-grade triage. It supports two providers out of the box:

| Provider | SDK | Default model | Token source |
|---|---|---|---|
| Claude | `anthropic` | `claude-opus-5` | `ANTHROPIC_API_KEY` env, settings panel, or `~/.z3r0scan.yml` |
| GPT | `openai` | `gpt-4o` | `OPENAI_API_KEY` env, settings panel, or `~/.z3r0scan.yml` |

```bash
pip install -e ".[ai]"                       # install the LLM SDKs

# CLI — AI triage appended to the run (provider auto-selected from your keys)
export ANTHROPIC_API_KEY=sk-ant-...
z3r0scan example.com -y --ai --html report.html

# Force a provider / model
z3r0scan example.com -y --ai --ai-provider openai --ai-model gpt-4o
```

The AI step is defensive-analysis only, runs **after** scanning, and never changes what traffic is sent to the target. If the SDK or key is missing it degrades to a `skipped` note instead of failing the scan. The analysis is included in the JSON, Markdown, and HTML reports.

## Install

```bash
git clone https://github.com/OhanyanDavit/z3r0scan.git
cd z3r0scan
python3 -m venv .venv && source .venv/bin/activate   # recommended (esp. on macOS)
python -m pip install -e .          # add ".[web]" for the dashboard
```

> On macOS `pip` alone is often not on PATH — use `python3 -m pip …`, and once
> the venv is activated you can use plain `pip`/`python`/`z3r0scan`.

Or run it in Docker (bundles nmap; other modules use the pure-Python fallback):

```bash
docker build -t z3r0scan .
# target is the first argument — there is no "scan" subcommand
docker run --rm z3r0scan example.com -y --md /dev/stdout
# mount a volume to keep report files (the container writes to /reports)
docker run --rm -v "$PWD/reports:/reports" z3r0scan example.com -y --html /reports/out.html
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

# Scan + AI triage of the findings (needs an Anthropic or OpenAI key)
z3r0scan example.com -y --ai --html report.html

# Gate CI on severity, and consume the JSON directly (stdout is pure JSON)
z3r0scan example.com -y --fail-on medium | jq '.severity_counts'

# List available modules
z3r0scan --list-modules
```

### Pipeline output & exit codes

In the default mode (no `--json`/`--md`/`--html`), **stdout is a single JSON document** and all human-facing output (banner, progress, severity table) goes to stderr — so `z3r0scan host | jq` just works. Exit codes are machine-readable:

| Code | Meaning |
|---|---|
| `0` | Completed; no finding reached the `--fail-on` severity (default `high`) |
| `2` | A finding reached the `--fail-on` threshold |
| `3` | One or more requested modules errored (a failed scan no longer exits `0`) |
| `64` | Invalid target or arguments (empty, spaces, control chars, or a leading `-`) |

Every target is validated before any packet is sent — option-like strings such as `-oX` are rejected so they can't be smuggled into a tool like nmap as a flag.

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
            ┌──────────────┐     ┌──────────────────────┐
            │  AI analysis │ ◀── │ findings (all modules)│
            │ (Claude/GPT) │     └──────────────────────┘
            └──────┬───────┘     (optional — needs a key)
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

# AI triage (optional) — bring your own key
ai_enabled: true
ai_provider: auto                 # auto | anthropic | openai
ai_model: claude-opus-5           # optional; omit to use the provider default
anthropic_api_key: "sk-ant-..."   # or the ANTHROPIC_API_KEY env var
openai_api_key: "sk-..."          # or the OPENAI_API_KEY env var
```

Precedence for AI keys, like everything else: **CLI flags → environment variables (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`) → `~/.z3r0scan.yml` → defaults.** In the web dashboard, keys entered in the settings panel are sent per-scan and take priority for that run.

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

- [x] Optional FastAPI server + web dashboard
- [x] AI finding triage (Claude / GPT, bring your own key)
- [ ] Async orchestration for concurrent module execution
- [ ] More enrichment sources (Censys, VirusTotal, SecurityTrails)
- [ ] Diff mode — compare two scans and alert on new exposures
- [ ] More AI providers (local models via Ollama, Azure OpenAI)

## License

MIT — see [LICENSE](LICENSE). Built by [Davit Ohanyan (z3r0_r3t)](https://github.com/OhanyanDavit).
