"""Command-line interface for z3r0scan.

Uses typer + rich for a polished UX when installed, and degrades to argparse +
plain printing if they are not. Either way the same scan runs.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import __version__
from .config import Config
from .modules import REGISTRY
from .orchestrator import Orchestrator
from .report import to_json, to_markdown, write

BANNER = rf"""
 ____  _____ _____  ___  ___  ___ __ _ _ __
|_  / |___ /|___ / / _ \/ __|/ __/ _` | '_ \
 / /   |_ \ |_ \| (_) \__ \ (_| (_| | | | |
/___| |___/|___/ \___/|___/\___\__,_|_| |_|
        modular recon & scan orchestrator  v{__version__}
"""

DISCLAIMER = (
    "z3r0scan sends traffic to the target. Only scan systems you own or are "
    "explicitly authorized to test. Unauthorized scanning may be illegal."
)


def _build_config(args) -> Config:
    modules = args.modules.split(",") if args.modules else None
    ports = [int(p) for p in args.ports.split(",")] if args.ports else None
    return Config.load(
        config_path=args.config,
        modules=modules,
        ports=ports,
        threads=args.threads,
        timeout=args.timeout,
        authorized=args.yes,
        ai_enabled=args.ai or None,
        ai_provider=args.ai_provider,
        ai_model=args.ai_model,
    )


def _run(args) -> int:
    try:
        from rich.console import Console
        from rich.table import Table
        console = Console()
        rich = True
    except ImportError:
        console = None
        rich = False

    def out(msg=""):
        console.print(msg) if rich else print(_strip(msg))

    out(f"[bold cyan]{BANNER}[/bold cyan]" if rich else BANNER)

    config = _build_config(args)

    if not config.authorized:
        out(f"[yellow]{DISCLAIMER}[/yellow]" if rich else DISCLAIMER)
        try:
            answer = input(f"Proceed with scanning '{args.target}'? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("y", "yes"):
            out("Aborted.")
            return 1

    active = [m for m in config.modules if m in REGISTRY]
    out(f"[dim]Target:[/dim] {args.target}   [dim]Modules:[/dim] {', '.join(active)}" if rich
        else f"Target: {args.target}   Modules: {', '.join(active)}")

    orch = Orchestrator(config)

    def progress(name, result):
        if result is None:
            out(f"[*] {name} ...") if not rich else console.print(f"[cyan][*][/cyan] running [b]{name}[/b] ...")
        else:
            tag = {"ok": "green", "skipped": "yellow", "error": "red"}.get(result.status, "white")
            n = len(result.findings)
            line = f"    -> {result.status}: {n} finding(s) in {result.duration:.1f}s  {result.detail}"
            console.print(f"    [->] [{tag}]{result.status}[/{tag}]: {n} finding(s) "
                          f"in {result.duration:.1f}s  [dim]{result.detail}[/dim]") if rich else out(line)

    report = orch.scan(args.target, on_progress=progress)

    # Summary
    counts = report.severity_counts()
    if rich:
        table = Table(title="Findings by severity", show_edge=False)
        table.add_column("Severity"); table.add_column("Count", justify="right")
        for sev in ["critical", "high", "medium", "low", "info"]:
            table.add_row(sev.upper(), str(counts[sev]))
        console.print(table)
    else:
        out("\nFindings by severity:")
        for sev in ["critical", "high", "medium", "low", "info"]:
            out(f"  {sev.upper():<9} {counts[sev]}")

    # AI analysis (if it ran)
    ai = report.ai
    if ai:
        if ai.get("status") == "ok" and ai.get("summary"):
            header = f"AI analysis — {ai.get('provider')} · {ai.get('model')}"
            if rich:
                from rich.markdown import Markdown
                from rich.panel import Panel
                console.print(Panel(Markdown(ai["summary"]), title=header, border_style="cyan"))
            else:
                out(f"\n=== {header} ===")
                out(ai["summary"])
        elif ai.get("status") != "skipped":
            out(f"[yellow][ai] {ai.get('detail')}[/yellow]" if rich else f"[ai] {ai.get('detail')}")

    # Output files
    if args.json:
        Path(args.json).write_text(to_json(report), encoding="utf-8")
        out(f"[green][+][/green] JSON  -> {args.json}" if rich else f"[+] JSON -> {args.json}")
    if args.md:
        Path(args.md).write_text(to_markdown(report), encoding="utf-8")
        out(f"[green][+][/green] MD    -> {args.md}" if rich else f"[+] MD -> {args.md}")
    if args.html:
        write(report, args.html, "html")
        out(f"[green][+][/green] HTML  -> {args.html}" if rich else f"[+] HTML -> {args.html}")
    if not (args.json or args.md or args.html):
        # Default: print JSON to stdout so the tool is pipeline-friendly.
        print(to_json(report))

    return 2 if report.top_severity.rank >= 3 else 0  # nonzero exit on high/critical


def _strip(msg: str) -> str:
    """Remove rich markup tags for plain-text output."""
    import re
    return re.sub(r"\[/?[a-z0-9_ #]+\]", "", msg)


def build_parser():
    import argparse

    p = argparse.ArgumentParser(
        prog="z3r0scan",
        description="Modular security recon & scan orchestrator.",
        epilog=DISCLAIMER,
    )
    p.add_argument("target", nargs="?", help="domain, IP, or URL to scan")
    p.add_argument("--modules", help=f"comma list; available: {','.join(REGISTRY)}")
    p.add_argument("--ports", help="comma-separated ports for host_scan")
    p.add_argument("--threads", type=int, help="concurrency for the fallback port scan")
    p.add_argument("--timeout", type=float, help="per-connection timeout (seconds)")
    p.add_argument("--config", help="path to a YAML config file")
    p.add_argument("--json", help="write JSON report to this path")
    p.add_argument("--md", help="write Markdown report to this path")
    p.add_argument("--html", help="write HTML report to this path")
    p.add_argument("-y", "--yes", action="store_true", help="skip the authorization prompt")
    p.add_argument("--ai", action="store_true",
                   help="run AI triage of findings (needs ANTHROPIC_API_KEY or OPENAI_API_KEY)")
    p.add_argument("--ai-provider", choices=["auto", "anthropic", "openai"],
                   help="which LLM backend to use for --ai (default: auto)")
    p.add_argument("--ai-model", help="override the AI model (e.g. claude-opus-5, gpt-4o)")
    p.add_argument("--list-modules", action="store_true", help="list available modules and exit")
    p.add_argument("--version", action="version", version=f"z3r0scan {__version__}")
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        for name, cls in REGISTRY.items():
            print(f"{name:<12} {cls.description}")
        return 0

    if not args.target:
        parser.print_help()
        return 1

    try:
        return _run(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
