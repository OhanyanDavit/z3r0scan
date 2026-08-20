"""Render a :class:`ScanReport` to JSON, Markdown, or a self-contained HTML file."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .models import ScanReport

SEV_COLORS = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#fbc02d",
    "low": "#388e3c",
    "info": "#607d8b",
}


def to_json(report: ScanReport, indent: int = 2) -> str:
    return json.dumps(report.to_dict(), indent=indent, default=str)


def to_markdown(report: ScanReport) -> str:
    d = report.to_dict()
    lines = [
        f"# z3r0scan report — `{report.target}`",
        "",
        f"- **Duration:** {d['duration']}s",
        f"- **Top severity:** {d['top_severity'].upper()}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "| --- | --- |",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {sev.capitalize()} | {d['severity_counts'][sev]} |")
    lines.append("")

    ai = d.get("ai")
    if ai and ai.get("status") == "ok" and ai.get("summary"):
        lines.append(f"## 🤖 AI analysis  _(via {ai.get('provider')} · {ai.get('model')})_")
        lines.append("")
        lines.append(ai["summary"])
        lines.append("")

    for module in report.modules:
        lines.append(f"## {module.module}  _(status: {module.status})_")
        if module.detail:
            lines.append(f"> {module.detail}")
        lines.append("")
        if not module.findings:
            lines.append("_No findings._\n")
            continue
        for f in module.findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title}")
            if f.description:
                lines.append(f"  - {f.description}")
        lines.append("")
    return "\n".join(lines)


def md_to_html(text: str) -> str:
    """Very small Markdown → HTML converter for AI summaries.

    Handles headings (``##``), unordered lists (``-``), ``**bold**``, and
    paragraphs. Not a full parser — just enough to render an LLM triage cleanly
    without pulling in a Markdown dependency. Input is HTML-escaped first.
    """
    import html as _html
    import re

    out: list[str] = []
    in_list = False

    def inline(s: str) -> str:
        s = _html.escape(s)
        s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
        s = re.sub(r"`([^`]+?)`", r"<code>\1</code>", s)
        return s

    for raw in text.splitlines():
        line = raw.rstrip()
        heading = re.match(r"^(#{1,6})\s+(.*)$", line)
        bullet = re.match(r"^\s*[-*]\s+(.*)$", line)
        if bullet:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(bullet.group(1))}</li>")
            continue
        if in_list:
            out.append("</ul>")
            in_list = False
        if heading:
            level = min(len(heading.group(1)) + 2, 6)  # ## -> h4, keeps report h2/h3 free
            out.append(f"<h{level}>{inline(heading.group(2))}</h{level}>")
        elif line:
            out.append(f"<p>{inline(line)}</p>")
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


def _ai_context(report: ScanReport) -> tuple[dict | None, str]:
    ai = report.ai
    if ai and ai.get("status") == "ok" and ai.get("summary"):
        return ai, md_to_html(ai["summary"])
    return ai, ""


def to_html(report: ScanReport) -> str:
    """Render HTML. Uses a Jinja2 template if available; otherwise builds the
    markup inline so the reporter has no hard template dependency."""
    d = report.to_dict()
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    ai, ai_html = _ai_context(report)

    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape

        env = Environment(
            loader=FileSystemLoader(str(Path(__file__).parent / "templates")),
            autoescape=select_autoescape(["html"]),
        )
        tmpl = env.get_template("report.html.j2")
        return tmpl.render(
            report=report, d=d, colors=SEV_COLORS, generated=generated, ai=ai, ai_html=ai_html
        )
    except Exception:  # noqa: BLE001 - any template failure must still yield a report
        return _html_fallback(report, d, generated)


def _html_fallback(report: ScanReport, d: dict, generated: str) -> str:
    import html

    rows = ""
    for module in report.modules:
        rows += f"<h2>{html.escape(module.module)} <small>({html.escape(module.status)})</small></h2>"
        if module.detail:
            rows += f"<p class='detail'>{html.escape(module.detail)}</p>"
        if not module.findings:
            rows += "<p class='none'>No findings.</p>"
            continue
        rows += "<ul>"
        for f in module.findings:
            color = SEV_COLORS[f.severity.value]
            rows += (
                f"<li><span class='sev' style='background:{color}'>"
                f"{f.severity.value.upper()}</span> {html.escape(f.title)}"
            )
            if f.description:
                rows += f"<div class='desc'>{html.escape(f.description)}</div>"
            rows += "</li>"
        rows += "</ul>"

    ai, ai_html = _ai_context(report)
    ai_block = ""
    if ai_html:
        ai_block = (
            f"<h2>🤖 AI analysis <small>(via {html.escape(str(ai.get('provider')))} · "
            f"{html.escape(str(ai.get('model')))})</small></h2>"
            f"<div class='ai'>{ai_html}</div>"
        )

    chips = "".join(
        f"<span class='chip' style='background:{SEV_COLORS[s]}'>{s}: {d['severity_counts'][s]}</span>"
        for s in ["critical", "high", "medium", "low", "info"]
    )
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>z3r0scan — {html.escape(report.target)}</title>
<style>
body{{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem;max-width:960px;margin:auto}}
h1{{color:#58a6ff}} h2{{border-bottom:1px solid #30363d;padding-bottom:.3rem;margin-top:2rem}}
small{{color:#8b949e;font-weight:normal}}
.chip,.sev{{color:#fff;padding:.15rem .5rem;border-radius:6px;font-size:.8rem;font-weight:600}}
.chip{{margin-right:.4rem}} .desc{{color:#8b949e;font-size:.9rem;margin:.2rem 0 .6rem 3.2rem}}
.detail{{color:#8b949e;font-style:italic}} .none{{color:#8b949e}}
ul{{list-style:none;padding:0}} li{{padding:.4rem 0;border-bottom:1px solid #21262d}}
header{{margin-bottom:1rem}}
.ai{{background:#161b22;border:1px solid #30363d;border-left:3px solid #58a6ff;border-radius:8px;padding:.6rem 1.1rem;margin:.5rem 0}}
.ai h4,.ai h5,.ai h6{{color:#58a6ff;margin:.9rem 0 .3rem}} .ai ul{{list-style:disc;padding-left:1.3rem}}
.ai li{{border:0;padding:.15rem 0}} .ai code{{background:#0d1117;padding:.1rem .3rem;border-radius:4px}}
</style></head><body>
<header><h1>z3r0scan report</h1>
<p>Target: <b>{html.escape(report.target)}</b> · Duration: {d['duration']}s · Generated: {generated}</p>
<div>{chips}</div></header>
{ai_block}
{rows}
<footer style="margin-top:3rem;color:#8b949e;font-size:.85rem">
Generated by z3r0scan — authorized security testing only.</footer>
</body></html>"""


def write(report: ScanReport, path: str, fmt: str) -> None:
    content = {"json": to_json, "md": to_markdown, "markdown": to_markdown, "html": to_html}[fmt](report)
    Path(path).write_text(content, encoding="utf-8")
