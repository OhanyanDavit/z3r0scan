"""AI-driven active scan.

Unlike the AI *triage* layer (:mod:`z3r0scan.ai`), which reviews the findings
other modules already produced, this is a first-class scanner module: it gathers
its own non-intrusive evidence from the live target (homepage, response headers,
a bounded body snippet, robots.txt, security.txt) and then asks the configured
LLM to reason over that evidence and emit its own structured security findings.

It complements the signature-based ``vuln_scan`` (nuclei) with reasoning: the
model can spot things like a leaked stack trace, a revealing header combo, an
overly broad CORS policy, or a suspicious path in robots.txt that no template
matches.

Safety and graceful degradation, matching every other module:
  * Only harmless GETs to the target root and two well-known files — no active
    exploitation, fuzzing, or payloads.
  * If no AI provider/key/SDK is configured, the module skips cleanly.
  * The model is instructed to ground every finding in the supplied evidence;
    unparseable output is surfaced as a single info finding rather than dropped.
"""

from __future__ import annotations

import json
import re

from ..models import Confidence, Finding, ModuleResult, Severity
from .base import ScanModule
from .web_probe import BROWSER_UA, candidate_urls

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:  # pragma: no cover
    requests = None

# Keep the evidence bundle bounded so a huge page can't blow the token budget.
MAX_BODY_SNIPPET = 4000
MAX_HEADERS = 40
MAX_ENDPOINTS = 40
# Don't let a chatty model flood the report.
MAX_FINDINGS = 40

# Endpoint/asset discovery from an HTML/JS body (best-effort, non-executing).
_ENDPOINT_RE = re.compile(
    r"""(?:href|src|action)\s*=\s*["']([^"'<>]+)["']"""       # HTML attributes
    r"""|(?:fetch|axios(?:\.\w+)?|open)\s*\(\s*["']([^"']+)["']"""  # JS calls
    r"""|["'](/[A-Za-z0-9_./-]+(?:\?[^"']*)?)["']""",         # bare absolute paths
    re.IGNORECASE,
)
_FORM_RE = re.compile(r"<form\b[^>]*>", re.IGNORECASE)
_PARAM_RE = re.compile(r"[?&]([A-Za-z0-9_\[\]-]{1,40})=")

_SEV_MAP = {
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}
_CONF_MAP = {
    "low": Confidence.LOW,
    "medium": Confidence.MEDIUM,
    "high": Confidence.HIGH,
    "verified": Confidence.VERIFIED,
}

_SYSTEM_PROMPT = (
    "You are a senior web-application penetration tester on an AUTHORIZED, "
    "in-scope engagement. You are given evidence collected from a single live "
    "web target by a non-intrusive HTTP probe: response headers, cookies, a body "
    "snippet, discovered endpoints/links/forms/parameters, robots.txt and "
    "security.txt. Perform a triage review as a human pentester would.\n\n"
    "Work through the OWASP Top 10 (2021) and report concrete, evidence-backed "
    "observations for whichever categories the evidence actually supports:\n"
    "  A01 Broken Access Control (admin/internal paths, IDOR-prone id params, "
    "CORS with credentials)\n"
    "  A02 Cryptographic Failures (missing HSTS, cookies without Secure, mixed "
    "content, sensitive data in the body)\n"
    "  A03 Injection (parameters/forms that look reflected or DB/OS-backed — "
    "candidates for SQLi/XSS/command injection)\n"
    "  A04 Insecure Design  A05 Security Misconfiguration (verbose errors/stack "
    "traces, default pages, debug endpoints, missing security headers, directory "
    "listing)\n"
    "  A06 Vulnerable & Outdated Components (server/framework/library versions "
    "with a known CVE class)\n"
    "  A07 Identification & Auth Failures (login/session endpoints, weak cookie "
    "flags: HttpOnly/SameSite)\n"
    "  A08 Software & Data Integrity  A09 Logging Failures  A10 SSRF "
    "(URL/redirect/fetch parameters).\n\n"
    "Rules:\n"
    "- Ground every finding in the supplied evidence. Do NOT invent endpoints, "
    "versions, or behavior that isn't shown. If evidence is thin, return few or "
    "no findings — never pad.\n"
    "- For each finding: name the OWASP category, cite the exact evidence "
    "(header value, cookie, endpoint, parameter), and give ONE concrete, "
    "non-destructive next test a tester would run to confirm it.\n"
    "- Set severity by real-world impact; set confidence by how strongly the "
    "evidence supports it (a raw observation is low/medium).\n"
    "- Do NOT provide working exploit payloads or instructions for destructive "
    "or mass exploitation — describe the verification step at a high level.\n\n"
    "Respond with STRICT JSON only — no prose, no code fences — of the form:\n"
    '{"findings": [{"title": str, "severity": '
    '"info|low|medium|high|critical", "confidence": '
    '"low|medium|high|verified", "owasp": "A01..A10 or empty", '
    '"endpoint": "relevant URL/param or empty", "description": str, '
    '"next_step": "one concrete non-destructive check"}]}\n'
    "Return an empty findings list if there is nothing security-relevant."
)


class AIScanModule(ScanModule):
    name = "ai_scan"
    description = "AI-driven active scan: gathers evidence, LLM finds issues (needs AI key)"

    def run(self, target: str) -> ModuleResult:
        result = self._result(target)

        # Resolve a provider the same way the triage layer does, so keys/SDK/
        # provider selection behave identically across both AI features.
        from ..ai import resolve_provider  # local import: AI layer is optional

        cls, reason, key = resolve_provider(self.config)
        if cls is None or key is None:
            return self._finish(result, "skipped", reason or "no AI provider configured")
        if requests is None:
            return self._finish(result, "skipped", "requests not installed — cannot gather evidence")

        evidence, probed_url = self._gather(target)
        if self._cancelled():
            return self._finish(result, "ok", "stopped before analysis")
        if not evidence.get("reachable"):
            return self._finish(
                result, "ok",
                f"no HTTP response to analyze for {probed_url} (target down or WAF-blocked)",
            )

        provider = cls(api_key=key, model=self.config.ai_model)
        user_prompt = self._build_prompt(target, evidence)
        try:
            text, _usage = provider.complete(_SYSTEM_PROMPT, user_prompt)
        except Exception as exc:  # noqa: BLE001 - an AI failure must not kill the run
            return self._finish(result, "error", f"{type(exc).__name__}: {exc}")

        if not text:
            return self._finish(
                result, "ok",
                f"{provider.label} returned no analysis (empty response or declined)",
            )

        findings, parse_ok = self._parse(text)
        if not parse_ok:
            # Don't lose the model's work: surface it as one unstructured finding.
            result.add(
                Finding(
                    title="AI analysis (unstructured)",
                    severity=Severity.INFO,
                    confidence=Confidence.LOW,
                    description=text[:2000],
                    evidence={"kind": "ai", "parsed": False, "url": probed_url},
                )
            )
            return self._finish(
                result, "ok", f"{provider.label} ({provider.model}) — output was not valid JSON",
            )

        for item in findings[:MAX_FINDINGS]:
            result.add(self._to_finding(item, probed_url))

        if not result.findings:
            return self._finish(
                result, "ok", f"{provider.label} ({provider.model}) — no security-relevant findings",
            )
        return self._finish(
            result, "ok",
            f"{len(result.findings)} finding(s) from {provider.label} ({provider.model})",
        )

    # ---- evidence gathering (non-intrusive) --------------------------------

    def _gather(self, target: str) -> tuple[dict, str]:
        """Collect a bounded evidence bundle from the target. Read-only GETs."""
        evidence: dict = {"reachable": False}
        probed_url = candidate_urls(target)[0]
        for url in candidate_urls(target):
            page = self._fetch(url)
            if page is None:
                continue
            status, headers, body = page
            probed_url = url
            endpoints, forms, params = self._extract_surface(body)
            evidence.update(
                reachable=True,
                url=url,
                status=status,
                headers=dict(list(headers.items())[:MAX_HEADERS]),
                cookies=self._cookie_flags(headers),
                endpoints=endpoints,
                forms=forms,
                params=params,
                body_snippet=body[:MAX_BODY_SNIPPET],
            )
            base = url.rstrip("/")
            robots = self._fetch(base + "/robots.txt")
            if robots and robots[0] == 200:
                evidence["robots_txt"] = robots[2][:MAX_BODY_SNIPPET]
            sectxt = self._fetch(base + "/.well-known/security.txt")
            if sectxt and sectxt[0] == 200:
                evidence["security_txt"] = sectxt[2][:1000]
            break
        return evidence, probed_url

    def _extract_surface(self, body: str) -> tuple[list[str], int, list[str]]:
        """Pull endpoints, form count, and query-parameter names from a body.

        Best-effort and non-executing — just regex over the served HTML/JS so the
        model has a concrete attack surface (links, form actions, fetch/XHR URLs,
        parameters) to reason about rather than only the homepage text.
        """
        endpoints: list[str] = []
        seen = set()
        for match in _ENDPOINT_RE.finditer(body or ""):
            raw = next((g for g in match.groups() if g), "")
            raw = raw.strip()
            # Skip noise: anchors, data/JS URIs, and asset files with no params.
            if not raw or raw.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
                continue
            if raw not in seen:
                seen.add(raw)
                endpoints.append(raw[:200])
            if len(endpoints) >= MAX_ENDPOINTS:
                break
        params = sorted({m.group(1) for m in _PARAM_RE.finditer(body or "")})[:MAX_ENDPOINTS]
        forms = len(_FORM_RE.findall(body or ""))
        return endpoints, forms, params

    def _cookie_flags(self, headers: dict) -> list[str]:
        """Summarize Set-Cookie flags (HttpOnly/Secure/SameSite) for A07/A02."""
        raw = ""
        for k, v in (headers or {}).items():
            if k.lower() == "set-cookie":
                raw = v
                break
        if not raw:
            return []
        out = []
        for chunk in raw.split(","):
            name = chunk.split("=", 1)[0].strip()
            if not name or "=" not in chunk:
                continue
            low = chunk.lower()
            samesite = "samesite" in low
            out.append(
                f"{name[:40]} [{'HttpOnly ' if 'httponly' in low else ''}"
                f"{'Secure ' if 'secure' in low else ''}"
                f"{'SameSite' if samesite else 'no-SameSite'}]".strip()
            )
            if len(out) >= 15:
                break
        return out

    def _fetch(self, url: str):
        """GET a URL. Returns (status, headers, text) or None."""
        try:
            resp = requests.get(
                url, timeout=self.config.timeout + 5, allow_redirects=True,
                headers={"User-Agent": BROWSER_UA}, verify=False,
            )
        except requests.RequestException:
            return None
        body = (resp.text or "")[: MAX_BODY_SNIPPET * 2]
        return resp.status_code, dict(resp.headers), body

    def _build_prompt(self, target: str, evidence: dict) -> str:
        lines = [
            f"# Target: {target}",
            f"Probed URL: {evidence.get('url')}  (HTTP {evidence.get('status')})",
            "",
            "## Response headers",
            json.dumps(evidence.get("headers", {}), indent=2),
        ]
        cookies = evidence.get("cookies") or []
        if cookies:
            lines += ["", "## Cookies (Set-Cookie flags)", "\n".join(f"- {c}" for c in cookies)]
        endpoints = evidence.get("endpoints") or []
        if endpoints:
            lines += ["", f"## Discovered endpoints ({len(endpoints)})",
                      "\n".join(f"- {e}" for e in endpoints)]
        params = evidence.get("params") or []
        if params:
            lines += ["", "## Query parameters seen", ", ".join(params)]
        forms = evidence.get("forms")
        if forms:
            lines += ["", f"## Forms on page: {forms}"]
        lines += ["", "## Body snippet (truncated)",
                  evidence.get("body_snippet", "") or "(empty)"]
        if "robots_txt" in evidence:
            lines += ["", "## robots.txt", evidence["robots_txt"]]
        if "security_txt" in evidence:
            lines += ["", "## /.well-known/security.txt", evidence["security_txt"]]
        return "\n".join(lines)

    # ---- model output parsing ----------------------------------------------

    def _parse(self, text: str) -> tuple[list[dict], bool]:
        """Extract the findings list from the model's reply. Returns (list, ok)."""
        raw = text.strip()
        # Strip a ```json ... ``` fence if the model added one despite instructions.
        fence = re.search(r"```(?:json)?\s*(.*?)```", raw, re.DOTALL)
        if fence:
            raw = fence.group(1).strip()
        # Fall back to the outermost {...} if there's leading/trailing prose.
        if not raw.startswith("{"):
            brace = re.search(r"\{.*\}", raw, re.DOTALL)
            if brace:
                raw = brace.group(0)
        try:
            data = json.loads(raw)
        except ValueError:
            return [], False
        findings = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(findings, list):
            return [], False
        return [f for f in findings if isinstance(f, dict)], True

    def _to_finding(self, item: dict, probed_url: str) -> Finding:
        sev = _SEV_MAP.get(str(item.get("severity", "info")).lower(), Severity.INFO)
        conf = _CONF_MAP.get(str(item.get("confidence", "low")).lower(), Confidence.LOW)
        owasp = str(item.get("owasp", "")).strip()
        endpoint = str(item.get("endpoint", "")).strip()
        next_step = str(item.get("next_step", "")).strip()
        base_title = str(item.get("title") or "AI finding").strip()[:200]
        title = f"[{owasp}] {base_title}" if owasp else base_title

        desc = str(item.get("description", "")).strip()
        if endpoint:
            desc += f"\nEndpoint: {endpoint}"
        if next_step:
            desc += f"\nNext step: {next_step}"
        return Finding(
            title=title,
            severity=sev,
            confidence=conf,
            description=desc.strip(),
            evidence={"kind": "ai", "parsed": True, "url": probed_url,
                      "owasp": owasp, "endpoint": endpoint, "next_step": next_step},
        )
