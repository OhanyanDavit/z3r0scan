"""AI analysis layer.

Turns a completed :class:`~z3r0scan.models.ScanReport` into an LLM-written triage
using whichever provider the user configured (Claude or GPT). The whole layer is
optional and degrades gracefully: no key, no SDK, or an API failure yields an
``AIAnalysis`` with a ``skipped``/``error`` status instead of raising.
"""

from __future__ import annotations

from ..config import Config
from ..models import ScanReport
from .anthropic_provider import AnthropicProvider
from .base import SYSTEM_PROMPT, AIAnalysis, AIProvider, build_prompt
from .openai_provider import OpenAIProvider

# Registered providers, in preference order for "auto" resolution.
PROVIDERS: dict[str, type[AIProvider]] = {
    AnthropicProvider.name: AnthropicProvider,
    OpenAIProvider.name: OpenAIProvider,
}

__all__ = ["PROVIDERS", "AIAnalysis", "AIProvider", "provider_status", "run_ai_analysis"]


def _key_for(provider_name: str, config: Config) -> str | None:
    return {
        "anthropic": config.anthropic_api_key,
        "openai": config.openai_api_key,
    }.get(provider_name)


def resolve_provider(config: Config) -> tuple[type[AIProvider] | None, str, str | None]:
    """Pick a provider class from config. Returns (cls, reason, api_key).

    ``cls`` is None when nothing usable is configured; ``reason`` explains why so
    the caller can surface it to the user.
    """
    requested = (config.ai_provider or "auto").lower()

    if requested != "auto":
        cls = PROVIDERS.get(requested)
        if cls is None:
            return None, f"unknown AI provider '{requested}'", None
        key = _key_for(requested, config)
        if not key:
            return None, f"no API key for {cls.label}", None
        if not cls.sdk_installed():
            return None, f"{cls.label} SDK not installed (pip install z3r0scan[ai])", None
        return cls, "", key

    # auto: first provider that has both a key and its SDK.
    missing = []
    for name, cls in PROVIDERS.items():
        key = _key_for(name, config)
        if not key:
            continue
        if not cls.sdk_installed():
            missing.append(f"{cls.label} (SDK missing)")
            continue
        return cls, "", key
    if missing:
        return None, "have key but SDK missing for: " + ", ".join(missing), None
    return None, "no AI API key configured (Claude or OpenAI)", None


def provider_status(config: Config | None = None) -> list[dict]:
    """Report each provider's availability — used by the dashboard settings UI."""
    out = []
    for name, cls in PROVIDERS.items():
        entry = {
            "name": name,
            "label": cls.label,
            "default_model": cls.default_model,
            "sdk_installed": cls.sdk_installed(),
            "has_key": bool(_key_for(name, config)) if config else False,
        }
        out.append(entry)
    return out


def run_ai_analysis(report: ScanReport, config: Config) -> AIAnalysis:
    """Run the configured provider over a report. Never raises."""
    cls, reason, key = resolve_provider(config)
    if cls is None or key is None:
        return AIAnalysis(provider=config.ai_provider or "auto", model="", status="skipped", detail=reason)

    provider = cls(api_key=key, model=config.ai_model)
    prompt = build_prompt(report)
    try:
        text, usage = provider.complete(SYSTEM_PROMPT, prompt)
    except Exception as exc:  # noqa: BLE001 - an AI failure must not break the scan
        return AIAnalysis(
            provider=provider.name,
            model=provider.model,
            status="error",
            detail=f"{type(exc).__name__}: {exc}",
        )
    if not text:
        return AIAnalysis(
            provider=provider.name, model=provider.model, status="error",
            detail="provider returned an empty response",
        )
    return AIAnalysis(
        provider=provider.name,
        model=provider.model,
        status="ok",
        detail=f"analysis by {provider.label} ({provider.model})",
        summary=text,
        usage=usage,
    )
