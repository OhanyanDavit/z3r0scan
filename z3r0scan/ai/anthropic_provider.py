"""Claude (Anthropic) provider.

Uses the official ``anthropic`` SDK. This is the "Claude API token" path: the
user supplies an Anthropic API key and z3r0scan sends the scan findings to
Claude for triage.
"""

from __future__ import annotations

from typing import Any

from .base import AIProvider

# Sensible defaults for a bounded analysis task. The findings prompt is small,
# so a non-streaming call with a few thousand output tokens is plenty.
_MAX_TOKENS = 4096


class AnthropicProvider(AIProvider):
    name = "anthropic"
    label = "Claude (Anthropic)"
    default_model = "claude-opus-5"

    @classmethod
    def sdk_installed(cls) -> bool:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            return False
        return True

    def complete(self, system: str, user: str) -> tuple[str, dict[str, Any]]:
        import anthropic

        client = anthropic.Anthropic(api_key=self.api_key)
        resp = client.messages.create(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        text = "".join(
            block.text for block in resp.content if getattr(block, "type", None) == "text"
        )
        usage = {}
        if getattr(resp, "usage", None) is not None:
            usage = {
                "input_tokens": getattr(resp.usage, "input_tokens", None),
                "output_tokens": getattr(resp.usage, "output_tokens", None),
            }
        return text.strip(), usage
