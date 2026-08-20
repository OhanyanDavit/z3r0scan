"""GPT (OpenAI) provider.

Uses the official ``openai`` SDK. This is the "GPT API token" path: the user
supplies an OpenAI API key and z3r0scan sends the scan findings to GPT for
triage.
"""

from __future__ import annotations

from typing import Any

from .base import AIProvider

_MAX_TOKENS = 4096


class OpenAIProvider(AIProvider):
    name = "openai"
    label = "GPT (OpenAI)"
    default_model = "gpt-4o"

    @classmethod
    def sdk_installed(cls) -> bool:
        try:
            import openai  # noqa: F401
        except ImportError:
            return False
        return True

    def complete(self, system: str, user: str) -> tuple[str, dict[str, Any]]:
        from openai import OpenAI

        client = OpenAI(api_key=self.api_key)
        resp = client.chat.completions.create(
            model=self.model,
            max_tokens=_MAX_TOKENS,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        text = (resp.choices[0].message.content or "").strip()
        usage = {}
        if getattr(resp, "usage", None) is not None:
            usage = {
                "input_tokens": getattr(resp.usage, "prompt_tokens", None),
                "output_tokens": getattr(resp.usage, "completion_tokens", None),
            }
        return text, usage
