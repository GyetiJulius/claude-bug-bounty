"""
LLM provider configuration schema.

Supports Groq and Cerebras providers, selected via environment variables or CLI flags.
No API keys are ever hardcoded — all secrets must be supplied through environment variables.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class ProviderName(str, Enum):
    """Supported LLM providers."""

    GROQ = "groq"
    CEREBRAS = "cerebras"


# Default model identifiers per provider
_PROVIDER_DEFAULT_MODELS: dict[str, str] = {
    ProviderName.GROQ: "llama-3.1-70b-versatile",
    ProviderName.CEREBRAS: "llama3.1-70b",
}


@dataclass
class LLMConfig:
    """
    Configuration for a single LLM provider connection.

    All credentials are read from environment variables; never pass raw API keys
    through code.
    """

    provider: ProviderName = field(
        default_factory=lambda: ProviderName(
            os.environ.get("LLM_PROVIDER", ProviderName.GROQ).lower()
        )
    )
    model: str = field(default="")
    temperature: float = 0.2
    max_tokens: int = 2048
    fallback_provider: Optional[ProviderName] = field(
        default_factory=lambda: _resolve_fallback_provider()
    )

    def __post_init__(self) -> None:
        # Normalise provider enum
        if isinstance(self.provider, str):
            self.provider = ProviderName(self.provider.lower())

        # Resolve model: CLI/env takes precedence, then provider default
        if not self.model:
            self.model = os.environ.get(
                "LLM_MODEL",
                _PROVIDER_DEFAULT_MODELS.get(self.provider, ""),
            )

        if self.fallback_provider and isinstance(self.fallback_provider, str):
            self.fallback_provider = ProviderName(self.fallback_provider.lower())

    @property
    def api_key(self) -> Optional[str]:
        """Return the API key for the configured provider from the environment."""
        return _get_api_key(self.provider)

    @property
    def fallback_api_key(self) -> Optional[str]:
        """Return the API key for the fallback provider, if configured."""
        if self.fallback_provider is None:
            return None
        return _get_api_key(self.fallback_provider)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """Build an LLMConfig entirely from environment variables."""
        provider_str = os.environ.get("LLM_PROVIDER", ProviderName.GROQ)
        fallback_str = os.environ.get("LLM_FALLBACK_PROVIDER")

        return cls(
            provider=ProviderName(provider_str.lower()),
            model=os.environ.get("LLM_MODEL", ""),
            fallback_provider=ProviderName(fallback_str.lower()) if fallback_str else None,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_api_key(provider: ProviderName) -> Optional[str]:
    """Look up the API key for *provider* from the environment."""
    key_map: dict[ProviderName, str] = {
        ProviderName.GROQ: "GROQ_API_KEY",
        ProviderName.CEREBRAS: "CEREBRAS_API_KEY",
    }
    env_var = key_map.get(provider)
    return os.environ.get(env_var) if env_var else None


def _resolve_fallback_provider() -> Optional[ProviderName]:
    """Read LLM_FALLBACK_PROVIDER from environment, return None if unset."""
    val = os.environ.get("LLM_FALLBACK_PROVIDER", "")
    if not val:
        return None
    try:
        return ProviderName(val.lower())
    except ValueError:
        return None
