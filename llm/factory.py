"""
LLM model factory.

Supports Groq and Cerebras as first-class chat model backends via LangChain.
If LangChain packages are not installed the module degrades gracefully and
``create_llm`` raises ``ImportError`` with a helpful message.

Provider selection order:
  1. Explicit ``provider`` argument.
  2. ``LLM_PROVIDER`` environment variable.
  3. Falls back to ``LLM_FALLBACK_PROVIDER`` if primary key is missing.

No API keys are embedded here — they are resolved from the environment via
``LLMConfig``.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

from .config import LLMConfig, ProviderName

if TYPE_CHECKING:
    # LangChain base type — imported lazily at runtime to avoid hard dependency
    pass

logger = logging.getLogger(__name__)


def create_llm(
    config: Optional[LLMConfig] = None,
    *,
    provider: Optional[str] = None,
    model: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 2048,
):
    """
    Instantiate a LangChain-compatible chat model for the requested provider.

    Parameters
    ----------
    config:
        Full ``LLMConfig``.  When *None* a config is built from environment
        variables.
    provider:
        Override the provider (``"groq"`` | ``"cerebras"``).
    model:
        Override the model name.
    temperature:
        Sampling temperature.
    max_tokens:
        Maximum tokens to generate.

    Returns
    -------
    A LangChain ``BaseChatModel`` instance ready for ``.invoke()`` / ``.stream()``.

    Raises
    ------
    ImportError
        If the required LangChain provider package is not installed.
    ValueError
        If no API key is found for the selected provider and no fallback is
        available.
    """
    if config is None:
        config = LLMConfig.from_env()

    # Allow caller-level overrides
    if provider:
        config.provider = ProviderName(provider.lower())
    if model:
        config.model = model
    if temperature != 0.2:
        config.temperature = temperature
    if max_tokens != 2048:
        config.max_tokens = max_tokens

    # Attempt primary provider; fall back if key is missing
    try:
        return _build_model(config, config.provider)
    except ValueError as primary_err:
        if config.fallback_provider and config.fallback_provider != config.provider:
            logger.warning(
                "Primary provider %s failed (%s); trying fallback %s.",
                config.provider,
                primary_err,
                config.fallback_provider,
            )
            try:
                return _build_model(config, config.fallback_provider)
            except (ValueError, ImportError) as fallback_err:
                raise ValueError(
                    f"Both primary provider ({config.provider}: {primary_err}) "
                    f"and fallback provider ({config.fallback_provider}: {fallback_err}) "
                    "failed.  Check API key environment variables."
                ) from fallback_err
        raise


def get_available_providers() -> list[ProviderName]:
    """Return providers for which an API key is present in the environment."""
    from .config import _get_api_key  # noqa: PLC0415

    return [p for p in ProviderName if _get_api_key(p)]


# ---------------------------------------------------------------------------
# Internal builder helpers
# ---------------------------------------------------------------------------


def _build_model(config: LLMConfig, provider: ProviderName):
    """Build the concrete LangChain chat model for *provider*."""
    api_key = config.api_key if provider == config.provider else config.fallback_api_key

    if not api_key:
        env_vars = {
            ProviderName.GROQ: "GROQ_API_KEY",
            ProviderName.CEREBRAS: "CEREBRAS_API_KEY",
        }
        raise ValueError(
            f"No API key found for provider '{provider}'. "
            f"Set the {env_vars.get(provider, '<PROVIDER>_API_KEY')} environment variable."
        )

    model_name = config.model or _default_model(provider)

    if provider == ProviderName.GROQ:
        return _build_groq(api_key, model_name, config.temperature, config.max_tokens)
    if provider == ProviderName.CEREBRAS:
        return _build_cerebras(api_key, model_name, config.temperature, config.max_tokens)

    raise ValueError(f"Unknown provider: {provider}")


def _default_model(provider: ProviderName) -> str:
    defaults = {
        ProviderName.GROQ: "llama-3.1-70b-versatile",
        ProviderName.CEREBRAS: "llama3.1-70b",
    }
    return defaults[provider]


def _build_groq(api_key: str, model: str, temperature: float, max_tokens: int):
    try:
        from langchain_groq import ChatGroq  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "langchain-groq is not installed.  "
            "Install it with: pip install langchain-groq"
        ) from exc

    return ChatGroq(
        groq_api_key=api_key,
        model_name=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def _build_cerebras(api_key: str, model: str, temperature: float, max_tokens: int):
    try:
        from langchain_cerebras import ChatCerebras  # type: ignore[import-untyped]
    except ImportError as exc:
        raise ImportError(
            "langchain-cerebras is not installed.  "
            "Install it with: pip install langchain-cerebras"
        ) from exc

    return ChatCerebras(
        cerebras_api_key=api_key,
        model=model,
        temperature=temperature,
        max_tokens=max_tokens,
    )
