"""
Tests for LLM provider selection and fallback logic (llm/factory.py).
"""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from llm.config import LLMConfig, ProviderName, _get_api_key
from llm.factory import create_llm, get_available_providers


# ---------------------------------------------------------------------------
# Config tests
# ---------------------------------------------------------------------------

class TestLLMConfig:
    def test_default_provider_from_env(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": "groq"}, clear=False):
            cfg = LLMConfig.from_env()
        assert cfg.provider == ProviderName.GROQ

    def test_cerebras_provider_from_env(self):
        with patch.dict(os.environ, {"LLM_PROVIDER": "cerebras"}, clear=False):
            cfg = LLMConfig.from_env()
        assert cfg.provider == ProviderName.CEREBRAS

    def test_invalid_provider_raises(self):
        with pytest.raises(ValueError):
            LLMConfig(provider="invalid_provider")  # type: ignore[arg-type]

    def test_model_from_env(self):
        with patch.dict(os.environ, {"LLM_MODEL": "llama3-8b", "LLM_PROVIDER": "groq"}, clear=False):
            cfg = LLMConfig.from_env()
        assert cfg.model == "llama3-8b"

    def test_fallback_provider_from_env(self):
        with patch.dict(
            os.environ,
            {"LLM_FALLBACK_PROVIDER": "cerebras", "LLM_PROVIDER": "groq"},
            clear=False,
        ):
            cfg = LLMConfig.from_env()
        assert cfg.fallback_provider == ProviderName.CEREBRAS

    def test_no_fallback_when_env_empty(self):
        env = {k: v for k, v in os.environ.items() if k != "LLM_FALLBACK_PROVIDER"}
        env["LLM_FALLBACK_PROVIDER"] = ""
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig.from_env()
        assert cfg.fallback_provider is None

    def test_api_key_returns_env_value(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key-123"}, clear=False):
            cfg = LLMConfig(provider=ProviderName.GROQ)
            assert cfg.api_key == "test-key-123"

    def test_api_key_returns_none_when_not_set(self):
        env = {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(provider=ProviderName.GROQ)
            assert cfg.api_key is None


class TestGetApiKey:
    def test_groq_key_from_env(self):
        with patch.dict(os.environ, {"GROQ_API_KEY": "groq-secret"}, clear=False):
            assert _get_api_key(ProviderName.GROQ) == "groq-secret"

    def test_cerebras_key_from_env(self):
        with patch.dict(os.environ, {"CEREBRAS_API_KEY": "cerebras-secret"}, clear=False):
            assert _get_api_key(ProviderName.CEREBRAS) == "cerebras-secret"

    def test_missing_key_returns_none(self):
        env = {k: v for k, v in os.environ.items() if k != "GROQ_API_KEY"}
        with patch.dict(os.environ, env, clear=True):
            assert _get_api_key(ProviderName.GROQ) is None


# ---------------------------------------------------------------------------
# Factory tests — use mocks to avoid actual LangChain/API calls
# ---------------------------------------------------------------------------

class TestCreateLLM:
    def test_raises_value_error_when_no_api_key(self):
        """create_llm should raise ValueError when no API key is configured."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("GROQ_API_KEY", "CEREBRAS_API_KEY")}
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(provider=ProviderName.GROQ, fallback_provider=None)
            cfg.__dict__["_mock_api_key"] = None
            with pytest.raises((ValueError, ImportError)):
                create_llm(cfg)

    def test_fallback_attempted_when_primary_fails(self):
        """When primary has no API key but fallback does, fallback is tried."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("GROQ_API_KEY", "CEREBRAS_API_KEY")}
        env["CEREBRAS_API_KEY"] = "cerebras-key"

        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(
                provider=ProviderName.GROQ,
                fallback_provider=ProviderName.CEREBRAS,
            )

            mock_model = MagicMock()
            # Patch _build_cerebras to return our mock when called
            with patch("llm.factory._build_cerebras", return_value=mock_model) as mock_cb:
                with patch("llm.factory._build_groq", side_effect=ValueError("No Groq key")):
                    result = create_llm(cfg)

            mock_cb.assert_called_once()
            assert result is mock_model

    def test_raises_when_both_providers_fail(self):
        """Should raise ValueError when both primary and fallback fail."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("GROQ_API_KEY", "CEREBRAS_API_KEY")}
        with patch.dict(os.environ, env, clear=True):
            cfg = LLMConfig(
                provider=ProviderName.GROQ,
                fallback_provider=ProviderName.CEREBRAS,
            )
            with patch("llm.factory._build_groq", side_effect=ValueError("No key")):
                with patch("llm.factory._build_cerebras", side_effect=ValueError("No key")):
                    with pytest.raises(ValueError, match="Both primary"):
                        create_llm(cfg)

    def test_groq_model_built_when_key_present(self):
        """When GROQ_API_KEY is set, _build_groq should be called."""
        with patch.dict(os.environ, {"GROQ_API_KEY": "test-key"}, clear=False):
            cfg = LLMConfig(provider=ProviderName.GROQ)
            mock_model = MagicMock()
            with patch("llm.factory._build_groq", return_value=mock_model) as mock_bg:
                result = create_llm(cfg)
            mock_bg.assert_called_once_with(
                "test-key",
                cfg.model,
                cfg.temperature,
                cfg.max_tokens,
            )
            assert result is mock_model

    def test_provider_override_via_kwarg(self):
        """Provider passed as kwarg should override config."""
        with patch.dict(os.environ, {"CEREBRAS_API_KEY": "cb-key"}, clear=False):
            mock_model = MagicMock()
            with patch("llm.factory._build_cerebras", return_value=mock_model):
                result = create_llm(provider="cerebras")
            assert result is mock_model


class TestGetAvailableProviders:
    def test_returns_providers_with_keys(self):
        with patch.dict(
            os.environ,
            {"GROQ_API_KEY": "gk", "CEREBRAS_API_KEY": "ck"},
            clear=False,
        ):
            providers = get_available_providers()
        assert ProviderName.GROQ in providers
        assert ProviderName.CEREBRAS in providers

    def test_empty_when_no_keys(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GROQ_API_KEY", "CEREBRAS_API_KEY")}
        with patch.dict(os.environ, env, clear=True):
            providers = get_available_providers()
        assert providers == []

    def test_only_groq_when_only_groq_key(self):
        env = {k: v for k, v in os.environ.items()
               if k not in ("GROQ_API_KEY", "CEREBRAS_API_KEY")}
        env["GROQ_API_KEY"] = "only-groq"
        with patch.dict(os.environ, env, clear=True):
            providers = get_available_providers()
        assert ProviderName.GROQ in providers
        assert ProviderName.CEREBRAS not in providers
