"""Configuration loading - LiteLLM configurable brain + runtime settings."""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

DEFAULT_CONFIG = {
    "llm": {
        "planner": {"provider": "openai", "model": "gpt-4o"},
        "mutator": {"provider": "litellm", "model": "anthropic/claude-3-haiku"},
        "judge": {
            "provider": "openai_compatible",
            "model": "gpt-4o",
            "base_url": None,  # set via config or env REDTEAM_JUDGE_BASE_URL
            # api_key is read from env: OPENAI_API_KEY / REDTEAM_JUDGE_API_KEY
        },
        "fallback": {"provider": "ollama", "model": "qwen2.5:14b"},
        "token_budget": 500000,
        "judge_temperature": 0.0,
        "judge_seed": 42,
    },
    "runtime": {
        "llm_timeout": 30,
        "web_timeout": 600,
        "job_timeout": 1800,
        "rate_limit_qps": 10,
        "per_endpoint_concurrency": 2,
        "hard_stop": False,
    },
}


class LLMConfig(BaseModel):
    provider: str = "openai_compatible"
    model: str = "gpt-4o"
    base_url: str | None = None


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `override` onto `base` (nested dicts merge key by
    key, so `llm.judge: {base_url: ...}` no longer wipes sibling keys like
    `model`)."""
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_merge(base[k], v)
        else:
            base[k] = v
    return base


class Config(BaseModel):
    llm: dict[str, Any] = Field(default_factory=lambda: copy.deepcopy(DEFAULT_CONFIG["llm"]))
    runtime: dict[str, Any] = Field(default_factory=lambda: copy.deepcopy(DEFAULT_CONFIG["runtime"]))

    @classmethod
    def load(cls, path: str | None = None) -> "Config":
        """Load config from YAML, deep-merging over defaults (deep-copied so
        no global-state mutation leaks across separate loads)."""
        data = copy.deepcopy(DEFAULT_CONFIG)
        if path and Path(path).exists():
            user = yaml.safe_load(Path(path).read_text()) or {}
            for section in ("llm", "runtime"):
                if section in user and isinstance(user[section], dict):
                    _deep_merge(data[section], user[section])
        return cls(**data)

    @staticmethod
    def resolve_env() -> dict[str, str]:
        """Collect OpenAI-compatible runtime settings from environment.

        Env vars (highest priority, override config.yaml):
          REDTEAM_JUDGE_MODEL      - judge model name
          REDTEAM_JUDGE_BASE_URL   - OpenAI-compatible endpoint base
          REDTEAM_JUDGE_API_KEY    - API key for that endpoint
        Falls back to OPENAI_API_KEY etc.
        """
        resolved = {}
        if m := os.environ.get("REDTEAM_JUDGE_MODEL"):
            resolved["model"] = m
        if b := os.environ.get("REDTEAM_JUDGE_BASE_URL"):
            resolved["base_url"] = b
        if k := os.environ.get("REDTEAM_JUDGE_API_KEY"):
            resolved["api_key"] = k
        elif k := os.environ.get("OPENAI_API_KEY"):
            resolved["api_key"] = k
        return resolved

    def api_key(self, provider: str) -> str | None:
        """Read API key from environment (never from repo/config)."""
        env_map = {
            "openai": "OPENAI_API_KEY",
            "anthropic": "ANTHROPIC_API_KEY",
            "groq": "GROQ_API_KEY",
            "deepseek": "DEEPSEEK_API_KEY",
        }
        env = env_map.get(provider)
        return os.environ.get(env) if env else None
