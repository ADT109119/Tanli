"""Judge - spec §6.4 Confidence / False Positive.

Two-track verification:
- Deterministic (Regex / status / response markers)
- LLM-as-a-Judge (secondary semantic confirmation, deterministic params)
High confidence = deterministic evidence + judge confirm + reproducible.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .config import Config

# Common vulnerability signatures (extensible)
SIGNATURES: dict[str, list[str]] = {
    "sqli": [r"SQL syntax", r"You have an error in your SQL", r"mysql_fetch", r"ORA-"],
    "xss_reflected": [r"<script>alert", r"<svg/onload"],
    "spi_notice": [r"mt_outofwhitespace", r"gamingbanner"],
    "path_traversal": [r"root:x:0:0", r"etc/passwd"],
    "php_errors": [r"PHP Warning", r"Fatal error:"],
}


@dataclass
class Judgment:
    confident: bool
    confidence: float
    false_positive_risk: str  # low|medium|high
    evidence: list[str]
    llm_verdict: str | None = None


class RegexJudge:
    def __init__(self):
        self._compiled = {k: [re.compile(p, re.I) for p in v] for k, v in SIGNATURES.items()}

    def determine(self, body: str, category: str | None = None) -> Judgment:
        """Deterministic scan of response body for known markers."""
        hits: list[str] = []
        cats = [category] if category else list(self._compiled)
        for cat in cats:
            for rx in self._compiled.get(cat, []):
                if rx.search(body):
                    hits.append(cat)
        if hits:
            return Judgment(True, 0.9, "low", hits)
        return Judgment(False, 0.0, "high", [])


class LLMJudge:
    """LLM-as-a-Judge. Deterministic params (temp=0, fixed seed).

    OpenAI-compatible endpoint configured via config.yaml (`llm.judge`)
    or environment (REDTEAM_JUDGE_MODEL / BASE_URL / API_KEY).
    """

    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self._client = None  # lazily init via openai SDK when configured

    @property
    def available(self) -> bool:
        """True if an LLM endpoint is configured & usable (no API call made)."""
        if self._client is not None:
            return True
        try:
            self._ensure_client()
            return True
        except RuntimeError:
            return False

    def _ensure_client(self) -> None:
        if self._client is not None:
            return
        env = Config.resolve_env()
        model = env.get("model") or self.cfg.get("model") or "gpt-4o"
        base_url = env.get("base_url") or self.cfg.get("base_url")
        api_key = env.get("api_key") or self.cfg.get("api_key")
        # Local/free OpenAI-compatible endpoints (vLLM, ollama) may not need a key.
        # Require a key only when no explicit base_url is given (must be cloud API).
        if not api_key and not base_url:
            raise RuntimeError(
                "LLM judge requires either an API key (REDTEAM_JUDGE_API_KEY / "
                "OPENAI_API_KEY) or an OpenAI-compatible base_url "
                "(REDTEAM_JUDGE_BASE_URL)."
            )
        try:
            from openai import OpenAI
        except ImportError:
            raise RuntimeError(
                "openai SDK not installed - run `pip install openai` (works with "
                "any OpenAI-compatible endpoint)."
            )
        kwargs: dict[str, Any] = {"api_key": api_key or "not-needed"}
        if base_url:
            kwargs["base_url"] = base_url
        self._client = OpenAI(**kwargs)
        self._model = model
        self._seed = self.cfg.get("judge_seed", 42)
        self._temperature = self.cfg.get("judge_temperature", 0.0)

    def confirm(self, evidence: str, suspect: str) -> str | None:
        """
        Ask the judge model to confirm/refute a potential finding.
        Returns model verdict text, or None if no LLM configured.

        Prompt is deterministic and asks for a structured verdict
        (confirmed / refuted / uncertain).
        """
        try:
            self._ensure_client()
        except RuntimeError:
            return None  # no LLM -> caller falls back to deterministic only

        # Model may be set by _ensure_client or injected (tests/mocks)
        env = Config.resolve_env()
        model = getattr(self, "_model", None) or env.get("model") or self.cfg.get("model") or "gpt-4o"
        temp = getattr(self, "_temperature", None) or self.cfg.get("judge_temperature", 0.0)
        seed = getattr(self, "_seed", None) or self.cfg.get("judge_seed", 42)

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a security verdict judge. Given a potential "
                    "vulnerability description and evidence, answer with EXACTLY "
                    "one line: CONFIRMED or REFUTED or UNCERTAIN, followed by a "
                    "short reason. Do not output anything else.\n"
                    "CONFIRMED: decisive evidence in the payload/response.\n"
                    "REFUTED: the evidence clearly does not indicate a real "
                    "vulnerability.\n"
                    "UNCERTAIN: cannot decide from evidence alone."
                ),
            },
            {
                "role": "user",
                "content": f"Suspect vulnerability: {suspect}\n\nEvidence:\n{evidence[:2000]}",
            },
        ]
        try:
            resp = self._client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temp,
                seed=seed,
                max_tokens=300,
            )
            return resp.choices[0].message.content or ""
        except Exception as e:  # noqa: BLE001
            return f"LLM_ERROR: {e}"

    def verdict(self, text: str | None) -> str:
        """Normalize LLM output to confirmed/refuted/uncertain."""
        if not text or text.startswith("LLM_ERROR") or text.startswith("None"):
            return "uncertain"
        t = text.strip().upper()
        if t.startswith("CONFIRMED"):
            return "confirmed"
        if t.startswith("REFUTED"):
            return "refuted"
        return "uncertain"
