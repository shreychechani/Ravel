"""LLM Provider abstraction, token budgeting, and kill switch.

Per PRODUCT.md §5 and §6:
1. Every LLM call is budget-capped with a hard kill switch, not a soft warning.
2. Local-first and swappable: supports offline mock, local Ollama, and BYO-key
   OpenAI-compatible endpoints.
3. Zero third-party network library dependencies: uses Python standard library
   ``urllib.request``.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from ravel.core.logging import get_logger

log = get_logger("ravel.triage.provider")


@dataclass(frozen=True)
class LLMResponse:
    content: str
    prompt_tokens: int
    completion_tokens: int
    model: str


class TokenBudgetExceededError(RuntimeError):
    """Raised when the kill switch is tripped and further LLM calls are blocked."""


@dataclass
class TokenBudget:
    """Hard per-run token budget with a strict kill switch (PRODUCT.md §6)."""

    limit: int = 100_000
    prompt_tokens: int = 0
    completion_tokens: int = 0
    tripped: bool = False

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    @property
    def remaining(self) -> int:
        return max(0, self.limit - self.total)

    def record(self, prompt_tokens: int, completion_tokens: int) -> None:
        self.prompt_tokens += prompt_tokens
        self.completion_tokens += completion_tokens
        if self.total >= self.limit:
            self.tripped = True
            log.warning(
                "token budget kill switch TRIPPED: %d >= limit %d tokens",
                self.total,
                self.limit,
            )

    def check(self) -> None:
        if self.tripped or self.total >= self.limit:
            self.tripped = True
            msg = (
                f"Token budget of {self.limit} tokens exceeded "
                f"(used {self.total}). Kill switch active."
            )
            raise TokenBudgetExceededError(msg)


class LLMProvider(Protocol):
    """Protocol for swappable LLM execution."""

    model_name: str

    def generate(self, prompt: str, system: str | None = None) -> LLMResponse:
        """Execute one completion under this provider."""
        ...


class MockProvider:
    """Deterministic, local offline provider for tests and dry-runs."""

    def __init__(
        self,
        model_name: str = "mock-triage-model",
        canned_verdict: str | None = None,
        canned_confidence: float = 0.9,
    ) -> None:
        self.model_name = model_name
        self.canned_verdict = canned_verdict
        self.canned_confidence = canned_confidence

    def generate(self, prompt: str, system: str | None = None) -> LLMResponse:
        prompt_tokens = max(1, len(prompt.split()))

        if self.canned_verdict:
            verdict = self.canned_verdict
            reasoning = f"Mock evaluation using canned {verdict} verdict."
        else:
            # Heuristic keyword matching for realistic test simulations
            prompt_lower = prompt.lower()
            if any(
                term in prompt_lower
                for term in ("sanitize", "escape", "clean", "quote", "parameterized")
            ):
                verdict = "false_positive"
                reasoning = (
                    "Code demonstrates effective sanitization or parameterization "
                    "along the execution path."
                )
            elif any(
                term in prompt_lower
                for term in ("unsanitized", "shell=true", "eval(", "exec(", "format(", "%s")
            ):
                verdict = "real"
                reasoning = (
                    "Untrusted input directly reaches the sink without validation "
                    "or defensive constraints."
                )
            else:
                verdict = "needs_review"
                reasoning = (
                    "Complex control flow or insufficient context to decisively "
                    "rule out vulnerability."
                )

        content = json.dumps(
            {
                "verdict": verdict,
                "confidence": self.canned_confidence,
                "reasoning": reasoning,
            }
        )
        completion_tokens = max(1, len(content.split()))

        return LLMResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            model=self.model_name,
        )


class OllamaProvider:
    """Local Ollama model provider (http://localhost:11434)."""

    def __init__(
        self,
        model_name: str = "llama3.2",
        host: str | None = None,
        timeout: float = 60.0,
        json_output: bool = True,
    ) -> None:
        self.model_name = model_name
        base = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.endpoint = base.rstrip("/") + "/api/chat"
        self.timeout = timeout
        self.json_output = json_output  # triage verdicts are JSON; summaries are prose

    def generate(self, prompt: str, system: str | None = None) -> LLMResponse:
        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "stream": False,
            "options": {"temperature": 0.0},
        }
        if self.json_output:
            payload["format"] = "json"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            log.error("Ollama connection failed at %s: %s", self.endpoint, exc)
            raise ConnectionError(f"Failed to connect to Ollama at {self.endpoint}: {exc}") from exc

        content = result.get("message", {}).get("content", "")
        prompt_tokens = int(result.get("prompt_eval_count", len(prompt.split())))
        completion_tokens = int(result.get("eval_count", len(content.split())))

        return LLMResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            model=self.model_name,
        )


class OpenAICompatibleProvider:
    """BYO-key provider for OpenAI, Groq, local vLLM, or other OpenAI-compatible endpoints."""

    def __init__(
        self,
        api_key: str | None = None,
        model_name: str = "gpt-4o-mini",
        base_url: str | None = None,
        timeout: float = 60.0,
        json_output: bool = True,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.model_name = model_name
        base = base_url or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self.endpoint = base.rstrip("/") + "/chat/completions"
        self.timeout = timeout
        self.json_output = json_output

    def generate(self, prompt: str, system: str | None = None) -> LLMResponse:
        if not self.api_key:
            raise ValueError("OpenAI API key missing. Pass an explicit key or set OPENAI_API_KEY.")

        messages: list[dict[str, str]] = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, object] = {
            "model": self.model_name,
            "messages": messages,
            "temperature": 0.0,
        }
        if self.json_output:
            payload["response_format"] = {"type": "json_object"}

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.endpoint,
            data=data,
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                result = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            log.error("OpenAI-compatible request failed at %s: %s", self.endpoint, exc)
            raise ConnectionError(
                f"Failed to query LLM endpoint at {self.endpoint}: {exc}"
            ) from exc

        choices = result.get("choices", [])
        content = choices[0].get("message", {}).get("content", "") if choices else ""
        usage = result.get("usage", {})
        prompt_tokens = int(usage.get("prompt_tokens", len(prompt.split())))
        completion_tokens = int(usage.get("completion_tokens", len(content.split())))

        return LLMResponse(
            content=content,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            model=self.model_name,
        )


def create_provider(
    provider_type: str = "mock",
    model: str | None = None,
    api_key: str | None = None,
    host: str | None = None,
    json_output: bool = True,
) -> LLMProvider:
    """Factory creating an LLM provider. ``json_output=False`` for prose (summaries)."""
    ptype = provider_type.lower()
    if ptype == "mock":
        return MockProvider(model_name=model or "mock-triage-model")
    if ptype == "ollama":
        return OllamaProvider(model_name=model or "llama3.2", host=host, json_output=json_output)
    if ptype in ("openai", "byo-key", "remote"):
        return OpenAICompatibleProvider(
            api_key=api_key,
            model_name=model or "gpt-4o-mini",
            base_url=host,
            json_output=json_output,
        )
    raise ValueError(
        f"Unknown LLM provider type: {provider_type!r}. Must be 'mock', 'ollama', or 'openai'."
    )
