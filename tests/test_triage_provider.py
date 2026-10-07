"""Tests for LLM provider abstraction, TokenBudget, and kill switch."""

import pytest
from ravel.triage.provider import (
    MockProvider,
    TokenBudget,
    TokenBudgetExceededError,
    create_provider,
)


def test_token_budget_tracking() -> None:
    budget = TokenBudget(limit=100)
    assert budget.total == 0
    assert budget.remaining == 100
    assert not budget.tripped

    budget.record(prompt_tokens=40, completion_tokens=30)
    assert budget.total == 70
    assert budget.remaining == 30
    assert not budget.tripped

    budget.check()  # should not raise


def test_token_budget_kill_switch_tripped() -> None:
    budget = TokenBudget(limit=50)
    budget.record(prompt_tokens=30, completion_tokens=25)
    assert budget.total == 55
    assert budget.tripped
    assert budget.remaining == 0

    with pytest.raises(TokenBudgetExceededError):
        budget.check()


def test_mock_provider_deterministic_evaluation() -> None:
    provider = MockProvider()
    resp_fp = provider.generate("data is sanitized with shlex.quote(param)")
    assert "false_positive" in resp_fp.content
    assert resp_fp.prompt_tokens > 0
    assert resp_fp.completion_tokens > 0

    resp_real = provider.generate("subprocess.run(f'cmd {user_input}', shell=True)")
    assert "real" in resp_real.content


def test_mock_provider_canned_verdict() -> None:
    provider = MockProvider(canned_verdict="real", canned_confidence=0.95)
    resp = provider.generate("arbitrary code")
    assert '"verdict": "real"' in resp.content
    assert '"confidence": 0.95' in resp.content


def test_create_provider_factory() -> None:
    p_mock = create_provider("mock", model="test-model")
    assert isinstance(p_mock, MockProvider)
    assert p_mock.model_name == "test-model"

    with pytest.raises(ValueError, match="Unknown LLM provider type"):
        create_provider("invalid-provider-name")
