"""Bottom-up summaries on the planted-bug shop fixture, with a deterministic fake model."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
from ravel.graph.resolve import build_graph
from ravel.models import NodeKind
from ravel.summarize.summaries import (
    SummaryCache,
    callee_first_order,
    known_names,
    summarize_graph,
    unknown_identifiers,
)
from ravel.triage.provider import LLMResponse, TokenBudget

SHOP = Path(__file__).parent.parent / "eval" / "fixtures" / "vuln_shop"


class FakeModel:
    """Names the thing it was asked about; optionally invents a name first."""

    model_name = "fake-summarizer"

    def __init__(self, invent: str | None = None, always_invent: bool = False) -> None:
        self.calls = 0
        self.invent = invent
        self.always_invent = always_invent

    def generate(self, prompt: str, system: str | None = None) -> LLMResponse:
        self.calls += 1
        target = re.search(r"Summarise (?:the module )?`([^`]+)`", prompt)
        name = target.group(1) if target else "?"
        lie = self.invent and (self.always_invent or "Do not mention" not in prompt)
        text = f"`{name}` does its job" + (f" via `{self.invent}`." if lie else ".")
        return LLMResponse(text, prompt_tokens=50, completion_tokens=10, model=self.model_name)


@pytest.fixture
def shop(tmp_path: Path) -> Path:
    repo = tmp_path / "shop"
    shutil.copytree(SHOP, repo)
    return repo


def _name_order(repo: Path) -> list[str]:
    graph = build_graph(repo)
    names = {n.id: n.qualified_name for n in graph.nodes}
    return [names[i] for i in callee_first_order(graph)]


def test_callees_come_before_their_callers(shop: Path) -> None:
    order = _name_order(shop)
    assert order.index("find_product") < order.index("search")
    assert order.index("run_ping") < order.index("ping")


def test_every_function_and_module_is_summarised_then_cached(shop: Path, tmp_path: Path) -> None:
    graph = build_graph(shop)
    cache = SummaryCache(tmp_path / "s.json")
    model = FakeModel()
    run = summarize_graph(graph, shop, model, TokenBudget(), cache)
    wanted = {n.id for n in graph.nodes if n.kind in (NodeKind.FUNCTION, NodeKind.FILE)}
    assert wanted <= set(run.summaries)
    assert run.stats.flagged == 0 and run.stats.cached == 0

    again = summarize_graph(graph, shop, FakeModel(), TokenBudget(), SummaryCache(cache.path))
    assert again.stats.llm_calls == 0
    assert again.stats.cached == len(run.summaries)


def test_an_edit_resummarises_only_the_function_its_callers_and_module(
    shop: Path, tmp_path: Path
) -> None:
    cache = SummaryCache(tmp_path / "s.json")
    summarize_graph(build_graph(shop), shop, FakeModel(), TokenBudget(), cache)

    db = shop / "shop" / "db.py"
    db.write_text(db.read_text().replace("fetchall()", "fetchmany(10)", 1), encoding="utf-8")
    graph = build_graph(shop)
    run = summarize_graph(graph, shop, FakeModel(), TokenBudget(), SummaryCache(cache.path))
    names = {n.id: n.qualified_name for n in graph.nodes}
    regenerated = {names[i] for i, s in run.summaries.items() if s.key not in cache._entries}
    # find_product changed; search calls it; both their modules list them.
    assert regenerated == {"find_product", "search", "shop.db", "shop.app"}


def test_truthfulness_guard_retries_once_then_flags(shop: Path) -> None:
    graph = build_graph(shop)
    fixed = summarize_graph(graph, shop, FakeModel(invent="made_up_helper"), TokenBudget(), limit=1)
    assert fixed.stats.flagged == 0 and fixed.stats.llm_calls > len(fixed.summaries)

    liar = summarize_graph(
        graph, shop, FakeModel(invent="made_up_helper", always_invent=True), TokenBudget(), limit=1
    )
    assert liar.stats.flagged == len(liar.summaries) > 0


def test_unknown_identifiers() -> None:
    assert unknown_identifiers("calls `search()` and `ghost`", {"search"}) == ["ghost"]


def test_builtins_are_known_names(shop: Path) -> None:
    names = known_names(build_graph(shop))
    assert unknown_identifiers("wraps it in `str()` and `open()`", names) == []


def test_budget_kill_switch_leaves_the_rest_unsummarised(shop: Path) -> None:
    run = summarize_graph(build_graph(shop), shop, FakeModel(), TokenBudget(limit=120))
    assert run.stats.skipped_budget > 0
    assert run.stats.generated + run.stats.skipped_budget == run.stats.total
