"""Tests for LLM triage adjudication orchestrator."""

from pathlib import Path

import networkx as nx
from ravel.graph.resolve import Coverage, GraphResult
from ravel.models import Finding, FindingSource, Node, NodeKind, Reachability, StaticEvidence
from ravel.triage.adjudicate import adjudicate_findings
from ravel.triage.cache import TriageCache
from ravel.triage.provider import MockProvider, TokenBudget


def test_unreachable_findings_skipped_by_llm(tmp_path: Path) -> None:
    f_node = Node(
        id="app.py::dead_sink::L1",
        kind=NodeKind.FUNCTION,
        qualified_name="dead_sink",
        file_path="app.py",
        start_line=1,
        end_line=2,
        source_hash="deadhash",
    )
    graph_res = GraphResult(
        graph=nx.MultiDiGraph(),
        nodes=[f_node],
        edges=[],
        external_refs=[],
        entry_points=[],
        coverage=Coverage(),
    )
    finding = Finding(
        id="f-dead",
        source=FindingSource.BANDIT,
        node_id=f_node.id,
        rule_id="B101",
        raw_severity="LOW",
        static_evidence=StaticEvidence(
            reachable=Reachability.UNREACHABLE,
            path=[],
            blast_radius=0,
        ),
    )

    provider = MockProvider()
    budget = TokenBudget()
    findings, stats = adjudicate_findings(
        findings=[finding],
        graph_result=graph_res,
        root=tmp_path,
        provider=provider,
        budget=budget,
    )

    assert finding.verdict == "unreachable"
    assert finding.confidence == 1.0
    assert stats.unreachable_skipped == 1
    assert stats.llm_calls == 0
    assert budget.total == 0  # Zero tokens consumed for unreachable finding!


def test_reachable_finding_adjudicated_and_cached(tmp_path: Path) -> None:
    src_file = tmp_path / "app.py"
    src_file.write_text("def sink(): eval(x)\n", encoding="utf-8")

    f_node = Node(
        id="app.py::sink::L1",
        kind=NodeKind.FUNCTION,
        qualified_name="sink",
        file_path="app.py",
        start_line=1,
        end_line=1,
        source_hash="sinkhash",
    )
    graph_res = GraphResult(
        graph=nx.MultiDiGraph(),
        nodes=[f_node],
        edges=[],
        external_refs=[],
        entry_points=[],
        coverage=Coverage(),
    )
    finding = Finding(
        id="f-live",
        source=FindingSource.BANDIT,
        node_id=f_node.id,
        rule_id="B307",
        raw_severity="HIGH",
        static_evidence=StaticEvidence(
            reachable=Reachability.REACHABLE,
            path=[f_node.id],
            blast_radius=1,
        ),
    )

    cache = TriageCache(tmp_path / "cache.json")
    provider = MockProvider(canned_verdict="real", canned_confidence=0.92)
    budget = TokenBudget()

    # First run: should call LLM
    findings, stats1 = adjudicate_findings(
        findings=[finding],
        graph_result=graph_res,
        root=tmp_path,
        provider=provider,
        budget=budget,
        cache=cache,
    )
    assert finding.verdict == "real"
    assert finding.confidence == 0.92
    assert stats1.llm_calls == 1
    assert stats1.cached_hits == 0

    # Second run: should hit cache
    findings, stats2 = adjudicate_findings(
        findings=[finding],
        graph_result=graph_res,
        root=tmp_path,
        provider=provider,
        budget=budget,
        cache=cache,
    )
    assert stats2.llm_calls == 0
    assert stats2.cached_hits == 1
    assert "[cached]" in (finding.reasoning or "")


def test_budget_exhaustion_trips_kill_switch(tmp_path: Path) -> None:
    f_node = Node(
        id="app.py::sink::L1",
        kind=NodeKind.FUNCTION,
        qualified_name="sink",
        file_path="app.py",
        start_line=1,
        end_line=1,
        source_hash="sinkhash",
    )
    graph_res = GraphResult(
        graph=nx.MultiDiGraph(),
        nodes=[f_node],
        edges=[],
        external_refs=[],
        entry_points=[],
        coverage=Coverage(),
    )
    finding = Finding(
        id="f-budget",
        source=FindingSource.BANDIT,
        node_id=f_node.id,
        rule_id="B307",
        raw_severity="HIGH",
        static_evidence=StaticEvidence(
            reachable=Reachability.REACHABLE,
            path=[f_node.id],
            blast_radius=1,
        ),
    )

    provider = MockProvider()
    budget = TokenBudget(limit=10)
    budget.record(10, 5)  # pre-trip budget

    findings, stats = adjudicate_findings(
        findings=[finding],
        graph_result=graph_res,
        root=tmp_path,
        provider=provider,
        budget=budget,
    )
    assert finding.verdict == "needs_review"
    assert "Token budget exhausted" in (finding.reasoning or "")
    assert stats.budget_exhausted == 1
    assert stats.llm_calls == 0
