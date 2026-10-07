"""Tests for finding ranking with LLM verdicts and confidence."""

from ravel.models import Finding, FindingSource, Reachability, StaticEvidence
from ravel.triage.ranking import rank_findings


def test_ranking_orders_by_reachability_then_verdict_then_confidence() -> None:
    f_real = Finding(
        id="f1",
        source=FindingSource.BANDIT,
        node_id="node1",
        rule_id="B602",
        raw_severity="HIGH",
        static_evidence=StaticEvidence(reachable=Reachability.REACHABLE, blast_radius=2),
        verdict="real",
        confidence=0.95,
    )
    f_review = Finding(
        id="f2",
        source=FindingSource.BANDIT,
        node_id="node2",
        rule_id="B602",
        raw_severity="HIGH",
        static_evidence=StaticEvidence(reachable=Reachability.REACHABLE, blast_radius=2),
        verdict="needs_review",
        confidence=0.5,
    )
    f_fp = Finding(
        id="f3",
        source=FindingSource.BANDIT,
        node_id="node3",
        rule_id="B602",
        raw_severity="CRITICAL",  # Higher raw severity, but FP verdict!
        static_evidence=StaticEvidence(reachable=Reachability.REACHABLE, blast_radius=2),
        verdict="false_positive",
        confidence=0.90,
    )
    f_unreachable = Finding(
        id="f4",
        source=FindingSource.BANDIT,
        node_id="node4",
        rule_id="B602",
        raw_severity="CRITICAL",
        static_evidence=StaticEvidence(reachable=Reachability.UNREACHABLE, blast_radius=0),
        verdict="unreachable",
        confidence=1.0,
    )

    # Scramble order
    ranked = rank_findings([f_fp, f_unreachable, f_review, f_real])

    assert [f.id for f in ranked] == ["f1", "f2", "f3", "f4"]
