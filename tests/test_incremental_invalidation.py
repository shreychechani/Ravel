"""Tests for selective reachability path invalidation (Phase 5 Incremental)."""

from __future__ import annotations

from pathlib import Path

from ravel.graph.resolve import build_graph
from ravel.incremental.ast_diff import NodeDiffResult
from ravel.incremental.invalidation import (
    should_invalidate_path,
    update_reachability_incrementally,
)
from ravel.models import Finding, FindingSource, Node, Reachability, StaticEvidence
from ravel.scanners.base import RawFinding, Severity
from ravel.scanners.normalize import LocatedFinding


def _make_lf(finding: Finding, node: Node, line: int = 1) -> LocatedFinding:
    raw = RawFinding(
        source=finding.source,
        rule_id=finding.rule_id,
        rel_path=node.file_path,
        line=line,
        end_line=line,
        raw_severity=finding.raw_severity,
        severity=Severity.LOW,
        confidence="HIGH",
        message="test finding message",
        cwe="CWE-123",
    )
    return LocatedFinding(finding=finding, raw=raw, node=node)


def test_should_invalidate_path() -> None:
    # 1. Dirty node in path
    path = ["entry_node", "middleware_node", "vuln_node"]
    assert should_invalidate_path(path, dirty_node_ids={"middleware_node"}, new_edges_by_dst={})

    # 2. Clean path with no new edges
    assert not should_invalidate_path(path, dirty_node_ids={"unrelated_node"}, new_edges_by_dst={})

    # 3. New external edge into a node on the path
    assert should_invalidate_path(
        path,
        dirty_node_ids=set(),
        new_edges_by_dst={"vuln_node": ["new_route_node"]},
    )


def test_update_reachability_incrementally(tmp_path: Path) -> None:
    # Setup tiny app
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "from fastapi import FastAPI\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/route')\n"
        "def route_fn():\n"
        "    return target_fn()\n"
        "\n"
        "def target_fn():\n"
        "    return 'vulnerable'\n"
        "\n"
        "def isolated_fn():\n"
        "    return 'safe_unreachable'\n",
        encoding="utf-8",
    )
    graph = build_graph(tmp_path)
    nodes_by_qname = {n.qualified_name: n for n in graph.nodes}

    # Finding 1: on isolated_fn (unreachable, clean)
    isolated_node = nodes_by_qname["isolated_fn"]
    f1 = _make_lf(
        Finding(
            id="f1",
            source=FindingSource.BANDIT,
            rule_id="B101",
            raw_severity="LOW",
            node_id=isolated_node.id,
            static_evidence=StaticEvidence(
                reachable=Reachability.UNREACHABLE,
                path=[isolated_node.id],
            ),
        ),
        node=isolated_node,
        line=11,
    )

    # Finding 2: on target_fn (dirty, path includes target_fn)
    target_node = nodes_by_qname["target_fn"]
    f2 = _make_lf(
        Finding(
            id="f2",
            source=FindingSource.BANDIT,
            rule_id="B608",
            raw_severity="HIGH",
            node_id=target_node.id,
            static_evidence=StaticEvidence(
                reachable=Reachability.UNKNOWN,
                path=["old_stale_path", target_node.id],
            ),
        ),
        node=target_node,
        line=8,
    )

    # Mark target_node as dirty, isolated_node as untouched
    diff = NodeDiffResult(
        unchanged_nodes=[isolated_node],
        modified_nodes=[target_node],
        dirty_node_ids={target_node.id},
    )

    result = update_reachability_incrementally(graph, [f1, f2], diff)

    # f1 must be reused (unmodified path)
    assert result.reused_count == 1
    # f2 must be invalidated & recomputed against the active graph
    assert result.invalidated_count == 1

    # Check updated f2: target_fn is reachable from route_fn!
    f2_updated = next(f for f in result.findings if f.finding.id == "f2")
    assert f2_updated.finding.static_evidence is not None
    assert f2_updated.finding.static_evidence.reachable is Reachability.REACHABLE
    assert any("route_fn" in p for p in f2_updated.finding.static_evidence.path)
