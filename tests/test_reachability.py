"""Tests for Phase 3 reachability analysis and ranking (PRODUCT.md §3, §4, §6)."""

from __future__ import annotations

from pathlib import Path

import networkx as nx
from ravel.graph.resolve import GraphResult
from ravel.models import (
    EntryPoint,
    EntryPointKind,
    Finding,
    FindingSource,
    Node,
    NodeKind,
    Reachability,
    Trust,
)
from ravel.scanners.run import scan_repo
from ravel.triage.ranking import rank_findings
from ravel.triage.reachability import analyze_reachability, evaluate_node_reachability

FLASKR = Path("eval/fixtures/flaskr")


def _make_node(nid: str, kind: NodeKind = NodeKind.FUNCTION) -> Node:
    return Node(
        id=nid,
        kind=kind,
        qualified_name=nid.split("::")[-1],
        file_path=nid.split("::")[0],
        start_line=1,
        end_line=10,
        source_hash="hash123",
    )


def _make_finding(fid: str, node_id: str, severity: str = "HIGH") -> Finding:
    return Finding(
        id=fid,
        source=FindingSource.BANDIT,
        node_id=node_id,
        rule_id="B101",
        raw_severity=severity,
    )


def test_reachable_path() -> None:
    """Entry point -> F1 -> F2 -> Sink (all resolved). Should be REACHABLE."""
    graph = nx.MultiDiGraph()
    nodes = [
        _make_node("app.py::route_handler"),
        _make_node("app.py::helper_f1"),
        _make_node("app.py::sink_f2"),
    ]
    for n in nodes:
        graph.add_node(n.id)

    graph.add_edge(
        "app.py::route_handler", "app.py::helper_f1", key="calls", kind="calls", resolved=True
    )
    graph.add_edge("app.py::helper_f1", "app.py::sink_f2", key="calls", kind="calls", resolved=True)

    eps = [
        EntryPoint(
            node_id="app.py::route_handler",
            kind=EntryPointKind.HTTP_ROUTE,
            trust=Trust.UNTRUSTED,
        )
    ]
    graph_res = GraphResult(graph=graph, nodes=nodes, edges=[], entry_points=eps)
    finding = _make_finding("f1", "app.py::sink_f2")

    analyze_reachability(graph_res, [finding])

    assert finding.static_evidence is not None
    assert finding.static_evidence.reachable is Reachability.REACHABLE
    assert finding.static_evidence.path == [
        "app.py::route_handler",
        "app.py::helper_f1",
        "app.py::sink_f2",
    ]
    assert finding.static_evidence.blast_radius == 1


def test_unreachable_path() -> None:
    """Isolated function with no path from untrusted entry point -> UNREACHABLE."""
    graph = nx.MultiDiGraph()
    nodes = [
        _make_node("app.py::route_handler"),
        _make_node("utils.py::dead_func"),
    ]
    for n in nodes:
        graph.add_node(n.id)

    eps = [
        EntryPoint(
            node_id="app.py::route_handler",
            kind=EntryPointKind.HTTP_ROUTE,
            trust=Trust.UNTRUSTED,
        )
    ]
    graph_res = GraphResult(graph=graph, nodes=nodes, edges=[], entry_points=eps)
    finding = _make_finding("f2", "utils.py::dead_func")

    analyze_reachability(graph_res, [finding])

    assert finding.static_evidence is not None
    assert finding.static_evidence.reachable is Reachability.UNREACHABLE
    assert finding.static_evidence.path == []
    assert finding.static_evidence.blast_radius == 0


def test_unknown_path_unresolved_edge() -> None:
    """Path containing an unresolved edge (resolved=False) -> UNKNOWN (never dropped)."""
    graph = nx.MultiDiGraph()
    nodes = [
        _make_node("app.py::route_handler"),
        _make_node("unknown::dynamic_call"),
        _make_node("db.py::query"),
    ]
    for n in nodes:
        graph.add_node(n.id)

    graph.add_edge(
        "app.py::route_handler",
        "unknown::dynamic_call",
        key="calls",
        kind="calls",
        resolved=False,
    )
    graph.add_edge(
        "unknown::dynamic_call",
        "db.py::query",
        key="calls",
        kind="calls",
        resolved=True,
    )

    eps = [
        EntryPoint(
            node_id="app.py::route_handler",
            kind=EntryPointKind.HTTP_ROUTE,
            trust=Trust.UNTRUSTED,
        )
    ]
    graph_res = GraphResult(graph=graph, nodes=nodes, edges=[], entry_points=eps)
    finding = _make_finding("f3", "db.py::query")

    analyze_reachability(graph_res, [finding])

    assert finding.static_evidence is not None
    assert finding.static_evidence.reachable is Reachability.UNKNOWN
    assert finding.static_evidence.path == [
        "app.py::route_handler",
        "unknown::dynamic_call",
        "db.py::query",
    ]
    assert finding.static_evidence.blast_radius == 1


def test_internal_entry_point_ignored() -> None:
    """Entry point with trust=Trust.INTERNAL should NOT mark findings as REACHABLE."""
    graph = nx.MultiDiGraph()
    nodes = [_make_node("cron.py::task"), _make_node("db.py::purge")]
    for n in nodes:
        graph.add_node(n.id)
    graph.add_edge("cron.py::task", "db.py::purge", key="calls", kind="calls", resolved=True)

    eps = [
        EntryPoint(
            node_id="cron.py::task",
            kind=EntryPointKind.CRON,
            trust=Trust.INTERNAL,
        )
    ]
    graph_res = GraphResult(graph=graph, nodes=nodes, edges=[], entry_points=eps)
    finding = _make_finding("f4", "db.py::purge")

    analyze_reachability(graph_res, [finding])

    assert finding.static_evidence is not None
    assert finding.static_evidence.reachable is Reachability.UNREACHABLE


def test_finding_without_node_is_unknown() -> None:
    """A finding with no node in the graph has nothing to trace -> UNKNOWN, not UNREACHABLE."""
    graph = nx.MultiDiGraph()
    graph.add_node("app.py::route_handler")
    eps = [
        EntryPoint(
            node_id="app.py::route_handler",
            kind=EntryPointKind.HTTP_ROUTE,
            trust=Trust.UNTRUSTED,
        )
    ]
    graph_res = GraphResult(graph=graph, nodes=[], edges=[], entry_points=eps)
    no_node = _make_finding("f_none", "")
    missing_node = _make_finding("f_missing", "gone.py::f")

    analyze_reachability(graph_res, [no_node, missing_node])

    for f in (no_node, missing_node):
        assert f.static_evidence is not None
        assert f.static_evidence.reachable is Reachability.UNKNOWN


def test_no_entry_points_marks_everything_unknown() -> None:
    """No entry points detected -> UNKNOWN for all, since unreachable would be a guess."""
    graph = nx.MultiDiGraph()
    nodes = [_make_node("app.py::handler"), _make_node("db.py::query")]
    for n in nodes:
        graph.add_node(n.id)
    graph.add_edge("app.py::handler", "db.py::query", key="calls", kind="calls", resolved=True)
    graph_res = GraphResult(graph=graph, nodes=nodes, edges=[], entry_points=[])
    finding = _make_finding("f_noep", "db.py::query")

    analyze_reachability(graph_res, [finding])

    assert finding.static_evidence is not None
    assert finding.static_evidence.reachable is Reachability.UNKNOWN


def test_blast_radius_multiple_routes() -> None:
    """A sink reachable from 3 untrusted routes has blast_radius == 3."""
    graph = nx.MultiDiGraph()
    nodes = [
        _make_node("api.py::route1"),
        _make_node("api.py::route2"),
        _make_node("api.py::route3"),
        _make_node("common.py::vulnerable_util"),
    ]
    for n in nodes:
        graph.add_node(n.id)

    graph.add_edge(
        "api.py::route1", "common.py::vulnerable_util", key="calls", kind="calls", resolved=True
    )
    graph.add_edge(
        "api.py::route2", "common.py::vulnerable_util", key="calls", kind="calls", resolved=True
    )
    graph.add_edge(
        "api.py::route3", "common.py::vulnerable_util", key="calls", kind="calls", resolved=True
    )

    eps = [
        EntryPoint(node_id="api.py::route1", kind=EntryPointKind.HTTP_ROUTE, trust=Trust.UNTRUSTED),
        EntryPoint(node_id="api.py::route2", kind=EntryPointKind.HTTP_ROUTE, trust=Trust.UNTRUSTED),
        EntryPoint(node_id="api.py::route3", kind=EntryPointKind.HTTP_ROUTE, trust=Trust.UNTRUSTED),
    ]
    graph_res = GraphResult(graph=graph, nodes=nodes, edges=[], entry_points=eps)
    finding = _make_finding("f5", "common.py::vulnerable_util")

    analyze_reachability(graph_res, [finding])

    assert finding.static_evidence is not None
    assert finding.static_evidence.reachable is Reachability.REACHABLE
    assert finding.static_evidence.blast_radius == 3


def test_rank_findings_ordering() -> None:
    """Findings rank by Reachability (REACHABLE > UNKNOWN > UNREACHABLE), blast radius, severity."""
    f_unreachable = _make_finding("f_unreach", "n1", "HIGH")
    g_isolated = nx.DiGraph()
    g_isolated.add_nodes_from(["ep1", "n1"])
    f_unreachable.static_evidence = evaluate_node_reachability(
        ["n1"], {"ep1"}, g_isolated, g_isolated
    )

    f_unknown = _make_finding("f_unk", "n2", "CRITICAL")
    f_unknown.static_evidence = evaluate_node_reachability(
        ["n2"], {"ep1"}, nx.DiGraph(), nx.DiGraph({"ep1": ["n2"]})
    )

    f_reachable_low = _make_finding("f_reach_low", "n3", "LOW")
    f_reachable_low.static_evidence = evaluate_node_reachability(
        ["n3"], {"ep1"}, nx.DiGraph({"ep1": ["n3"]}), nx.DiGraph({"ep1": ["n3"]})
    )

    f_reachable_high_blast = _make_finding("f_reach_high_blast", "n4", "MEDIUM")
    # Reachable from 2 entry points
    g_res = nx.DiGraph({"ep1": ["n4"], "ep2": ["n4"]})
    f_reachable_high_blast.static_evidence = evaluate_node_reachability(
        ["n4"], {"ep1", "ep2"}, g_res, g_res
    )

    findings = [f_unreachable, f_unknown, f_reachable_low, f_reachable_high_blast]
    ranked = rank_findings(findings)

    # Expected order:
    # 1. f_reachable_high_blast (REACHABLE, blast_radius=2)
    # 2. f_reachable_low (REACHABLE, blast_radius=1)
    # 3. f_unknown (UNKNOWN, blast_radius=1)
    # 4. f_unreachable (UNREACHABLE, blast_radius=0)
    assert ranked[0].id == "f_reach_high_blast"
    assert ranked[1].id == "f_reach_low"
    assert ranked[2].id == "f_unk"
    assert ranked[3].id == "f_unreach"


def test_scan_repo_runs_reachability_on_flaskr() -> None:
    """Verify Bandit asserts in test files are UNREACHABLE on flaskr."""
    report = scan_repo(FLASKR)

    assert len(report.findings) > 0
    # Every finding should have static_evidence populated by reachability
    for lf in report.findings:
        assert lf.finding.static_evidence is not None

    # Test file findings (Bandit B101 in tests/test_auth.py) must NOT be REACHABLE from routes
    test_findings = [lf for lf in report.findings if "tests/" in lf.raw.rel_path]
    for tf in test_findings:
        assert tf.finding.static_evidence is not None
        assert tf.finding.static_evidence.reachable is Reachability.UNREACHABLE
