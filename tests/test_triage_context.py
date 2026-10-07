"""Tests for graph context assembly and content hashing."""

from pathlib import Path

import networkx as nx
from ravel.graph.resolve import Coverage, GraphResult
from ravel.models import Finding, FindingSource, Node, NodeKind, Reachability, StaticEvidence
from ravel.triage.context import assemble_finding_context


def test_assemble_finding_context(tmp_path: Path) -> None:
    source_file = tmp_path / "app.py"
    source_file.write_text(
        '"""App module docstring."""\n'
        "def entry():\n"
        "    vulnerable_sink(user_param)\n"
        "def vulnerable_sink(val):\n"
        "    eval(val)\n",
        encoding="utf-8",
    )

    f_node = Node(
        id="app.py::<file>",
        kind=NodeKind.FILE,
        qualified_name="app",
        file_path="app.py",
        start_line=1,
        end_line=5,
        source_hash="filehash",
        docstring="App module docstring.",
    )
    sink_node = Node(
        id="app.py::vulnerable_sink::L4",
        kind=NodeKind.FUNCTION,
        qualified_name="vulnerable_sink",
        file_path="app.py",
        start_line=4,
        end_line=5,
        source_hash="sinkhash",
    )
    entry_node = Node(
        id="app.py::entry::L2",
        kind=NodeKind.FUNCTION,
        qualified_name="entry",
        file_path="app.py",
        start_line=2,
        end_line=3,
        source_hash="entryhash",
    )

    g = nx.MultiDiGraph()
    g.add_node(f_node.id)
    g.add_node(entry_node.id)
    g.add_node(sink_node.id)
    g.add_edge(entry_node.id, sink_node.id, key="calls", kind="calls", resolved=True)

    graph_res = GraphResult(
        graph=g,
        nodes=[f_node, entry_node, sink_node],
        edges=[],
        external_refs=[],
        entry_points=[],
        coverage=Coverage(),
    )

    finding = Finding(
        id="find-123",
        source=FindingSource.BANDIT,
        node_id=sink_node.id,
        rule_id="B307",
        raw_severity="HIGH",
        cwe="CWE-78",
        static_evidence=StaticEvidence(
            reachable=Reachability.REACHABLE,
            path=[entry_node.id, sink_node.id],
            blast_radius=1,
        ),
    )

    ctx = assemble_finding_context(finding, graph_res, tmp_path)
    assert ctx.finding_id == "find-123"
    assert ctx.target_node_name == "vulnerable_sink"
    assert "eval(val)" in ctx.target_code
    assert "App module docstring." in ctx.canonical_text
    assert len(ctx.context_hash) == 64  # valid SHA-256 hex string
    assert len(ctx.callers) == 1
    assert "entry" in ctx.callers[0]
