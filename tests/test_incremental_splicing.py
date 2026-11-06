"""Tests for incremental graph splicing and edge reconstruction."""

from __future__ import annotations

from pathlib import Path

from ravel.graph.resolve import build_graph
from ravel.incremental.ast_diff import compute_node_diff
from ravel.incremental.diff import FileChange, FileChangeKind
from ravel.incremental.splicing import splice_graph
from ravel.models import EdgeKind


def test_splice_graph_preserves_untouched_edges_and_updates_dirty(tmp_path: Path) -> None:
    # 1. Initial repo setup
    f_routes = tmp_path / "routes.py"
    f_routes.write_text(
        "from services import get_data\n\ndef route_handler():\n    return get_data()\n",
        encoding="utf-8",
    )
    f_services = tmp_path / "services.py"
    f_services.write_text(
        "def get_data():\n    return {'status': 'ok'}\n",
        encoding="utf-8",
    )

    initial_graph = build_graph(tmp_path)
    assert len(initial_graph.nodes) >= 4  # 2 files + 2 functions

    # 2. Add extra.py which calls get_data()
    f_extra = tmp_path / "extra.py"
    f_extra.write_text(
        "from services import get_data\n\ndef extra_worker():\n    return get_data()\n",
        encoding="utf-8",
    )

    changes = [FileChange(path="extra.py", kind=FileChangeKind.ADDED)]
    diff = compute_node_diff(tmp_path, changes, initial_graph.nodes)

    spliced = splice_graph(tmp_path, initial_graph, diff)

    # Verify nodes
    node_qnames = {n.qualified_name for n in spliced.nodes}
    assert "route_handler" in node_qnames
    assert "get_data" in node_qnames
    assert "extra_worker" in node_qnames

    # Verify both routes.py and extra.py have calls edges to get_data
    calls_edges = [e for e in spliced.edges if e.kind is EdgeKind.CALLS]
    assert len(calls_edges) >= 2


def test_splice_graph_remaps_renamed_nodes(tmp_path: Path) -> None:
    # 1. Initial repo setup: caller -> target in a package
    (tmp_path / "__init__.py").touch()
    f_a = tmp_path / "a.py"
    f_a.write_text(
        "from .b import target_worker\ndef caller():\n    return target_worker()\n",
        encoding="utf-8",
    )
    f_b = tmp_path / "b.py"
    f_b.write_text(
        "def target_worker():\n    return 100\n",
        encoding="utf-8",
    )
    g1 = build_graph(tmp_path)

    # 2. Move b.py to c.py (target_worker has identical source_hash)
    f_b.unlink()
    f_c = tmp_path / "c.py"
    f_c.write_text(
        "def target_worker():\n    return 100\n",
        encoding="utf-8",
    )

    changes = [
        FileChange(path="b.py", kind=FileChangeKind.DELETED),
        FileChange(path="c.py", kind=FileChangeKind.ADDED),
    ]
    diff = compute_node_diff(tmp_path, changes, g1.nodes)
    assert len(diff.renamed_nodes) == 1

    spliced = splice_graph(tmp_path, g1, diff)

    # The caller edge from a.py should now have its dst_id remapped to c.py
    calls_to_target = [
        e for e in spliced.edges if e.kind is EdgeKind.CALLS and "target_worker" in e.dst_id
    ]
    assert len(calls_to_target) >= 1
    assert any("c.py" in e.dst_id for e in calls_to_target)
