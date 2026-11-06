"""Tests for AST-level function diffing and content hash comparison."""

from __future__ import annotations

from pathlib import Path

from ravel.graph.parse import parse_file
from ravel.incremental.ast_diff import _file_node, compute_node_diff, load_single_source
from ravel.incremental.diff import FileChange, FileChangeKind
from ravel.models import Node


def test_ast_diff_unchanged_and_modified_functions(tmp_path: Path) -> None:
    # 1. Setup initial file with two functions: f_stable and f_changing
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "def f_stable():\n    return 42\n\ndef f_changing():\n    return 'v1'\n",
        encoding="utf-8",
    )
    src_v1 = load_single_source(tmp_path, "app.py")
    assert src_v1 is not None
    initial_nodes: list[Node] = [_file_node(src_v1), *parse_file(src_v1)]
    assert len(initial_nodes) == 3  # file + 2 functions

    # 2. Modify only f_changing, leaving f_stable byte-for-byte identical
    app_py.write_text(
        "def f_stable():\n    return 42\n\ndef f_changing():\n    return 'v2_modified'\n",
        encoding="utf-8",
    )

    changes = [FileChange(path="app.py", kind=FileChangeKind.MODIFIED)]
    diff = compute_node_diff(tmp_path, changes, initial_nodes)

    unchanged_qnames = {n.qualified_name for n in diff.unchanged_nodes}
    modified_qnames = {n.qualified_name for n in diff.modified_nodes}

    # f_stable must be recognized as UNCHANGED by its content hash
    assert "f_stable" in unchanged_qnames
    # f_changing must be recognized as MODIFIED
    assert "f_changing" in modified_qnames
    # app.py file node changed content hash
    assert "app.py" in modified_qnames

    # Dirty node IDs include f_changing but NOT f_stable
    assert any("f_changing" in nid for nid in diff.dirty_node_ids)
    assert not any("f_stable" in nid for nid in diff.dirty_node_ids)


def test_ast_diff_added_and_deleted_files(tmp_path: Path) -> None:
    # Initial state: old.py exists
    old_py = tmp_path / "old.py"
    old_py.write_text("def old_fn(): pass\n", encoding="utf-8")
    src_old = load_single_source(tmp_path, "old.py")
    assert src_old is not None
    initial_nodes = [_file_node(src_old), *parse_file(src_old)]

    # Changes: delete old.py, add new.py
    old_py.unlink()
    new_py = tmp_path / "new.py"
    new_py.write_text("def new_fn(): pass\n", encoding="utf-8")

    changes = [
        FileChange(path="old.py", kind=FileChangeKind.DELETED),
        FileChange(path="new.py", kind=FileChangeKind.ADDED),
    ]

    diff = compute_node_diff(tmp_path, changes, initial_nodes)

    assert any(n.qualified_name == "old_fn" for n in diff.deleted_nodes)
    assert any(n.qualified_name == "new_fn" for n in diff.added_nodes)
    assert len(diff.unchanged_nodes) == 0
