"""Tests for function and class rename detection by content hash."""

from __future__ import annotations

from pathlib import Path

from ravel.graph.parse import parse_file
from ravel.incremental.ast_diff import _file_node, compute_node_diff, load_single_source
from ravel.incremental.diff import FileChange, FileChangeKind
from ravel.incremental.renames import detect_node_renames
from ravel.models import Node


def test_rename_file_preserves_function_nodes(tmp_path: Path) -> None:
    # Version 1: module_old.py has 2 functions
    f_old = tmp_path / "module_old.py"
    f_old.write_text(
        "def process_order(order_id):\n"
        "    return f'processed {order_id}'\n"
        "\n"
        "def validate_order(order):\n"
        "    return bool(order)\n",
        encoding="utf-8",
    )
    src_old = load_single_source(tmp_path, "module_old.py")
    assert src_old is not None
    v1_nodes: list[Node] = [_file_node(src_old), *parse_file(src_old)]

    # Version 2: module_old.py renamed to module_new.py (delete + add in git diff)
    f_old.unlink()
    f_new = tmp_path / "module_new.py"
    f_new.write_text(
        "def process_order(order_id):\n"
        "    return f'processed {order_id}'\n"
        "\n"
        "def validate_order(order):\n"
        "    return bool(order)\n",
        encoding="utf-8",
    )

    changes = [
        FileChange(path="module_old.py", kind=FileChangeKind.DELETED),
        FileChange(path="module_new.py", kind=FileChangeKind.ADDED),
    ]

    diff = compute_node_diff(tmp_path, changes, v1_nodes)

    # Both functions must be matched by content hash across the diff
    assert len(diff.renamed_nodes) == 2
    renamed_qnames = {r.new_node.qualified_name for r in diff.renamed_nodes}
    assert "process_order" in renamed_qnames
    assert "validate_order" in renamed_qnames

    # Check mapping
    for ren in diff.renamed_nodes:
        assert ren.old_node.id in diff.rename_map
        assert diff.rename_map[ren.old_node.id] == ren.new_node.id

    # No phantom deleted functions
    assert not any(n.qualified_name == "process_order" for n in diff.deleted_nodes)
    assert not any(n.qualified_name == "validate_order" for n in diff.deleted_nodes)


def test_move_function_across_files(tmp_path: Path) -> None:
    f_orig = tmp_path / "origin.py"
    f_orig.write_text("def shared_worker():\n    return [1, 2, 3]\n", encoding="utf-8")
    src_orig = load_single_source(tmp_path, "origin.py")
    assert src_orig is not None
    v1_nodes: list[Node] = [_file_node(src_orig), *parse_file(src_orig)]

    # Version 2: Function removed from origin.py, added to dest.py
    f_orig.write_text("# empty now\n", encoding="utf-8")
    f_dest = tmp_path / "dest.py"
    f_dest.write_text("def shared_worker():\n    return [1, 2, 3]\n", encoding="utf-8")

    changes = [
        FileChange(path="origin.py", kind=FileChangeKind.MODIFIED),
        FileChange(path="dest.py", kind=FileChangeKind.ADDED),
    ]

    diff = compute_node_diff(tmp_path, changes, v1_nodes)

    assert len(diff.renamed_nodes) == 1
    assert diff.renamed_nodes[0].old_node.file_path == "origin.py"
    assert diff.renamed_nodes[0].new_node.file_path == "dest.py"
    assert diff.renamed_nodes[0].new_node.qualified_name == "shared_worker"


def test_standalone_detect_node_renames() -> None:
    old_fn = Node(
        id="old::f::L1",
        kind="function",  # type: ignore[arg-type]
        qualified_name="f_old",
        file_path="a.py",
        start_line=1,
        end_line=2,
        source_hash="hash1234",
    )
    new_fn = Node(
        id="new::f::L5",
        kind="function",  # type: ignore[arg-type]
        qualified_name="f_new",
        file_path="b.py",
        start_line=5,
        end_line=6,
        source_hash="hash1234",
    )
    deleted, added, res = detect_node_renames([old_fn], [new_fn])
    assert len(deleted) == 0
    assert len(added) == 0
    assert len(res.renamed_nodes) == 1
    assert res.rename_map["old::f::L1"] == "new::f::L5"
