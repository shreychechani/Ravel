"""AST-level function and class diffing with content hash comparison.

Per PRODUCT.md §8:
- Re-parse only changed files.
- Unchanged hash -> retain node state, summaries, and triage verdicts.
- Changed hash -> mark dirty for edge rebuilding and reachability invalidation.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.hashing import content_hash
from ravel.core.logging import get_logger
from ravel.graph.parse import parse_file
from ravel.incremental.diff import FileChange, FileChangeKind
from ravel.ingest.loader import PYTHON_SUFFIXES, SourceFile
from ravel.models import Node, NodeKind

log = get_logger("ravel.incremental.ast_diff")


def _file_node(source: SourceFile) -> Node:
    return Node(
        id=source.rel_path,
        kind=NodeKind.FILE,
        qualified_name=source.rel_path,
        file_path=source.rel_path,
        start_line=1,
        end_line=source.lines,
        source_hash=source.content_hash,
    )


def load_single_source(root: Path, rel_path: str) -> SourceFile | None:
    path = root / rel_path
    if not path.is_file() or path.suffix.lower() not in PYTHON_SUFFIXES:
        return None
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return SourceFile(
        path=path,
        rel_path=rel_path.replace("\\", "/"),
        content=content,
        content_hash=content_hash(content),
        lines=content.count("\n") + 1 if content else 0,
    )


@dataclass
class NodeDiffResult:
    """Classified diff of AST nodes between two versions."""

    unchanged_nodes: list[Node] = field(default_factory=list)
    modified_nodes: list[Node] = field(default_factory=list)
    added_nodes: list[Node] = field(default_factory=list)
    deleted_nodes: list[Node] = field(default_factory=list)
    dirty_node_ids: set[str] = field(default_factory=set)

    @property
    def total_changed(self) -> int:
        return len(self.modified_nodes) + len(self.added_nodes) + len(self.deleted_nodes)


def compute_node_diff(
    repo_root: Path | str,
    file_changes: list[FileChange],
    previous_nodes: list[Node],
) -> NodeDiffResult:
    """Compute AST-level differences by comparing node source hashes."""
    root = Path(repo_root).resolve()
    result = NodeDiffResult()

    # Index previous nodes by file
    prev_by_file: dict[str, list[Node]] = defaultdict(list)
    for n in previous_nodes:
        prev_by_file[n.file_path].append(n)

    # Index changes by normalized relative path
    change_by_path = {c.path.replace("\\", "/"): c for c in file_changes}

    # 1. Process files that were completely untouched
    for file_path, nodes in prev_by_file.items():
        if file_path not in change_by_path:
            result.unchanged_nodes.extend(nodes)

    # 2. Process changed files
    for change in file_changes:
        rel_path = change.path.replace("\\", "/")
        prev_nodes = prev_by_file.get(rel_path, [])
        if change.old_path:
            # In case of rename, check previous nodes under old path too
            prev_nodes = prev_nodes or prev_by_file.get(change.old_path.replace("\\", "/"), [])

        if change.kind is FileChangeKind.DELETED:
            for n in prev_nodes:
                result.deleted_nodes.append(n)
                result.dirty_node_ids.add(n.id)
            continue

        source = load_single_source(root, rel_path)
        if source is None:
            # Not a python file or unreadable, mark previous nodes deleted
            for n in prev_nodes:
                result.deleted_nodes.append(n)
                result.dirty_node_ids.add(n.id)
            continue

        new_file_node = _file_node(source)
        new_def_nodes = parse_file(source)
        new_nodes = [new_file_node, *new_def_nodes]

        if change.kind is FileChangeKind.ADDED:
            for n in new_nodes:
                result.added_nodes.append(n)
                result.dirty_node_ids.add(n.id)
            continue

        # FileChangeKind.MODIFIED or FileChangeKind.RENAMED
        old_nodes_by_qname = {n.qualified_name: n for n in prev_nodes}
        seen_old_qnames: set[str] = set()

        for new_node in new_nodes:
            old_node = old_nodes_by_qname.get(new_node.qualified_name)
            if old_node is None:
                # Brand new function/class in this file
                result.added_nodes.append(new_node)
                result.dirty_node_ids.add(new_node.id)
            else:
                seen_old_qnames.add(new_node.qualified_name)
                if new_node.source_hash == old_node.source_hash:
                    # Content hash is identical! Keep it unchanged
                    result.unchanged_nodes.append(new_node)
                else:
                    # Content hash differs: modified
                    result.modified_nodes.append(new_node)
                    result.dirty_node_ids.add(new_node.id)
                    result.dirty_node_ids.add(old_node.id)

        # Old nodes that no longer exist in the file
        for old_qname, old_node in old_nodes_by_qname.items():
            if old_qname not in seen_old_qnames:
                result.deleted_nodes.append(old_node)
                result.dirty_node_ids.add(old_node.id)

    return result
