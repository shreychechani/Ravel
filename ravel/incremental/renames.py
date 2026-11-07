"""Function and class rename detection by content hash.

Per PRODUCT.md §8:
"Known trap — renames: a rename looks like delete + add. Detect renames by
matching content hash across the diff, or you get dangling edges plus a phantom
node the dead-code check will happily flag."
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ravel.core.logging import get_logger
from ravel.models import Node, NodeKind

log = get_logger("ravel.incremental.renames")


@dataclass(frozen=True)
class RenamedNode:
    """A node that was moved or renamed between revisions."""

    old_node: Node
    new_node: Node


@dataclass
class RenameDetectionResult:
    """Outcome of matching deleted nodes against added nodes by source hash."""

    renamed_nodes: list[RenamedNode] = field(default_factory=list)
    rename_map: dict[str, str] = field(default_factory=dict)  # old_node.id -> new_node.id


def detect_node_renames(
    deleted_nodes: list[Node],
    added_nodes: list[Node],
) -> tuple[list[Node], list[Node], RenameDetectionResult]:
    """Match deleted nodes with added nodes having the identical content hash.

    Matches 1-to-1. If multiple candidates share a hash, prefers candidates
    in the same file or with the same qualified name.

    Returns:
        (remaining_deleted, remaining_added, rename_result)
    """
    result = RenameDetectionResult()
    if not deleted_nodes or not added_nodes:
        return deleted_nodes, added_nodes, result

    # Index added def nodes by source_hash (skip FILE nodes for symbol rename)
    added_by_hash: dict[str, list[Node]] = defaultdict(list)
    for n in added_nodes:
        if n.kind is not NodeKind.FILE:
            added_by_hash[n.source_hash].append(n)

    remaining_deleted: list[Node] = []
    matched_added_ids: set[str] = set()

    for old_node in deleted_nodes:
        if old_node.kind is NodeKind.FILE:
            remaining_deleted.append(old_node)
            continue

        candidates = [
            c for c in added_by_hash.get(old_node.source_hash, []) if c.id not in matched_added_ids
        ]
        if not candidates:
            remaining_deleted.append(old_node)
            continue

        # Preference: same file path, then same qualified name, then first available
        best_match = next(
            (c for c in candidates if c.file_path == old_node.file_path),
            next(
                (c for c in candidates if c.qualified_name == old_node.qualified_name),
                candidates[0],
            ),
        )

        matched_added_ids.add(best_match.id)
        result.renamed_nodes.append(RenamedNode(old_node=old_node, new_node=best_match))
        result.rename_map[old_node.id] = best_match.id
        log.info(
            "detected rename by content hash: %s -> %s (hash %s)",
            old_node.id,
            best_match.id,
            old_node.source_hash[:8],
        )

    remaining_added = [n for n in added_nodes if n.id not in matched_added_ids]
    return remaining_deleted, remaining_added, result
