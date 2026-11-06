"""Incremental re-indexing and reachability invalidation.

See PRODUCT.md §8 for the incremental update specification.
"""

from __future__ import annotations

from ravel.incremental.ast_diff import NodeDiffResult, compute_node_diff
from ravel.incremental.diff import FileChange, FileChangeKind, get_git_diff
from ravel.incremental.renames import RenameDetectionResult, RenamedNode, detect_node_renames

__all__ = [
    "FileChange",
    "FileChangeKind",
    "NodeDiffResult",
    "RenameDetectionResult",
    "RenamedNode",
    "compute_node_diff",
    "detect_node_renames",
    "get_git_diff",
]
