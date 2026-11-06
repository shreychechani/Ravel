"""Incremental re-indexing and reachability invalidation.

See PRODUCT.md §8 for the incremental update specification.
"""

from __future__ import annotations

from ravel.incremental.ast_diff import NodeDiffResult, compute_node_diff
from ravel.incremental.diff import FileChange, FileChangeKind, get_git_diff

__all__ = [
    "FileChange",
    "FileChangeKind",
    "NodeDiffResult",
    "compute_node_diff",
    "get_git_diff",
]
