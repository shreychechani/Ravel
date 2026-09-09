"""Content hashing — the cache-key primitive.

Per PRODUCT.md §6, cache keys are content hashes, never paths or line numbers,
so they survive edits above them and file moves.
"""

from __future__ import annotations

import hashlib


def content_hash(data: str | bytes) -> str:
    """Return the hex SHA-256 of ``data`` (UTF-8 encoded if a str)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()
