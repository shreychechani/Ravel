"""Discover Python source files in a repository.

File-type filtering is informed by reference/Arcflow/js/analysis/parser-core.js
(codeExts / skip lists), ported and trimmed to Python-only for v1.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ravel.core.hashing import content_hash

PYTHON_SUFFIXES = {".py", ".pyw", ".pyi"}

# Directories we never descend into.
SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    ".tox",
    "site-packages",
    ".idea",
    ".vscode",
    ".eggs",
}


@dataclass(frozen=True)
class SourceFile:
    """A single source file, with its content already hashed."""

    path: Path  # absolute
    rel_path: str  # POSIX, relative to the repo root
    content: str
    content_hash: str
    lines: int


def discover(root: Path | str) -> list[SourceFile]:
    """Walk ``root`` and return every Python source file (skip lists applied)."""
    root = Path(root).resolve()
    files: list[SourceFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place so we don't descend into them.
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            path = Path(dirpath) / filename
            if path.suffix.lower() not in PYTHON_SUFFIXES:
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files.append(
                SourceFile(
                    path=path,
                    rel_path=path.relative_to(root).as_posix(),
                    content=content,
                    content_hash=content_hash(content),
                    lines=content.count("\n") + 1 if content else 0,
                )
            )
    files.sort(key=lambda f: f.rel_path)
    return files
