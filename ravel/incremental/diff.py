"""Git diff extraction and change classification for incremental updates.

Ported and designed per PRODUCT.md §8 (Incremental update logic).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from git import InvalidGitRepositoryError, NoSuchPathError, Repo

from ravel.core.logging import get_logger

log = get_logger("ravel.incremental.diff")


class FileChangeKind(StrEnum):
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


@dataclass(frozen=True)
class FileChange:
    """A single file change between revisions or between a revision and the working tree."""

    path: str  # Repo-relative path (the new path if renamed)
    kind: FileChangeKind
    old_path: str | None = None  # Populated only if kind is RENAMED


def _to_file_change(diff_item: Any) -> FileChange | None:
    ct = diff_item.change_type
    if ct == "A":
        path = diff_item.b_path or diff_item.a_path
        return FileChange(path=str(path).replace("\\", "/"), kind=FileChangeKind.ADDED)
    if ct == "D":
        path = diff_item.a_path or diff_item.b_path
        return FileChange(path=str(path).replace("\\", "/"), kind=FileChangeKind.DELETED)
    if ct == "R":
        old_p = str(diff_item.a_path).replace("\\", "/")
        new_p = str(diff_item.b_path).replace("\\", "/")
        return FileChange(path=new_p, kind=FileChangeKind.RENAMED, old_path=old_p)
    if ct == "M":
        path = diff_item.b_path or diff_item.a_path
        return FileChange(path=str(path).replace("\\", "/"), kind=FileChangeKind.MODIFIED)
    return None


def get_git_diff(
    repo_root: Path | str,
    base_ref: str | None = None,
    target_ref: str | None = None,
) -> list[FileChange]:
    """Inspect git changes between base_ref and target_ref (or working tree).

    Args:
        repo_root: Root directory of the git repository.
        base_ref: Base git commit, branch, or tag (e.g., 'HEAD~1' or 'main').
                  If None, defaults to 'HEAD'.
        target_ref: Target git commit, branch, or tag.
                    If None, compares base_ref against the active working tree.

    Returns:
        List of classified FileChange records.
    """
    root = Path(repo_root).resolve()
    try:
        repo = Repo(root)
    except (NoSuchPathError, InvalidGitRepositoryError) as exc:
        log.warning("not a git repository: %s (%s)", root, exc)
        return []

    changes: dict[str, FileChange] = {}

    if target_ref is not None:
        # Diffing two explicit commits/references
        base_commit = repo.commit(base_ref or "HEAD")
        target_commit = repo.commit(target_ref)
        diff_index = base_commit.diff(target_commit)
        for d in diff_index:
            change = _to_file_change(d)
            if change:
                changes[change.path] = change
    else:
        # Diffing base_ref against working tree (staged + unstaged + untracked)
        base = base_ref or "HEAD"
        try:
            base_commit = repo.commit(base)
            diff_index = base_commit.diff(None)  # Diff base against working tree
            for d in diff_index:
                change = _to_file_change(d)
                if change:
                    changes[change.path] = change
        except Exception as exc:
            log.debug("could not resolve base commit %s: %s", base, exc)

        # Untracked files are considered ADDED
        for untracked in repo.untracked_files:
            p = str(untracked).replace("\\", "/")
            changes[p] = FileChange(path=p, kind=FileChangeKind.ADDED)

    return sorted(changes.values(), key=lambda c: c.path)
