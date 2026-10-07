"""Remote repositories: clone once into a local cache, then scan the copy.

``ravel scan https://github.com/owner/repo`` is the one place Ravel reaches the
network on its own, and only because the user passed a URL. It clones with
GitPython into ``$RAVEL_REPO_CACHE`` (default ``~/.cache/ravel/repos``), never
pushes, and never touches the remote again unless asked for a ref the copy
does not have. Everything after the clone is the same local, read-only scan.

The cache directory is keyed by a hash of the URL, so two forks with the same
name do not collide. Without ``--ref`` the clone is shallow (latest commit);
a ref needs history, so the copy is deepened first.
"""

from __future__ import annotations

import os
from pathlib import Path

from git import GitCommandError, Repo

from ravel.core.hashing import content_hash
from ravel.core.logging import get_logger

log = get_logger("ravel.ingest.remote")

_REMOTE_PREFIXES = ("https://", "http://", "ssh://", "git://", "git@", "file://")


def is_remote(target: str) -> bool:
    return target.startswith(_REMOTE_PREFIXES)


def repo_cache() -> Path:
    return Path(os.environ.get("RAVEL_REPO_CACHE", "~/.cache/ravel/repos")).expanduser()


def _dest(url: str, cache: Path) -> Path:
    name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git") or "repo"
    return cache / f"{name}-{content_hash(url)[:12]}"


def fetch_repo(url: str, ref: str | None = None, cache: Path | None = None) -> Path:
    """Local path of ``url``'s working tree, at ``ref`` if given."""
    dest = _dest(url, cache or repo_cache())
    if not (dest / ".git").is_dir():
        dest.parent.mkdir(parents=True, exist_ok=True)
        log.info("cloning %s into %s", url, dest)
        if ref is None:
            Repo.clone_from(url, dest, depth=1)
        else:
            Repo.clone_from(url, dest)
    repo = Repo(dest)
    if ref is not None:
        try:
            repo.git.checkout(ref)
        except GitCommandError:
            log.info("ref %s not in the local copy; fetching history", ref)
            if (dest / ".git" / "shallow").exists():
                repo.git.fetch("--unshallow")
            repo.git.fetch("origin", ref)
            repo.git.checkout(ref)
    log.info("scanning %s at %s", url, repo.head.commit.hexsha[:12])
    return dest
