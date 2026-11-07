"""Tests for git diff extraction and classification (Phase 5 Incremental)."""

from __future__ import annotations

from pathlib import Path

from git import Repo
from ravel.incremental.diff import FileChangeKind, get_git_diff


def test_git_diff_non_git_dir(tmp_path: Path) -> None:
    res = get_git_diff(tmp_path)
    assert res == []


def test_git_diff_commits_and_working_tree(tmp_path: Path) -> None:
    repo = Repo.init(tmp_path)
    # Configure user for commits in test repo
    repo.git.config("user.email", "test@ravel.dev")
    repo.git.config("user.name", "Ravel Tester")

    # Commit 1: Initial files
    f1 = tmp_path / "app.py"
    f1.write_text("def hello(): return 'hello'\n", encoding="utf-8")
    f2 = tmp_path / "utils.py"
    f2.write_text("def add(a, b): return a + b\n", encoding="utf-8")
    repo.index.add(["app.py", "utils.py"])
    c1 = repo.index.commit("Initial commit")

    # Commit 2: Modify app.py, add routes.py, delete utils.py
    f1.write_text("def hello(): return 'hello world'\n", encoding="utf-8")
    f3 = tmp_path / "routes.py"
    f3.write_text("def index(): return hello()\n", encoding="utf-8")
    f2.unlink()
    repo.index.remove(["utils.py"])
    repo.index.add(["app.py", "routes.py"])
    c2 = repo.index.commit("Second commit")

    # Test diff between c1 and c2
    diffs = get_git_diff(tmp_path, base_ref=c1.hexsha, target_ref=c2.hexsha)
    diff_map = {d.path: d for d in diffs}
    assert diff_map["app.py"].kind is FileChangeKind.MODIFIED
    assert diff_map["routes.py"].kind is FileChangeKind.ADDED
    assert diff_map["utils.py"].kind is FileChangeKind.DELETED

    # Commit 3: Rename routes.py to api.py
    repo.git.mv("routes.py", "api.py")
    c3 = repo.index.commit("Rename routes to api")

    diffs_rename = get_git_diff(tmp_path, base_ref=c2.hexsha, target_ref=c3.hexsha)
    assert len(diffs_rename) == 1
    rename = diffs_rename[0]
    assert rename.kind is FileChangeKind.RENAMED
    assert rename.path == "api.py"
    assert rename.old_path == "routes.py"

    # Working tree test: modify app.py without committing
    f1.write_text("def hello(): return 'hello from working tree'\n", encoding="utf-8")
    # Untracked file
    untracked = tmp_path / "new_module.py"
    untracked.write_text("x = 1\n", encoding="utf-8")

    wt_diffs = get_git_diff(tmp_path, base_ref=c3.hexsha)
    wt_map = {d.path: d for d in wt_diffs}
    assert wt_map["app.py"].kind is FileChangeKind.MODIFIED
    assert wt_map["new_module.py"].kind is FileChangeKind.ADDED
