"""Scanning a git URL: clone into a cache, check out a ref (Phase 1).

Uses a local repository over ``file://`` so no network is needed.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
from ravel.cli.main import app
from ravel.ingest.remote import fetch_repo, is_remote
from typer.testing import CliRunner

SAMPLE = Path(__file__).parent.parent / "eval" / "fixtures" / "sample_app"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


@pytest.fixture
def origin(tmp_path: Path) -> tuple[str, str, str]:
    """A repo with two commits: the sample app, then one more function."""
    repo = tmp_path / "origin"
    shutil.copytree(SAMPLE, repo)
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "sample app")
    first = _git(repo, "rev-parse", "HEAD")
    (repo / "extra.py").write_text("def added_later():\n    return 1\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "add a function")
    return f"file://{repo}", first, _git(repo, "rev-parse", "HEAD")


@pytest.mark.parametrize(
    ("target", "remote"),
    [
        ("https://github.com/pallets/flask", True),
        ("git@github.com:pallets/flask.git", True),
        ("file:///tmp/repo", True),
        ("eval/fixtures/flaskr", False),
    ],
)
def test_is_remote(target: str, remote: bool) -> None:
    assert is_remote(target) is remote


def test_clones_latest_then_checks_out_an_older_ref(
    origin: tuple[str, str, str], tmp_path: Path
) -> None:
    url, first, latest = origin
    cache = tmp_path / "cache"
    latest_tree = fetch_repo(url, cache=cache)
    assert (latest_tree / "extra.py").is_file()
    assert _git(latest_tree, "rev-parse", "HEAD") == latest

    old_tree = fetch_repo(url, ref=first, cache=cache)  # same cache dir, deepened
    assert old_tree == latest_tree
    assert _git(old_tree, "rev-parse", "HEAD") == first
    assert not (old_tree / "extra.py").exists()


def test_cli_indexes_a_url(origin: tuple[str, str, str], tmp_path: Path) -> None:
    url, _, _ = origin
    result = CliRunner().invoke(
        app, ["index", url], env={"RAVEL_REPO_CACHE": str(tmp_path / "c"), "COLUMNS": "200"}
    )
    assert result.exit_code == 0, result.output
    assert "Resolution coverage" in result.output


def test_ref_without_url_is_refused() -> None:
    result = CliRunner().invoke(app, ["index", str(SAMPLE), "--ref", "main"])
    assert result.exit_code != 0
    assert "--ref only applies to a git URL" in result.output
