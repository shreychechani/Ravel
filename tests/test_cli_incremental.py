"""Tests for CLI incremental scan with --since (Phase 5 Incremental)."""

from __future__ import annotations

from pathlib import Path

from git import Repo
from ravel.cli.main import app
from typer.testing import CliRunner


def test_cli_scan_since_option(tmp_path: Path) -> None:
    repo = Repo.init(tmp_path)
    repo.git.config("user.email", "test@ravel.dev")
    repo.git.config("user.name", "Ravel Tester")

    # Initial commit
    app_py = tmp_path / "app.py"
    app_py.write_text(
        "def helper():\n    assert True\n\ndef main():\n    return helper()\n",
        encoding="utf-8",
    )
    repo.index.add(["app.py"])
    c1 = repo.index.commit("Initial commit")

    # Commit 2: Add extra.py
    extra_py = tmp_path / "extra.py"
    extra_py.write_text(
        "def extra():\n    return 123\n",
        encoding="utf-8",
    )
    repo.index.add(["extra.py"])
    repo.index.commit("Second commit")

    runner = CliRunner()
    result = runner.invoke(app, ["scan", str(tmp_path), "--since", c1.hexsha])
    assert result.exit_code == 0, result.output
    assert "Incremental Analysis Summary" in result.output
    assert "Paths Reused" in result.output
