"""Environment discovery — resolution must see the *scanned* repo's deps.

The code under analysis is the real ``flask_app`` fixture, copied next to a
virtualenv-shaped directory. The installed "flask" is a minimal package with
Flask's public shape — a stand-in for ``site-packages``, since real third-party
installs can't live in the repo.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from ravel.graph.environment import discover_env, jedi_sys_path
from ravel.graph.resolve import build_graph

FLASK_FIXTURE = Path(__file__).parent.parent / "eval" / "fixtures" / "flask_app"

_FLASK_STUB = """
class Flask:
    def __init__(self, import_name): ...
    def route(self, rule, **options): ...
    def get(self, rule, **options): ...

class Request:
    form: dict[str, str]

request = Request()
"""


def _make_venv(path: Path, packages: dict[str, str] | None = None) -> Path:
    """A virtualenv on disk: ``pyvenv.cfg`` + ``lib/python3.X/site-packages``."""
    site = path / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (path / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    for name, source in (packages or {}).items():
        (site / name).mkdir()
        (site / name / "__init__.py").write_text(source, encoding="utf-8")
    return site


@pytest.fixture
def flask_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "flask_app"
    shutil.copytree(FLASK_FIXTURE, repo)
    return repo


def test_no_venv_is_stdlib_only(flask_repo: Path) -> None:
    env = discover_env(flask_repo)
    assert not env.found
    assert "--venv" in env.describe()
    # Ravel's own installed packages must never leak into the target's resolution.
    assert not any("site-packages" in p for p in jedi_sys_path(env))


def test_in_repo_venv_is_discovered(flask_repo: Path) -> None:
    site = _make_venv(flask_repo / ".venv")
    env = discover_env(flask_repo)
    assert env.found
    assert env.venv == flask_repo / ".venv"
    assert str(site) in jedi_sys_path(env)


def test_explicit_venv_must_be_a_virtualenv(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="pyvenv.cfg"):
        discover_env(tmp_path, venv=tmp_path)


def test_pth_paths_honoured_but_import_lines_ignored(tmp_path: Path) -> None:
    src = tmp_path / "editable_src"
    src.mkdir()
    site = _make_venv(tmp_path / "venv")
    (site / "__editable__.pkg.pth").write_text(f"{src}\n", encoding="utf-8")
    (site / "hook.pth").write_text("import os; os.system('x')\n# comment\n", encoding="utf-8")

    env = discover_env(tmp_path, venv=tmp_path / "venv")
    assert env.pth_paths == (src.resolve(),)


def test_third_party_calls_resolve_against_the_repo_venv(flask_repo: Path) -> None:
    without = build_graph(flask_repo)
    assert without.coverage.unresolved > 0

    _make_venv(flask_repo / ".venv", {"flask": _FLASK_STUB})
    with_env = build_graph(flask_repo)

    assert with_env.coverage.unresolved == 0
    assert with_env.coverage.internal == without.coverage.internal  # in-repo edges unchanged
    assert {r.package for r in with_env.external_refs} >= {"flask"}
    # The venv is resolved against, never indexed as source.
    assert not any(".venv" in n.file_path for n in with_env.nodes)
