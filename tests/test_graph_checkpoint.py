"""Phase 1 checkpoint as a regression test (BUILD-PLAN §1).

Runs the hand-checked flaskr ground truth (``eval/ground_truth/flaskr_graph.toml``)
and requires every case to pass at 100% edge precision *and* recall.

The call-site **coverage** half of the gate needs Flask installed in the
fixture's environment, which CI can't fetch — run it with a real venv::

    uv run python -m eval.graph_checkpoint --venv /path/to/venv-with-flask-and-pytest

Here the fixture's environment gets only the real ``pytest`` package (linked
from Ravel's dev env): Jedi needs it to follow ``@pytest.fixture`` injection.
"""

from __future__ import annotations

from pathlib import Path

import _pytest
import pluggy
import pytest
from eval.graph_checkpoint import run_checkpoint


@pytest.fixture(scope="module")
def pytest_venv(tmp_path_factory: pytest.TempPathFactory) -> Path:
    venv = tmp_path_factory.mktemp("flaskr-venv")
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    for module in (pytest, _pytest, pluggy):
        assert module.__file__ is not None
        src = Path(module.__file__)
        pkg = src.parent if src.name == "__init__.py" else src
        (site / pkg.name).symlink_to(pkg)
    return venv


def test_every_hand_checked_case_passes(pytest_venv: Path) -> None:
    report = run_checkpoint(venv=pytest_venv)
    assert not report.unknown_names, report.unknown_names
    failed = [f"{c.label}: {c.detail}" for c in report.cases if not c.passed]
    assert not failed, failed
    assert len(report.cases) >= 20  # the checkpoint's minimum sample


def test_edge_precision_and_recall_are_exact(pytest_venv: Path) -> None:
    report = run_checkpoint(venv=pytest_venv)
    assert report.false_positives == set()
    assert report.precision == 1.0
    assert report.recall == 1.0


def test_calls_through_parameters_stay_unknown() -> None:
    # Regression: `view(**kwargs)` in login_required once resolved to the
    # enclosing decorator, because goto stops at the parameter's binding.
    report = run_checkpoint()
    case = next(c for c in report.cases if c.label.endswith("unknown::view"))
    assert case.passed
    assert not any(src.endswith("wrapped_view") for src, _ in report.emitted)
