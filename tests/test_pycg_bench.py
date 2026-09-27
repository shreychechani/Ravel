"""PyCG micro-benchmark as a regression floor (research/07 items 1.1, 1.2).

Not a target to tune against — a ratchet: the published ground truth must not
get *worse*. The floors are the scores measured on 2026-09-27; raise them when
the resolver improves, never lower them to make a change pass.
"""

from __future__ import annotations

import pytest
from eval.pycg_bench import CaseScore, Totals, run_bench

# Measured 2026-09-27 (`uv run python -m eval.pycg_bench`): precision 98.3%,
# recall 71.2%, 16 silent misses, 73/119 exact.
PRECISION_FLOOR = 0.98
RECALL_FLOOR = 0.71
SILENT_CEILING = 16

# Categories Ravel resolves completely today — any miss here is a regression.
PERFECT = {"exceptions", "external", "functions", "imports"}


@pytest.fixture(scope="module")
def scores() -> list[CaseScore]:
    return run_bench()


def _totals(scores: list[CaseScore]) -> Totals:
    t = Totals()
    for s in scores:
        t.add(s)
    return t


def test_benchmark_is_complete(scores: list[CaseScore]) -> None:
    assert len(scores) == 119


def test_precision_and_recall_floors(scores: list[CaseScore]) -> None:
    t = _totals(scores)
    assert t.precision >= PRECISION_FLOOR
    assert t.recall >= RECALL_FLOOR


def test_silent_misses_do_not_grow(scores: list[CaseScore]) -> None:
    # A call that vanishes without an unknown edge is the §6 failure mode.
    assert _totals(scores).misses["silent"] <= SILENT_CEILING


def test_perfect_categories_stay_perfect(scores: list[CaseScore]) -> None:
    broken = [f"{s.category}/{s.name}" for s in scores if s.category in PERFECT and not s.exact]
    assert not broken, broken


def test_decorators_and_raise_are_calls(scores: list[CaseScore]) -> None:
    by_name = {f"{s.category}/{s.name}": s for s in scores}
    assert ("main", "main.dec") in by_name["decorators/call"].emitted
    assert ("main", "main.A.__init__") in by_name["exceptions/raise"].emitted
