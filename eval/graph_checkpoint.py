"""Phase 1 checkpoint — is the call graph correct? (BUILD-PLAN §1, PRODUCT.md §10)

Scores Ravel's graph for a fixture against a hand-checked ground-truth file:

- every ``[[edge]]`` must be a resolved ``calls`` edge (recall);
- the ``[[edge]]`` list is exhaustive, so any *other* resolved internal edge
  from repo code is a false positive (precision);
- every ``[[no_edge]]`` must be absent, and every ``[[unknown]]`` (or a
  ``no_edge`` with ``unknown = ...``) must survive as ``unknown::<name>``.

The gate passes when every case passes **and** call-site coverage is ≥80%.
Coverage needs the fixture's dependencies, so pass ``--venv``::

    uv run python -m eval.graph_checkpoint --venv /path/to/flaskr-venv
"""

from __future__ import annotations

import argparse
import sys
import tomllib
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ravel.core.logging import configure_logging
from ravel.graph.environment import PythonEnv
from ravel.graph.resolve import Coverage, GraphResult, build_graph
from ravel.models import EdgeKind
from rich.console import Console
from rich.table import Table

HERE = Path(__file__).parent
DEFAULT_FIXTURE = HERE / "fixtures" / "flaskr"
DEFAULT_TRUTH = HERE / "ground_truth" / "flaskr_graph.toml"
COVERAGE_GATE = 0.80

Pair = tuple[str, str]


@dataclass(frozen=True)
class CaseResult:
    kind: str  # "edge" | "no_edge" | "unknown"
    label: str
    passed: bool
    detail: str = ""


@dataclass
class CheckpointReport:
    cases: list[CaseResult]
    truth: set[Pair]  # hand-checked internal edges
    emitted: set[Pair]  # resolved internal calls edges Ravel drew
    coverage: Coverage
    environment: PythonEnv
    unknown_names: list[str] = field(default_factory=list)  # truth names Ravel lacks

    @property
    def true_positives(self) -> set[Pair]:
        return self.truth & self.emitted

    @property
    def false_positives(self) -> set[Pair]:
        return self.emitted - self.truth

    @property
    def precision(self) -> float:
        return len(self.true_positives) / len(self.emitted) if self.emitted else 1.0

    @property
    def recall(self) -> float:
        return len(self.true_positives) / len(self.truth) if self.truth else 1.0

    @property
    def cases_passed(self) -> int:
        return sum(c.passed for c in self.cases)

    @property
    def gate_passed(self) -> bool:
        return (
            not self.unknown_names
            and self.cases_passed == len(self.cases)
            and self.coverage.ratio >= COVERAGE_GATE
        )


def _names(result: GraphResult) -> tuple[dict[str, str], dict[str, set[str]]]:
    """node id → "file::qname", and the reverse (a qname can be redefined)."""
    by_id = {n.id: f"{n.file_path}::{n.qualified_name}" for n in result.nodes}
    by_name: dict[str, set[str]] = defaultdict(set)
    for node_id, name in by_id.items():
        by_name[name].add(node_id)
    return by_id, by_name


def run_checkpoint(
    fixture: Path = DEFAULT_FIXTURE,
    truth_file: Path = DEFAULT_TRUTH,
    venv: Path | None = None,
) -> CheckpointReport:
    truth_doc: dict[str, Any] = tomllib.loads(truth_file.read_text(encoding="utf-8"))
    result = build_graph(fixture, venv=venv)
    by_id, by_name = _names(result)

    calls = [e for e in result.edges if e.kind is EdgeKind.CALLS]
    emitted = {
        (by_id[e.src_id], by_id[e.dst_id])
        for e in calls
        if e.resolved and e.src_id in by_id and e.dst_id in by_id
    }
    unknown_from: dict[str, set[str]] = defaultdict(set)
    for e in calls:
        if not e.resolved and e.src_id in by_id:
            unknown_from[by_id[e.src_id]].add(e.dst_id.removeprefix("unknown::"))

    # A ground-truth name Ravel has no node for is a broken case, not a pass.
    referenced = {
        name
        for kind in ("edge", "no_edge", "unknown")
        for case in truth_doc.get(kind, [])
        for name in (case["src"], case.get("dst"))
        if name is not None
    }
    missing = sorted(n for n in referenced if n not in by_name)

    cases: list[CaseResult] = []
    truth: set[Pair] = set()
    for case in truth_doc.get("edge", []):
        pair = (case["src"], case["dst"])
        truth.add(pair)
        ok = pair in emitted
        cases.append(
            CaseResult("edge", f"{pair[0]} → {pair[1]}", ok, "" if ok else "edge not resolved")
        )

    for case in truth_doc.get("no_edge", []):
        pair = (case["src"], case["dst"])
        ok, detail = pair not in emitted, ""
        if not ok:
            detail = "wrong edge drawn"
        elif "unknown" in case and case["unknown"] not in unknown_from[pair[0]]:
            ok, detail = False, f"call dropped — no unknown::{case['unknown']}"
        cases.append(CaseResult("no_edge", f"{pair[0]} ↛ {pair[1]}", ok, detail))

    for case in truth_doc.get("unknown", []):
        ok = case["name"] in unknown_from[case["src"]]
        cases.append(
            CaseResult(
                "unknown",
                f"{case['src']} → unknown::{case['name']}",
                ok,
                "" if ok else "call dropped or wrongly resolved",
            )
        )

    return CheckpointReport(
        cases=cases,
        truth=truth,
        emitted=emitted,
        coverage=result.coverage,
        environment=result.environment,
        unknown_names=missing,
    )


def render(report: CheckpointReport, console: Console) -> None:
    table = Table(title="Phase 1 graph checkpoint — hand-checked cases")
    table.add_column("kind", style="cyan")
    table.add_column("case")
    table.add_column("result")
    for c in report.cases:
        mark = "[green]pass[/green]" if c.passed else f"[red]FAIL[/red] {c.detail}"
        table.add_row(c.kind, c.label, mark)
    console.print(table)

    for name in report.unknown_names:
        console.print(f"[red]ground truth names a function Ravel has no node for:[/red] {name}")
    for src, dst in sorted(report.false_positives):
        console.print(f"[red]false-positive edge:[/red] {src} → {dst}")

    cov = report.coverage
    summary = Table(title="Checkpoint summary")
    summary.add_column("metric", style="cyan")
    summary.add_column("value", justify="right")
    summary.add_row("Cases passed", f"{report.cases_passed} / {len(report.cases)}")
    # Precision is never reported without recall (PRODUCT.md §6).
    summary.add_row("Edge precision", f"{report.precision:.1%}")
    summary.add_row("Edge recall", f"{report.recall:.1%}")
    summary.add_row(
        "Call-site coverage", f"{cov.ratio:.1%} ({cov.resolved}/{cov.total}, gate ≥80%)"
    )
    summary.add_row("Python env", report.environment.describe())
    verdict = "[green]PASS[/green]" if report.gate_passed else "[red]FAIL[/red]"
    summary.add_row("Gate", verdict)
    console.print(summary)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--truth", type=Path, default=DEFAULT_TRUTH)
    parser.add_argument("--venv", type=Path, default=None, help="the fixture's virtualenv")
    args = parser.parse_args(argv)

    configure_logging()
    report = run_checkpoint(args.fixture, args.truth, args.venv)
    render(report, Console())
    return 0 if report.gate_passed else 1


if __name__ == "__main__":
    sys.exit(main())
