"""Call-graph recall against a dynamic oracle (research/07 item 1.4; Sui et al., ICSE '20).

Call-site coverage only grades the call sites Ravel *saw*. It can't reveal an
edge that never surfaced as a call site at all. So: run the fixture's own test
suite, record every repo-internal call that actually happened
(``eval/oracle/trace_calls.py``), and report what share of those the static
graph recovered.

Dynamic oracles under-approximate — only exercised paths show up — so this
measures **recall only, never precision**. Each observed call the static graph
lacks is classified like the PyCG scorer: ``unknown`` (the caller has an
``unknown`` edge, so Ravel flagged uncertainty there) or ``silent`` (no trace
of it in the static graph — the PRODUCT.md §6 failure mode).

    uv run python -m eval.dynamic_recall --venv <venv with flask + pytest>

**Eval-only**: this runs the fixture's tests, on a throwaway copy. Ravel itself
never executes scanned code.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.logging import configure_logging
from ravel.graph.resolve import build_graph
from ravel.models import EdgeKind, NodeKind
from rich.console import Console
from rich.table import Table

from eval.pycg_bench import _c3

HERE = Path(__file__).parent
DEFAULT_FIXTURE = HERE / "fixtures" / "flaskr"
TRACER = HERE / "oracle" / "trace_calls.py"

Pair = tuple[str, str]


@dataclass
class RecallReport:
    observed: set[Pair]
    recovered: set[Pair]
    misses: dict[Pair, str] = field(default_factory=dict)  # "unknown" | "silent"
    tests_exit: int = 0

    @property
    def recall(self) -> float:
        return len(self.recovered) / len(self.observed) if self.observed else 1.0

    def count(self, kind: str) -> int:
        return sum(1 for k in self.misses.values() if k == kind)


def trace(fixture: Path, venv: Path) -> tuple[set[Pair], int]:
    """Run the fixture's tests under the call tracer, on a throwaway copy."""
    python = venv / "bin" / "python"
    with tempfile.TemporaryDirectory(prefix="ravel-oracle-") as tmp:
        work = Path(tmp).resolve() / fixture.name
        shutil.copytree(fixture, work)
        out = Path(tmp) / "pairs.json"
        env = {**os.environ, "PYTHONPATH": str(work), "PYTHONDONTWRITEBYTECODE": "1"}
        subprocess.run(
            [str(python), str(TRACER), str(work), str(out)],
            cwd=work,
            env=env,
            check=True,
            capture_output=True,
        )
        data = json.loads(out.read_text(encoding="utf-8"))
    return {(a, b) for a, b in data["pairs"]}, int(data["exit"])


def score(fixture: Path, observed: set[Pair], venv: Path | None) -> RecallReport:
    result = build_graph(fixture, venv=venv)
    by_id = {
        n.id: f"{n.file_path}::<file>"
        if n.kind is NodeKind.FILE
        else f"{n.file_path}::{n.qualified_name}"
        for n in result.nodes
    }
    kinds = {by_id[n.id]: n.kind for n in result.nodes}

    parents: dict[str, list[str]] = defaultdict(list)
    static: set[Pair] = set()
    has_unknown: set[str] = set()
    for e in result.edges:
        if e.kind is EdgeKind.INHERITS and e.resolved and e.dst_id in by_id:
            parents[by_id[e.src_id]].append(by_id[e.dst_id])
        elif e.kind is EdgeKind.CALLS and e.src_id in by_id:
            if not e.resolved:
                has_unknown.add(by_id[e.src_id])
            elif e.dst_id in by_id:
                static.add((by_id[e.src_id], by_id[e.dst_id]))

    # A static edge to a class stands for the constructor it runs (C3 order).
    for src, dst in list(static):
        if kinds.get(dst) is NodeKind.CLASS:
            init = next(
                (f"{c}.__init__" for c in _c3(dst, parents) if f"{c}.__init__" in kinds), None
            )
            if init is not None:
                static.add((src, init))

    report = RecallReport(observed=observed, recovered=observed & static)
    for pair in sorted(observed - static):
        report.misses[pair] = "unknown" if pair[0] in has_unknown else "silent"
    return report


def render(report: RecallReport, console: Console, show_misses: bool) -> None:
    table = Table(title="Dynamic-oracle recall — calls observed while running the test suite")
    table.add_column("metric", style="cyan")
    table.add_column("value", justify="right")
    table.add_row("Observed repo-internal calls", str(len(report.observed)))
    table.add_row("Recovered by static graph", str(len(report.recovered)))
    table.add_row("Recall", f"{report.recall:.1%}")
    table.add_row("  missed, caller flagged unknown", str(report.count("unknown")))
    silent = report.count("silent")
    table.add_row("  missed silently", f"[red]{silent}[/red]" if silent else "0")
    table.add_row("Fixture test-suite exit code", str(report.tests_exit))
    console.print(table)
    if show_misses:
        for (caller, callee), kind in report.misses.items():
            console.print(f"miss ({kind}): {caller} → {callee}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static call-graph recall vs. a dynamic oracle.")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--venv", type=Path, required=True, help="the fixture's virtualenv")
    parser.add_argument("--show-misses", action="store_true")
    args = parser.parse_args(argv)

    configure_logging()
    logging.getLogger("ravel.graph.resolve").setLevel(logging.WARNING)
    fixture = args.fixture.resolve()
    observed, exit_code = trace(fixture, args.venv.resolve())
    report = score(fixture, observed, args.venv.resolve())
    report.tests_exit = exit_code
    render(report, Console(), args.show_misses)
    return 0


if __name__ == "__main__":
    sys.exit(main())
