"""Score Ravel's call graph on the PyCG micro-benchmark (research/07 items 1.1, 1.2).

The hand-checked flaskr checkpoint is our own answer key; this is a published
one (PyCG, ICSE '21): 119 small programs in 18 categories, each with a
complete ground-truth call graph. That makes Ravel's resolver quality an
externally checkable number, split by category, so it's clear where Jedi
falls short.

**Scope.** Ravel draws ``calls`` edges only between in-repo nodes (builtins and
third-party callees become ``ExternalRef``s), so only truth edges whose callee
is in-repo are scored. Name mapping:

- a Ravel function/class ``qualified_name`` → ``<module>.<qualified_name>``;
  module-level code (Ravel's FILE node) → ``<module>``;
- Ravel links ``Cls()`` to the class node; PyCG to the ``__init__`` it runs —
  found here by walking Ravel's own ``inherits`` edges in C3 (MRO) order — and
  to nothing if no class in the MRO defines one.

**Every missed truth edge is classified** (PRODUCT.md §6):

- ``no_node``  — the callee is something Ravel doesn't model as a node
  (e.g. PyCG's ``main.<lambda1>``);
- ``unknown``  — the caller has at least one ``unknown`` call edge, so the
  miss may be one of them: honest, if imprecise;
- ``silent``   — the caller has **no** ``unknown`` edge: the call vanished
  without a trace, which §6 forbids. These are the misses to fix first.

``unknown`` is attributed per caller, not per call site (PyCG's truth has no
line numbers), so it is an optimistic label: it can hide a silent miss in a
caller that also has some unrelated unknown call.

    uv run python -m eval.pycg_bench [--show-misses]
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.logging import configure_logging
from ravel.graph.resolve import GraphResult, build_graph
from ravel.models import EdgeKind, NodeKind
from rich.console import Console
from rich.table import Table

SNIPPETS = Path(__file__).parent / "benchmarks" / "pycg" / "snippets"

Pair = tuple[str, str]
MISS_KINDS = ("no_node", "unknown", "silent")


@dataclass
class CaseScore:
    category: str
    name: str
    truth: set[Pair]
    emitted: set[Pair]
    misses: dict[Pair, str] = field(default_factory=dict)  # pair → MISS_KINDS entry

    @property
    def tp(self) -> int:
        return len(self.truth & self.emitted)

    @property
    def false_positives(self) -> set[Pair]:
        return self.emitted - self.truth

    @property
    def exact(self) -> bool:
        return self.truth == self.emitted


@dataclass
class Totals:
    cases: int = 0
    exact: int = 0
    tp: int = 0
    emitted: int = 0
    truth: int = 0
    misses: dict[str, int] = field(default_factory=lambda: dict.fromkeys(MISS_KINDS, 0))

    def add(self, score: CaseScore) -> None:
        self.cases += 1
        self.exact += score.exact
        self.tp += score.tp
        self.emitted += len(score.emitted)
        self.truth += len(score.truth)
        for kind in score.misses.values():
            self.misses[kind] += 1

    @property
    def precision(self) -> float:
        return self.tp / self.emitted if self.emitted else 1.0

    @property
    def recall(self) -> float:
        return self.tp / self.truth if self.truth else 1.0


def _pycg_names(result: GraphResult) -> dict[str, str]:
    """Ravel node id → PyCG-style module-qualified name."""
    module_of = {n.file_path: n.qualified_name for n in result.nodes if n.kind is NodeKind.FILE}
    out: dict[str, str] = {}
    for n in result.nodes:
        if n.kind is NodeKind.FILE:
            out[n.id] = n.qualified_name
        else:
            out[n.id] = f"{module_of[n.file_path]}.{n.qualified_name}"
    return out


def _c3(cls: str, parents: dict[str, list[str]]) -> list[str]:
    """Python's C3 method resolution order over in-repo ``inherits`` edges."""
    seqs = [_c3(p, parents) for p in parents.get(cls, [])] + [list(parents.get(cls, []))]
    out = [cls]
    while any(seqs):
        seqs = [s for s in seqs if s]
        head = next((s[0] for s in seqs if not any(s[0] in other[1:] for other in seqs)), None)
        if head is None:  # inconsistent hierarchy — Python would raise; stop here
            break
        out.append(head)
        seqs = [s[1:] if s[0] == head else s for s in seqs]
    return out


def score_case(case_dir: Path) -> CaseScore:
    truth_graph: dict[str, list[str]] = json.loads(
        (case_dir / "callgraph.json").read_text(encoding="utf-8")
    )
    result = build_graph(case_dir)
    names = _pycg_names(result)
    known = set(names.values())
    modules = {n.qualified_name for n in result.nodes if n.kind is NodeKind.FILE}
    kinds = {n.id: n.kind for n in result.nodes}

    parents: dict[str, list[str]] = defaultdict(list)  # edges keep base order
    for e in result.edges:
        if e.kind is EdgeKind.INHERITS and e.resolved and e.dst_id in names:
            parents[names[e.src_id]].append(names[e.dst_id])

    emitted: set[Pair] = set()
    has_unknown: set[str] = set()
    for e in result.edges:
        if e.kind is not EdgeKind.CALLS or e.src_id not in names:
            continue
        if not e.resolved:
            has_unknown.add(names[e.src_id])
            continue
        if e.dst_id not in names:
            continue
        dst = names[e.dst_id]
        if kinds[e.dst_id] is NodeKind.CLASS:
            # Constructor call: PyCG names the __init__ it runs, or nothing.
            init = next(
                (f"{c}.__init__" for c in _c3(dst, parents) if f"{c}.__init__" in known), None
            )
            if init is None:
                continue
            dst = init
        emitted.add((names[e.src_id], dst))

    def in_repo(callee: str) -> bool:
        return callee in known or any(callee.startswith(f"{m}.") for m in modules)

    truth = {
        (caller, callee)
        for caller, callees in truth_graph.items()
        for callee in callees
        if in_repo(callee)
    }

    score = CaseScore(case_dir.parent.name, case_dir.name, truth, emitted)
    for pair in sorted(truth - emitted):
        caller, callee = pair
        if callee not in known:
            score.misses[pair] = "no_node"
        elif caller in has_unknown:
            score.misses[pair] = "unknown"
        else:
            score.misses[pair] = "silent"
    return score


def run_bench(snippets: Path = SNIPPETS) -> list[CaseScore]:
    cases = sorted(p.parent for p in snippets.glob("*/*/callgraph.json"))
    return [score_case(c) for c in cases]


def render(scores: list[CaseScore], console: Console, show_misses: bool = False) -> None:
    by_cat: dict[str, Totals] = defaultdict(Totals)
    overall = Totals()
    for s in scores:
        by_cat[s.category].add(s)
        overall.add(s)

    table = Table(title="PyCG micro-benchmark — in-repo call edges")
    for col in ("category", "exact", "precision", "recall", *MISS_KINDS):
        table.add_column(col, justify="left" if col == "category" else "right")
    rows = [*sorted(by_cat.items()), ("TOTAL", overall)]
    for cat, t in rows:
        silent = t.misses["silent"]
        table.add_row(
            f"[bold]{cat}[/bold]" if cat == "TOTAL" else cat,
            f"{t.exact}/{t.cases}",
            f"{t.precision:.1%}",  # never without recall (PRODUCT.md §6)
            f"{t.recall:.1%}",
            str(t.misses["no_node"]),
            str(t.misses["unknown"]),
            f"[red]{silent}[/red]" if silent else "0",
        )
    console.print(table)
    console.print(
        f"{overall.tp} of {overall.truth} truth edges found; "
        f"{overall.emitted - overall.tp} false-positive edges; "
        f"{overall.misses['silent']} silently missing (no unknown edge in the caller)."
    )

    if show_misses:
        for s in scores:
            for (caller, callee), kind in s.misses.items():
                console.print(f"miss ({kind}) {s.category}/{s.name}: {caller} → {callee}")
            for caller, callee in sorted(s.false_positives):
                case = f"{s.category}/{s.name}"
                console.print(f"[red]false positive[/red] {case}: {caller} → {callee}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Score Ravel on the PyCG micro-benchmark.")
    parser.add_argument("--snippets", type=Path, default=SNIPPETS)
    parser.add_argument("--show-misses", action="store_true", help="list every miss and FP")
    args = parser.parse_args(argv)

    configure_logging()
    # Benchmark cases are stdlib-only; don't warn "no virtualenv" 119 times.
    logging.getLogger("ravel.graph.environment").setLevel(logging.ERROR)
    render(run_bench(args.snippets), Console(), args.show_misses)
    return 0


if __name__ == "__main__":
    sys.exit(main())
