"""``ravel`` CLI.

v1 slice: ``ravel index PATH`` reads a Python repo and extracts the
function/class nodes, printing a summary. Later phases add graph edges,
scanners, reachability, and triage.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from ravel.core.logging import configure_logging, get_logger
from ravel.graph.parse import PROVENANCE
from ravel.graph.resolve import build_graph
from ravel.models import EdgeKind, NodeKind

app = typer.Typer(add_completion=False, help="Ravel — reachability-aware security triage.")
console = Console()
log = get_logger("ravel.cli")


@app.callback()
def _root() -> None:
    """Ravel — reachability-aware security triage for Python codebases."""


@app.command()
def index(
    path: Annotated[
        Path,
        typer.Argument(
            exists=True,
            file_okay=False,
            dir_okay=True,
            readable=True,
            help="Path to a Python repository.",
        ),
    ],
    json_out: Annotated[
        Path | None,
        typer.Option("--json", help="Write the extracted nodes to this JSON file."),
    ] = None,
) -> None:
    """Index a Python repo: build the call graph and report coverage."""
    configure_logging()

    result = build_graph(path)
    nodes = result.nodes
    cov = result.coverage

    functions = sum(1 for n in nodes if n.kind is NodeKind.FUNCTION)
    classes = sum(1 for n in nodes if n.kind is NodeKind.CLASS)
    files = sum(1 for n in nodes if n.kind is NodeKind.FILE)
    call_edges = sum(1 for e in result.edges if e.kind is EdgeKind.CALLS and e.resolved)
    import_edges = sum(1 for e in result.edges if e.kind is EdgeKind.IMPORTS and e.resolved)
    unknown_imports = sum(1 for e in result.edges if e.kind is EdgeKind.IMPORTS and not e.resolved)

    # Coverage is the Phase 1 gate: ≥80% of call sites resolved (BUILD-PLAN §1).
    cov_pct = cov.ratio * 100
    cov_style = "green" if cov.ratio >= 0.80 else "yellow"

    table = Table(title=f"Ravel index — {path}")
    table.add_column("metric", style="cyan")
    table.add_column("value", justify="right", style="green")
    table.add_row("Python files", str(files))
    table.add_row("Functions", str(functions))
    table.add_row("Classes", str(classes))
    table.add_row("Call edges (resolved)", str(call_edges))
    table.add_row("Import edges (resolved / unknown)", f"{import_edges} / {unknown_imports}")
    table.add_row("External refs", str(len(result.external_refs)))
    table.add_row("Entry points (untrusted)", str(len(result.entry_points)))
    table.add_row("Call sites", str(cov.total))
    table.add_row("  ├─ resolved (internal)", str(cov.internal))
    table.add_row("  ├─ resolved (external)", str(cov.external))
    table.add_row("  └─ unresolved", str(cov.unresolved))
    table.add_row("Resolution coverage", f"[{cov_style}]{cov_pct:.1f}%[/{cov_style}]")
    table.add_row("Parser", PROVENANCE)
    console.print(table)

    if result.entry_points:
        by_id = {n.id: n for n in nodes}
        ep_table = Table(title="Entry points (reachability sources)")
        ep_table.add_column("handler", style="cyan")
        ep_table.add_column("kind")
        ep_table.add_column("trust", style="yellow")
        for ep in result.entry_points:
            handler = by_id[ep.node_id]
            ep_table.add_row(
                f"{handler.qualified_name}  [dim]({handler.file_path}:{handler.start_line})[/dim]",
                ep.kind.value,
                ep.trust.value,
            )
        console.print(ep_table)

    if json_out is not None:
        payload = {
            "nodes": [n.model_dump() for n in nodes],
            "edges": [e.model_dump() for e in result.edges],
            "external_refs": [r.model_dump() for r in result.external_refs],
            "entry_points": [ep.model_dump() for ep in result.entry_points],
            "coverage": {
                "total": cov.total,
                "internal": cov.internal,
                "external": cov.external,
                "unresolved": cov.unresolved,
                "ratio": cov.ratio,
            },
        }
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote graph (%d nodes, %d edges) to %s", len(nodes), len(result.edges), json_out)


def run() -> None:
    """Console-script entry point."""
    app()
