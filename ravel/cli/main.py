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
from ravel.graph.parse import PROVENANCE, parse_file
from ravel.ingest.loader import discover
from ravel.models import Node, NodeKind

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
    """Index a Python repo: read files and extract function/class nodes."""
    configure_logging()

    files = discover(path)
    nodes: list[Node] = []
    for source in files:
        nodes.extend(parse_file(source))

    functions = sum(1 for n in nodes if n.kind is NodeKind.FUNCTION)
    classes = sum(1 for n in nodes if n.kind is NodeKind.CLASS)
    loc = sum(f.lines for f in files)

    table = Table(title=f"Ravel index — {path}")
    table.add_column("metric", style="cyan")
    table.add_column("value", justify="right", style="green")
    table.add_row("Python files", str(len(files)))
    table.add_row("Lines of code", str(loc))
    table.add_row("Nodes (functions + classes)", str(len(nodes)))
    table.add_row("Functions", str(functions))
    table.add_row("Classes", str(classes))
    table.add_row("Parser", PROVENANCE)
    console.print(table)

    if json_out is not None:
        json_out.write_text(
            json.dumps([n.model_dump() for n in nodes], indent=2), encoding="utf-8"
        )
        log.info("Wrote %d nodes to %s", len(nodes), json_out)


def run() -> None:
    """Console-script entry point."""
    app()
