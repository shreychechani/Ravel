"""``ravel`` CLI.

``ravel index PATH`` builds the call graph and reports coverage.
``ravel scan PATH`` runs the security scanners and anchors every finding on a
graph node. Later phases add reachability and triage.
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
from ravel.scanners.base import ScanStatus
from ravel.scanners.normalize import cross_scanner_duplicates
from ravel.scanners.run import default_scanners, scan_repo

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
    venv: Annotated[
        Path | None,
        typer.Option(
            "--venv",
            exists=True,
            file_okay=False,
            help="The repo's virtualenv, if not at PATH/.venv, venv or env. Read, never run.",
        ),
    ] = None,
) -> None:
    """Index a Python repo: build the call graph and report coverage."""
    configure_logging()

    try:
        result = build_graph(path, venv=venv)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--venv") from exc
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
    env_style = "green" if result.environment.found else "yellow"
    table.add_row("Python env", f"[{env_style}]{result.environment.describe()}[/{env_style}]")
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
            "environment": {
                "venv": str(result.environment.venv) if result.environment.venv else None,
                "site_packages": [str(p) for p in result.environment.site_packages],
            },
        }
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote graph (%d nodes, %d edges) to %s", len(nodes), len(result.edges), json_out)


_PathArg = Annotated[
    Path,
    typer.Argument(
        exists=True, file_okay=False, dir_okay=True, readable=True, help="Path to a Python repo."
    ),
]
_VenvOpt = Annotated[
    Path | None,
    typer.Option(
        "--venv",
        exists=True,
        file_okay=False,
        help="The repo's virtualenv, if not at PATH/.venv, venv or env. Read, never run.",
    ),
]


@app.command()
def scan(
    path: _PathArg,
    venv: _VenvOpt = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write normalized findings to this JSON file.")
    ] = None,
    limit: Annotated[int, typer.Option(help="Max findings to list (0 = all).")] = 50,
    semgrep_config: Annotated[
        list[str] | None,
        typer.Option(
            "--semgrep-config",
            help="Local Semgrep rules file/dir (repeatable). Registry ids are refused.",
        ),
    ] = None,
    semgrep_bin: Annotated[
        Path | None, typer.Option("--semgrep-bin", help="Path to the semgrep executable.")
    ] = None,
) -> None:
    """Run the security scanners and anchor each finding on a graph node."""
    configure_logging()
    try:
        scanners = default_scanners(semgrep_config, semgrep_bin)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--semgrep-config") from exc
    try:
        report = scan_repo(path, venv=venv, scanners=scanners)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--venv") from exc

    status_table = Table(title=f"Ravel scan — {path}")
    status_table.add_column("scanner", style="cyan")
    status_table.add_column("status")
    status_table.add_column("version")
    status_table.add_column("findings", justify="right")
    for r in report.results:
        style = {ScanStatus.OK: "green", ScanStatus.NOT_CONFIGURED: "yellow"}.get(r.status, "red")
        status_table.add_row(
            r.source.value,
            f"[{style}]{r.status.value}[/{style}]",
            r.version or "-",
            str(len(r.findings)),
        )
    for missing in report.not_integrated:
        # Never imply full coverage: a scanner we don't run is recall we don't have.
        status_table.add_row(missing.value, "[yellow]not integrated yet[/yellow]", "-", "-")
    console.print(status_table)

    m = report.mapping
    style = "green" if m.ratio >= 0.95 else "yellow"
    summary = Table(title="Findings")
    summary.add_column("metric", style="cyan")
    summary.add_column("value", justify="right")
    summary.add_row("Findings", str(m.total))
    summary.add_row("Mapped to a node (gate ≥95%)", f"[{style}]{m.ratio:.1%}[/{style}]")
    summary.add_row("  ├─ function / class", str(m.to_def))
    summary.add_row("  ├─ module level (file node)", str(m.to_file))
    summary.add_row("  └─ unmapped", str(m.unmapped))
    summary.add_row("Non-Python files (no node; outside the rate)", str(m.non_python))
    summary.add_row("Cross-scanner duplicates", str(cross_scanner_duplicates(report.groups)))
    cov = report.graph.coverage.ratio
    # <60% coverage invalidates reachability claims built on this graph (PRODUCT.md §9).
    cov_style = "green" if cov >= 0.80 else "yellow" if cov >= 0.60 else "red"
    summary.add_row("Graph coverage", f"[{cov_style}]{cov:.1%}[/{cov_style}]")
    summary.add_row("Python env", report.graph.environment.describe())
    console.print(summary)

    shown = report.findings if limit == 0 else report.findings[:limit]
    if shown:
        table = Table(title=f"Findings ({len(shown)} of {len(report.findings)})")
        table.add_column("rule", style="cyan")
        table.add_column("sev")
        table.add_column("cwe")
        table.add_column("location")
        table.add_column("node")
        for lf in shown:
            table.add_row(
                lf.finding.rule_id,
                lf.raw.severity.value,
                lf.finding.cwe or "-",
                f"{lf.raw.rel_path}:{lf.raw.line}",
                lf.node.qualified_name if lf.node else "[dim](non-Python file)[/dim]",
            )
        console.print(table)

    if json_out is not None:
        payload = {
            "scanners": [
                {
                    "source": r.source.value,
                    "status": r.status.value,
                    "version": r.version,
                    "errors": r.errors,
                }
                for r in report.results
            ],
            "not_integrated": [s.value for s in report.not_integrated],
            "mapping": {
                "total": m.total,
                "to_def": m.to_def,
                "to_file": m.to_file,
                "unmapped": m.unmapped,
                "non_python": m.non_python,
                "ratio": m.ratio,
            },
            "findings": [
                {
                    **lf.finding.model_dump(),
                    "file": lf.raw.rel_path,
                    "line": lf.raw.line,
                    "end_line": lf.raw.end_line,
                    "severity": lf.raw.severity.value,
                    "confidence": lf.raw.confidence,
                    "message": lf.raw.message,
                }
                for lf in report.findings
            ],
        }
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote %d findings to %s", len(report.findings), json_out)


def run() -> None:
    """Console-script entry point."""
    app()
