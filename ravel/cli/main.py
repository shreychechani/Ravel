"""``ravel`` CLI.

``ravel index PATH`` builds the call graph and reports coverage.
``ravel scan PATH`` runs the security scanners, filters findings by reachability,
optionally performs LLM adjudication, and anchors every finding on a graph node.
``ravel deps PATH`` reports dependency upgrades and deprecated APIs, by reachability.
``ravel serve PATH`` opens the web view of a scan on localhost.
``ravel summarize PATH`` writes bottom-up function and module summaries with an LLM.
``ravel osv-db update`` downloads the offline vulnerability database.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from ravel.api.server import ReportStore, ScanSettings, Workspace, create_app, load_report
from ravel.core.logging import configure_logging, get_logger
from ravel.deps.report import DepsReport, Urgency, build_deps_report, deps_payload
from ravel.graph.parse import PROVENANCE
from ravel.graph.resolve import build_graph
from ravel.ingest.remote import is_remote, resolve_target
from ravel.models import EdgeKind, NodeKind, Reachability
from ravel.report import build_report
from ravel.scanners.base import ScanStatus
from ravel.scanners.normalize import LocatedFinding, cross_scanner_duplicates
from ravel.scanners.osv import OsvScanner, default_db_dir, update_db
from ravel.scanners.run import default_scanners, scan_repo, scan_repo_incremental
from ravel.summarize.summaries import SummaryCache, summaries_payload, summarize_graph
from ravel.triage.cache import TriageCache
from ravel.triage.provider import TokenBudget, create_provider

app = typer.Typer(add_completion=False, help="Ravel — reachability-aware security triage.")
osv_db_app = typer.Typer(help="Manage the offline OSV vulnerability database.")
app.add_typer(osv_db_app, name="osv-db")
console = Console()
log = get_logger("ravel.cli")


@app.callback()
def _root() -> None:
    """Ravel — reachability-aware security triage for Python codebases."""


_TargetArg = Annotated[
    str,
    typer.Argument(help="Path to a Python repo, or a git URL to clone (https://, git@...)."),
]
_RefOpt = Annotated[
    str | None,
    typer.Option("--ref", help="With a git URL: the commit, tag or branch to scan."),
]


def _resolve_target(target: str, ref: str | None) -> Path:
    """A local repo directory: the path itself, or a cached clone of a git URL."""
    try:
        return resolve_target(target, ref)
    except ValueError as exc:
        hint = "--ref" if "--ref" in str(exc) else None
        raise typer.BadParameter(str(exc), param_hint=hint) from exc


@app.command()
def index(
    target: _TargetArg,
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
    ref: _RefOpt = None,
) -> None:
    """Index a Python repo: build the call graph and report coverage."""
    configure_logging()
    path = _resolve_target(target, ref)

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

    cov_pct = cov.ratio * 100
    cov_style = "green" if cov.ratio >= 0.80 else "yellow"

    table = Table(title=f"Ravel index - {path}")
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
    table.add_row("  |- resolved (internal)", str(cov.internal))
    table.add_row("  |- resolved (external)", str(cov.external))
    table.add_row("  \\- unresolved", str(cov.unresolved))
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
    target: _TargetArg,
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
    osv_db: Annotated[
        Path | None,
        typer.Option("--osv-db", help="Offline OSV database dir (default: $RAVEL_OSV_DB)."),
    ] = None,
    osv_bin: Annotated[
        Path | None, typer.Option("--osv-bin", help="Path to the osv-scanner executable.")
    ] = None,
    triage: Annotated[
        bool,
        typer.Option("--triage/--no-triage", help="Enable LLM triage adjudication on survivors."),
    ] = False,
    llm_provider: Annotated[
        str,
        typer.Option("--llm-provider", help="LLM provider: 'mock', 'ollama', or 'openai'."),
    ] = "mock",
    model: Annotated[
        str | None,
        typer.Option("--model", help="Model name (e.g. 'llama3.2', 'gpt-4o-mini')."),
    ] = None,
    token_budget: Annotated[
        int,
        typer.Option("--token-budget", help="Maximum token budget before kill switch trips."),
    ] = 100_000,
    triage_cache: Annotated[
        Path | None,
        typer.Option("--triage-cache", help="Path to triage cache JSON file."),
    ] = None,
    since: Annotated[
        str | None,
        typer.Option(
            "--since",
            help="Base git commit/ref for incremental scan (e.g. HEAD~1, main). "
            "Only changed files are parsed and affected paths invalidated.",
        ),
    ] = None,
    ref: _RefOpt = None,
) -> None:
    """Run the security scanners, reachability filter, and optionally adjudicate findings."""
    configure_logging()
    path = _resolve_target(target, ref)
    try:
        scanners = default_scanners(semgrep_config, semgrep_bin, osv_db, osv_bin)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--semgrep-config") from exc

    provider = None
    budget = None
    cache = None
    if triage:
        try:
            provider = create_provider(llm_provider, model=model)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--llm-provider") from exc
        budget = TokenBudget(limit=token_budget)
        cache = TriageCache(cache_file=triage_cache)

    try:
        if since is not None:
            report = scan_repo_incremental(
                path,
                base_ref=since,
                venv=venv,
                scanners=scanners,
                triage_provider=provider,
                token_budget=budget,
                triage_cache=cache,
            )
        else:
            report = scan_repo(
                path,
                venv=venv,
                scanners=scanners,
                triage_provider=provider,
                token_budget=budget,
                triage_cache=cache,
            )
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--venv") from exc

    if report.incremental_stats is not None and report.diff_stats is not None:
        inc = report.incremental_stats
        diff_s = report.diff_stats
        inc_table = Table(title=f"Incremental Analysis Summary (since {since})")
        inc_table.add_column("metric", style="cyan")
        inc_table.add_column("value", justify="right")
        inc_table.add_row("Base Revision", since or "HEAD")
        inc_table.add_row("Dirty / Added Nodes", str(len(diff_s.dirty_node_ids)))
        inc_table.add_row("Renamed Functions Detected", str(len(diff_s.renamed_nodes)))
        inc_table.add_row("Untouched Nodes Reused", str(len(diff_s.unchanged_nodes)))
        inc_table.add_row("Paths Reused", f"[green]{inc.reused_count}[/green]")
        inc_table.add_row("Paths Re-evaluated", f"[yellow]{inc.invalidated_count}[/yellow]")
        console.print(inc_table)

    status_table = Table(title=f"Ravel scan - {path}")
    status_table.add_column("scanner", style="cyan")
    status_table.add_column("status")
    status_table.add_column("version")
    status_table.add_column("findings", justify="right")
    status_table.add_column("detail")
    for r in report.results:
        style = {ScanStatus.OK: "green", ScanStatus.NOT_CONFIGURED: "yellow"}.get(r.status, "red")
        status_table.add_row(
            r.source.value,
            f"[{style}]{r.status.value}[/{style}]",
            r.version or "-",
            str(len(r.findings)),
            r.detail or "",
        )
    for missing in report.not_integrated:
        status_table.add_row(missing.value, "[yellow]not integrated yet[/yellow]", "-", "-", "")
    console.print(status_table)

    m = report.mapping
    style = "green" if m.ratio >= 0.95 else "yellow"
    summary = Table(title="Findings Summary")
    summary.add_column("metric", style="cyan")
    summary.add_column("value", justify="right")
    summary.add_row("Total Findings", str(m.total))
    summary.add_row("Mapped to a node (gate >=95%)", f"[{style}]{m.ratio:.1%}[/{style}]")
    summary.add_row("  |- function / class", str(m.to_def))
    summary.add_row("  |- module level (file node)", str(m.to_file))
    summary.add_row("  |- dependency, linked to its importers", str(m.to_package))
    summary.add_row("  |- transitive dependency, via parent package", str(m.via_dependency))
    summary.add_row("  \\- unmapped", str(m.unmapped))
    summary.add_row("Non-Python files (no node; outside the rate)", str(m.non_python))
    summary.add_row("Unused deps: nothing imports or needs them", str(m.unused_dependency))
    summary.add_row("Deps not imported, usage unknown — no env", str(m.dependency_unknown))
    summary.add_row("Cross-scanner duplicates", str(cross_scanner_duplicates(report.groups)))

    # Reachability summary
    reachable_cnt = sum(
        1
        for f in report.findings
        if f.finding.static_evidence
        and f.finding.static_evidence.reachable is Reachability.REACHABLE
    )
    unknown_cnt = sum(
        1
        for f in report.findings
        if f.finding.static_evidence and f.finding.static_evidence.reachable is Reachability.UNKNOWN
    )
    unreachable_cnt = sum(
        1
        for f in report.findings
        if f.finding.static_evidence
        and f.finding.static_evidence.reachable is Reachability.UNREACHABLE
    )
    reach_summary = (
        f"[green]{reachable_cnt} reachable[/green] | "
        f"[yellow]{unknown_cnt} unknown[/yellow] | "
        f"[dim]{unreachable_cnt} unreachable[/dim]"
    )
    summary.add_row("Reachability (Phase 3)", reach_summary)

    if report.triage_stats is not None:
        ts = report.triage_stats
        triage_text = (
            f"[red]{ts.real_count} real[/red] | "
            f"[green]{ts.false_positive_count} false positive[/green] | "
            f"[yellow]{ts.needs_review_count} needs review[/yellow]"
        )
        summary.add_row("LLM Triage (Phase 4)", triage_text)
        summary.add_row(
            "Triage LLM calls / cache hits", f"{ts.llm_calls} calls / {ts.cached_hits} cached"
        )
        if budget is not None:
            summary.add_row("Token budget used", f"{budget.total} / {budget.limit} tokens")

    cov = report.graph.coverage.ratio
    cov_style = "green" if cov >= 0.80 else "yellow" if cov >= 0.60 else "red"
    summary.add_row("Graph coverage", f"[{cov_style}]{cov:.1%}[/{cov_style}]")
    summary.add_row("Python env", report.graph.environment.describe())
    console.print(summary)

    shown = report.findings if limit == 0 else report.findings[:limit]
    if shown:
        table = Table(title=f"Ranked Findings ({len(shown)} of {len(report.findings)})")
        table.add_column("rule", style="cyan")
        table.add_column("sev")
        table.add_column("reachability")
        table.add_column("blast", justify="right")
        if triage:
            table.add_column("verdict")
            table.add_column("conf", justify="right")
        table.add_column("cwe")
        table.add_column("location")
        table.add_column("node")
        for lf in shown:
            ev = lf.finding.static_evidence
            reach_str = ev.reachable.value if ev else "unknown"
            reach_style = (
                "green"
                if reach_str == "reachable"
                else "yellow"
                if reach_str == "unknown"
                else "dim"
            )
            blast_str = str(ev.blast_radius) if ev else "0"

            row = [
                lf.finding.rule_id,
                lf.raw.severity.value,
                f"[{reach_style}]{reach_str}[/{reach_style}]",
                blast_str,
            ]
            if triage:
                v = lf.finding.verdict or "unadjudicated"
                v_style = (
                    "red"
                    if v == "real"
                    else "green"
                    if v == "false_positive"
                    else "yellow"
                    if v == "needs_review"
                    else "dim"
                )
                conf_str = (
                    f"{lf.finding.confidence:.2f}" if lf.finding.confidence is not None else "-"
                )
                row.extend([f"[{v_style}]{v}[/{v_style}]", conf_str])

            row.extend(
                [
                    lf.finding.cwe or "-",
                    _location(lf),
                    _anchor_label(lf),
                ]
            )
            table.add_row(*row)
        console.print(table)

    if json_out is not None:
        payload = build_report(report, path, budget)
        json_out.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log.info("Wrote %d findings to %s", len(report.findings), json_out)


_URGENCY_STYLE = {
    Urgency.URGENT: "bold red",
    Urgency.CHECK: "yellow",
    Urgency.ROUTINE: "dim",
    Urgency.MIGRATE: "cyan",
    Urgency.OK: "green",
}
_REACH_STYLE = {
    Reachability.REACHABLE: "green",
    Reachability.UNKNOWN: "yellow",
    Reachability.UNREACHABLE: "dim",
}


@app.command()
def deps(
    target: _TargetArg,
    venv: _VenvOpt = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the dependency report to this JSON file.")
    ] = None,
    osv_db: Annotated[
        Path | None,
        typer.Option("--osv-db", help="Offline OSV database dir (default: $RAVEL_OSV_DB)."),
    ] = None,
    osv_bin: Annotated[
        Path | None, typer.Option("--osv-bin", help="Path to the osv-scanner executable.")
    ] = None,
    ref: _RefOpt = None,
) -> None:
    """What would upgrading cost? Advisories and deprecated APIs, ranked by reachability."""
    configure_logging()
    path = _resolve_target(target, ref)
    try:
        scan_report = scan_repo(path, venv=venv, scanners=[OsvScanner(osv_db, osv_bin)])
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--venv") from exc
    report = build_deps_report(scan_report)
    _print_deps(report, path, scan_report.graph.environment.describe())
    if json_out is not None:
        json_out.write_text(json.dumps(deps_payload(report), indent=2), encoding="utf-8")
        log.info("Wrote the dependency report (%d packages) to %s", len(report.packages), json_out)


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _print_deps(report: DepsReport, path: Path, env: str) -> None:
    osv = report.osv
    osv_text = "not run"
    if osv is not None:
        style = "green" if osv.status is ScanStatus.OK else "yellow"
        osv_text = f"[{style}]{osv.status.value}[/{style}]" + (
            f" ({osv.detail})" if osv.detail else ""
        )
    c = report.check
    summary = Table(title=f"Ravel deps - {path}")
    summary.add_column("metric", style="cyan")
    summary.add_column("value")
    summary.add_row("Third-party packages used", str(len(report.third_party)))
    summary.add_row(
        "Upgrades by urgency",
        " | ".join(
            f"[{_URGENCY_STYLE[u]}]{report.count(u)} {u.value}[/{_URGENCY_STYLE[u]}]"
            for u in (Urgency.URGENT, Urgency.CHECK, Urgency.ROUTINE, Urgency.MIGRATE)
        ),
    )
    summary.add_row("Known advisories (OSV)", osv_text)
    summary.add_row(
        "Deprecation check",
        f"{c.checked} resolved external calls read · {c.deprecated} deprecated · "
        f"{c.no_source} without source",
    )
    summary.add_row(
        "  not seen by the check",
        f"[yellow]{report.unresolved_calls} unresolved call sites[/yellow]"
        if report.unresolved_calls
        else "0 unresolved call sites",
    )
    summary.add_row("Stdlib judged against", f"Python {report.python} (the one running Ravel)")
    summary.add_row("Python env", env)
    console.print(summary)

    listed = [p for p in report.packages if p.urgency is not Urgency.OK]
    if listed:
        table = Table(title="Packages to act on (most urgent first)")
        table.add_column("package", style="cyan")
        table.add_column("version")
        table.add_column("urgency")
        table.add_column("advisories", justify="right")
        table.add_column("upgrade to")
        table.add_column("deprecated calls", justify="right")
        table.add_column("usage")
        for p in listed:
            version = p.version or p.declared or ("stdlib" if p.stdlib else "?")
            if p.declared and p.version and p.declared != p.version:
                version += f" (pinned {p.declared})"
            worst = f" ({p.worst_severity.value})" if p.worst_severity else ""
            upgrade = p.upgrade_to or ("-" if not p.advisories else "no fix listed")
            if p.upgrade_to and p.unfixed:
                upgrade += f" (+{p.unfixed} unfixed)"
            if p.via:
                usage = f"runs under {', '.join(p.via)} ({_plural(p.files, 'file')})"
            elif not p.users:
                usage = "[dim]not imported by repo code[/dim]"
            else:
                usage = f"{_plural(p.references, 'ref')} in {_plural(p.files, 'file')}"
            if p.pin_is_stale:
                upgrade += " [green](installed already fixed: update the pin)[/green]"
            style = _URGENCY_STYLE[p.urgency]
            table.add_row(
                p.name,
                version,
                f"[{style}]{p.urgency.value}[/{style}]",
                f"{len(p.advisories)}{worst}" if p.advisories else "-",
                upgrade,
                str(p.deprecated_calls) if p.deprecated else "-",
                usage,
            )
        console.print(table)
    else:
        console.print(
            "[green]No package needs action: no known advisories, no deprecated calls.[/green]"
        )

    apis = [(p, a) for p in report.packages for a in p.deprecated]
    if apis:
        table = Table(title="Deprecated APIs in use (as their libraries mark them)")
        table.add_column("API", style="cyan", overflow="fold")
        table.add_column("reachability")
        table.add_column("calls", justify="right")
        table.add_column("where")
        table.add_column("library says")
        for _p, a in apis:
            reach = a.reach.reachable
            style = _REACH_STYLE[reach]
            first = a.calls[0].use
            where = f"{first.node_id.split('::', 1)[0]}:{first.line}"
            if len(a.calls) > 1:
                where += f" (+{len(a.calls) - 1})"
            note = a.marker.message or a.marker.category or "deprecated"
            if a.marker.conditional:
                note = f"[yellow](only some calls)[/yellow] {note}"
            table.add_row(
                a.symbol, f"[{style}]{reach.value}[/{style}]", str(len(a.calls)), where, note
            )
        console.print(table)
    console.print(
        "[dim]'upgrade to' = the smallest release fixing every known advisory (offline OSV DB), "
        "not the latest release: Ravel never sends your dependency list off this machine.[/dim]"
    )


@app.command()
def summarize(
    target: _TargetArg,
    venv: _VenvOpt = None,
    ref: _RefOpt = None,
    llm_provider: Annotated[
        str, typer.Option("--llm-provider", help="LLM provider: 'mock', 'ollama', or 'openai'.")
    ] = "mock",
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
    token_budget: Annotated[
        int, typer.Option("--token-budget", help="Token budget before the kill switch.")
    ] = 100_000,
    limit: Annotated[
        int | None, typer.Option(help="Summarise at most this many functions/classes.")
    ] = None,
    summary_cache: Annotated[
        Path | None, typer.Option("--summary-cache", help="Path to the summary cache JSON.")
    ] = None,
    json_out: Annotated[
        Path | None, typer.Option("--json", help="Write the summaries to this JSON file.")
    ] = None,
) -> None:
    """Summarise a repo bottom-up with an LLM: functions callee-first, then modules."""
    configure_logging()
    path = _resolve_target(target, ref)
    try:
        provider = create_provider(llm_provider, model=model, json_output=False)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--llm-provider") from exc
    try:
        graph = build_graph(path, venv=venv)
    except ValueError as exc:
        raise typer.BadParameter(str(exc), param_hint="--venv") from exc
    budget = TokenBudget(limit=token_budget)
    run = summarize_graph(graph, path, provider, budget, SummaryCache(summary_cache), limit)

    nodes = {n.id: n for n in graph.nodes}
    table = Table(title=f"Module summaries - {path}")
    table.add_column("module", style="cyan")
    table.add_column("summary")
    for s in run.summaries.values():
        node = nodes[s.node_id]
        if node.kind is NodeKind.FILE:
            flag = " [yellow](unverified names)[/yellow]" if s.flagged else ""
            table.add_row(node.file_path, s.text + flag)
    console.print(table)
    st = run.stats
    console.print(
        f"{st.generated} generated, {st.cached} from cache, {st.flagged} flagged, "
        f"{st.skipped_budget} skipped by the token budget · {st.llm_calls} LLM calls, "
        f"{budget.total}/{budget.limit} tokens"
    )
    if json_out is not None:
        json_out.write_text(json.dumps(summaries_payload(run, graph), indent=2), encoding="utf-8")
        log.info("Wrote %d summaries to %s", len(run.summaries), json_out)


_DEFAULT_UI_DIR = Path(__file__).resolve().parents[2] / "web" / "out"


@app.command()
def serve(
    target: Annotated[
        str | None,
        typer.Argument(
            help="A Python repo or git URL to scan, or a report written by `ravel scan --json`. "
            "Leave it out to choose a repo in the browser.",
        ),
    ] = None,
    venv: _VenvOpt = None,
    port: Annotated[int, typer.Option(help="Port to listen on (127.0.0.1 only).")] = 8765,
    triage: Annotated[
        bool, typer.Option("--triage/--no-triage", help="Run LLM triage on the first scan.")
    ] = False,
    llm_provider: Annotated[
        str, typer.Option("--llm-provider", help="LLM provider: 'mock', 'ollama', or 'openai'.")
    ] = "mock",
    model: Annotated[str | None, typer.Option("--model", help="Model name.")] = None,
    token_budget: Annotated[
        int, typer.Option("--token-budget", help="Token budget per scan before the kill switch.")
    ] = 100_000,
    triage_cache: Annotated[
        Path | None, typer.Option("--triage-cache", help="Path to triage cache JSON file.")
    ] = None,
    semgrep_config: Annotated[
        list[str] | None,
        typer.Option("--semgrep-config", help="Local Semgrep rules file/dir (repeatable)."),
    ] = None,
    osv_db: Annotated[
        Path | None,
        typer.Option("--osv-db", help="Offline OSV database dir (default: $RAVEL_OSV_DB)."),
    ] = None,
    ui_dir: Annotated[
        Path | None, typer.Option("--ui-dir", help="Built web view (default: web/out).")
    ] = None,
    ref: _RefOpt = None,
) -> None:
    """Open the web view of a scan on http://127.0.0.1 (local only, read-only)."""
    import uvicorn

    configure_logging()
    try:
        scanners = default_scanners(semgrep_config, None, osv_db, None)
        create_provider(llm_provider, model=model)  # fail fast on a bad provider
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    workspace = Workspace(ScanSettings(scanners, llm_provider, model, token_budget, triage_cache))

    if target is not None and not is_remote(target) and Path(target).is_file():
        try:
            store = ReportStore(report=load_report(Path(target)), workspace=workspace)
        except (ValueError, json.JSONDecodeError) as exc:
            raise typer.BadParameter(str(exc), param_hint="TARGET") from exc
    else:
        store = ReportStore(workspace=workspace)
        if target is not None:
            try:
                workspace.open(target, ref, venv)
            except ValueError as exc:
                raise typer.BadParameter(str(exc), param_hint="TARGET") from exc
            store.rescan(triage)  # the page opens on a finished scan

    url = f"http://127.0.0.1:{port}"
    console.print(f"Ravel web view: [bold]{url}[/bold]  (Ctrl+C to stop)")
    uvicorn.run(create_app(store, ui_dir or _DEFAULT_UI_DIR), host="127.0.0.1", port=port)


def _location(lf: LocatedFinding) -> str:
    if lf.raw.package is not None:
        return f"{lf.raw.package} {lf.raw.package_version or '?'} ({lf.raw.rel_path})"
    return f"{lf.raw.rel_path}:{lf.raw.line}"


def _anchor_label(lf: LocatedFinding) -> str:
    if lf.node is not None:
        return lf.node.qualified_name
    if lf.raw.package is not None:
        n = len(lf.anchors)
        if not n:
            return "[dim]not imported by repo code[/dim]"
        via = f" via {', '.join(lf.via)}" if lf.via else ""
        return f"{n} importer{'s' if n != 1 else ''}{via}"
    return "[dim](non-Python file)[/dim]"


@osv_db_app.command("update")
def osv_db_update(
    db: Annotated[
        Path | None,
        typer.Option("--db", help="Where to keep the database (default: $RAVEL_OSV_DB)."),
    ] = None,
    osv_bin: Annotated[
        Path | None, typer.Option("--osv-bin", help="Path to the osv-scanner executable.")
    ] = None,
    host: Annotated[Path | None, typer.Option("--host", hidden=True)] = None,
) -> None:
    """Download the PyPI OSV database for offline scans (uses the network)."""
    configure_logging()
    target = db or default_db_dir()
    try:
        date = update_db(target, osv_bin)
    except (FileNotFoundError, RuntimeError) as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from exc
    console.print(f"OSV database ready at {target} (dated {date.isoformat()})")


def run() -> None:
    """Console-script entry point."""
    app()
