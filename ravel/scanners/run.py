"""Run every scanner on a repo, reachability filter, and optionally adjudicate with LLM."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult, build_graph
from ravel.incremental.ast_diff import NodeDiffResult, compute_node_diff
from ravel.incremental.diff import get_git_diff
from ravel.incremental.invalidation import (
    IncrementalReachabilityResult,
    update_reachability_incrementally,
)
from ravel.incremental.splicing import splice_graph
from ravel.models import FindingSource, NodeKind
from ravel.scanners.bandit import BanditScanner
from ravel.scanners.base import Scanner, ScanResult
from ravel.scanners.gitleaks import GitleaksScanner
from ravel.scanners.normalize import (
    DuplicateGroup,
    LocatedFinding,
    MappingStats,
    dedupe,
    normalize,
)
from ravel.scanners.osv import OsvScanner
from ravel.scanners.semgrep import SemgrepScanner
from ravel.triage.adjudicate import TriageStats, adjudicate_findings
from ravel.triage.cache import TriageCache
from ravel.triage.provider import LLMProvider, TokenBudget
from ravel.triage.ranking import rank_findings
from ravel.triage.reachability import analyze_reachability

log = get_logger("ravel.scanners.run")

# Scanners in PRODUCT.md §5 that have no wrapper yet. Listed so every report
# states the recall it is missing instead of implying full coverage.
NOT_YET_INTEGRATED: tuple[FindingSource, ...] = ()


def default_scanners(
    semgrep_configs: list[str] | None = None,
    semgrep_bin: Path | None = None,
    osv_db: Path | None = None,
    osv_bin: Path | None = None,
) -> list[Scanner]:
    """Every integrated scanner. Semgrep runs only with user-supplied local
    rules; OSV only against an offline database the user downloaded."""
    return [
        BanditScanner(),
        SemgrepScanner(semgrep_configs, semgrep_bin),
        OsvScanner(osv_db, osv_bin),
        GitleaksScanner(),
    ]


@dataclass
class ScanReport:
    graph: GraphResult
    results: list[ScanResult]
    findings: list[LocatedFinding]
    mapping: MappingStats
    groups: list[DuplicateGroup] = field(default_factory=list)
    triage_stats: TriageStats | None = None
    not_integrated: tuple[FindingSource, ...] = NOT_YET_INTEGRATED
    diff_stats: NodeDiffResult | None = None
    incremental_stats: IncrementalReachabilityResult | None = None


def scan_repo(
    root: Path | str,
    venv: Path | None = None,
    scanners: list[Scanner] | None = None,
    graph: GraphResult | None = None,
    triage_provider: LLMProvider | None = None,
    token_budget: TokenBudget | None = None,
    triage_cache: TriageCache | None = None,
) -> ScanReport:
    """Build (or reuse) the graph, run each scanner, normalize, reachability filter,
    optionally adjudicate via LLM, and rank."""
    root = Path(root).resolve()
    graph = graph or build_graph(root, venv=venv)
    files = sorted({n.file_path for n in graph.nodes if n.kind is NodeKind.FILE})

    if scanners is None:
        scanners = default_scanners()
    results = [s.scan(root, files) for s in scanners]  # [] means: graph only, no scanners
    raw = [f for r in results for f in r.findings]
    findings, mapping = normalize(
        raw,
        graph.nodes,
        root,
        external_refs=graph.external_refs,
        site_packages=list(graph.environment.site_packages),
    )
    log.info(
        "scan: %d findings from %d scanner(s), %.1f%% mapped to nodes",
        len(findings),
        len(results),
        mapping.ratio * 100,
    )
    findings = analyze_reachability(graph, findings)

    triage_stats: TriageStats | None = None
    if triage_provider is not None:
        budget = token_budget or TokenBudget()
        findings, triage_stats = adjudicate_findings(
            findings=findings,
            graph_result=graph,
            root=root,
            provider=triage_provider,
            budget=budget,
            cache=triage_cache,
        )

    findings = rank_findings(findings)
    return ScanReport(
        graph, results, findings, mapping, dedupe(findings), triage_stats=triage_stats
    )


def scan_repo_incremental(
    root: Path | str,
    base_ref: str,
    previous_report: ScanReport | None = None,
    venv: Path | None = None,
    scanners: list[Scanner] | None = None,
    triage_provider: LLMProvider | None = None,
    token_budget: TokenBudget | None = None,
    triage_cache: TriageCache | None = None,
) -> ScanReport:
    """Incrementally scan only changed files and selectively update reachability."""
    root = Path(root).resolve()
    file_changes = get_git_diff(root, base_ref=base_ref)
    if not file_changes:
        log.info("incremental scan: no changes detected since %s", base_ref)
        if previous_report is not None:
            return previous_report
        return scan_repo(
            root,
            venv=venv,
            scanners=scanners,
            triage_provider=triage_provider,
            token_budget=token_budget,
            triage_cache=triage_cache,
        )

    if previous_report is None:
        # Build baseline
        previous_report = scan_repo(root, venv=venv, scanners=scanners)

    prev_graph = previous_report.graph
    prev_findings = previous_report.findings

    # 1. Compute AST-level node diff and detect renames
    diff = compute_node_diff(root, file_changes, prev_graph.nodes)

    # 2. Splice the call graph incrementally
    spliced_graph = splice_graph(root, prev_graph, diff, venv=venv)

    # 3. Run scanners only on dirty / added files
    dirty_files = sorted(
        {
            n.file_path
            for n in [*diff.modified_nodes, *diff.added_nodes]
            if n.kind is NodeKind.FILE
        }
    )
    if scanners is None:
        scanners = default_scanners()

    new_results = [s.scan(root, dirty_files) for s in scanners] if dirty_files else []
    new_raw = [f for r in new_results for f in r.findings]
    new_findings, mapping = normalize(
        new_raw,
        spliced_graph.nodes,
        root,
        external_refs=spliced_graph.external_refs,
        site_packages=list(spliced_graph.environment.site_packages),
    )

    # 4. Invalidate and update reachability selectively
    inc_result = update_reachability_incrementally(
        spliced_graph,
        prev_findings,
        diff,
        new_findings=new_findings,
    )

    # 5. Adjudicate triage if requested
    triage_stats: TriageStats | None = None
    final_findings = inc_result.findings
    if triage_provider is not None:
        budget = token_budget or TokenBudget()
        final_findings, triage_stats = adjudicate_findings(
            findings=final_findings,
            graph_result=spliced_graph,
            root=root,
            provider=triage_provider,
            budget=budget,
            cache=triage_cache,
        )

    final_findings = rank_findings(final_findings)
    return ScanReport(
        graph=spliced_graph,
        results=previous_report.results,
        findings=final_findings,
        mapping=mapping,
        groups=dedupe(final_findings),
        triage_stats=triage_stats,
        diff_stats=diff,
        incremental_stats=inc_result,
    )
