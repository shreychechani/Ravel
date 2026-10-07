"""Run every scanner on a repo, reachability filter, and optionally adjudicate with LLM."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult, build_graph
from ravel.models import FindingSource, NodeKind
from ravel.scanners.bandit import BanditScanner
from ravel.scanners.base import Scanner, ScanResult
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
NOT_YET_INTEGRATED = (FindingSource.GITLEAKS,)


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

    results = [s.scan(root, files) for s in (scanners or default_scanners())]
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
