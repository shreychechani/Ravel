"""Run every scanner on a repo and anchor the results on its graph."""

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
from ravel.scanners.semgrep import SemgrepScanner

log = get_logger("ravel.scanners.run")

# Scanners in PRODUCT.md §5 that have no wrapper yet. Listed so every report
# states the recall it is missing instead of implying full coverage.
NOT_YET_INTEGRATED = (FindingSource.GITLEAKS, FindingSource.OSV)


def default_scanners(
    semgrep_configs: list[str] | None = None, semgrep_bin: Path | None = None
) -> list[Scanner]:
    """Every integrated scanner. Semgrep runs only with user-supplied local rules."""
    return [BanditScanner(), SemgrepScanner(semgrep_configs, semgrep_bin)]


@dataclass
class ScanReport:
    graph: GraphResult
    results: list[ScanResult]
    findings: list[LocatedFinding]
    mapping: MappingStats
    groups: list[DuplicateGroup] = field(default_factory=list)
    not_integrated: tuple[FindingSource, ...] = NOT_YET_INTEGRATED


def scan_repo(
    root: Path | str,
    venv: Path | None = None,
    scanners: list[Scanner] | None = None,
    graph: GraphResult | None = None,
) -> ScanReport:
    """Build (or reuse) the graph, run each scanner, normalize and dedupe."""
    root = Path(root).resolve()
    graph = graph or build_graph(root, venv=venv)
    files = sorted({n.file_path for n in graph.nodes if n.kind is NodeKind.FILE})

    results = [s.scan(root, files) for s in (scanners or default_scanners())]
    raw = [f for r in results for f in r.findings]
    findings, mapping = normalize(raw, graph.nodes, root)
    log.info(
        "scan: %d findings from %d scanner(s), %.1f%% mapped to nodes",
        len(findings),
        len(results),
        mapping.ratio * 100,
    )
    return ScanReport(graph, results, findings, mapping, dedupe(findings))
