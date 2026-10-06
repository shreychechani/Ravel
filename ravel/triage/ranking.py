"""Finding ranking engine (PRODUCT.md §3, §4; BUILD-PLAN §4).

Ranks findings by:
1. **Reachability status**: ``REACHABLE`` > ``UNKNOWN`` > ``UNREACHABLE``
2. **Blast radius**: number of distinct untrusted entry points reaching the node (descending)
3. **Raw severity**: ``CRITICAL`` / ``HIGH`` > ``MEDIUM`` > ``LOW`` > ``INFO``
"""

from __future__ import annotations

from typing import TypeVar

from ravel.models import Finding, Reachability
from ravel.scanners.normalize import LocatedFinding

F = TypeVar("F", Finding, LocatedFinding)

_REACHABILITY_WEIGHT: dict[Reachability, int] = {
    Reachability.REACHABLE: 3,
    Reachability.UNKNOWN: 2,
    Reachability.UNREACHABLE: 1,
}

_SEVERITY_WEIGHT: dict[str, int] = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1,
}


def _severity_rank(severity: str) -> int:
    return _SEVERITY_WEIGHT.get(severity.upper(), 0)


def _reachability_rank(finding: Finding) -> int:
    if finding.static_evidence is None:
        return 0
    return _REACHABILITY_WEIGHT.get(finding.static_evidence.reachable, 0)


def _blast_radius(finding: Finding) -> int:
    if finding.static_evidence is None:
        return 0
    return finding.static_evidence.blast_radius


def rank_findings(findings: list[F]) -> list[F]:
    """Sort findings by reachability tier, blast radius, and raw severity.

    Returns a new list containing the sorted findings.
    """
    def key_fn(item: F) -> tuple[int, int, int]:
        finding = item.finding if isinstance(item, LocatedFinding) else item
        return (
            _reachability_rank(finding),
            _blast_radius(finding),
            _severity_rank(finding.raw_severity),
        )

    return sorted(findings, key=key_fn, reverse=True)
