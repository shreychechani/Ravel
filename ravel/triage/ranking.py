"""Finding ranking engine (PRODUCT.md §3, §4; BUILD-PLAN §4).

Ranks findings by:
1. **Reachability status**: ``REACHABLE`` > ``UNKNOWN`` > ``UNREACHABLE``
2. **LLM verdict**: ``real`` > ``needs_review`` > ``false_positive`` > unadjudicated
3. **Verdict confidence**: float 0.0 to 1.0 (descending)
4. **Blast radius**: number of distinct untrusted entry points reaching the node (descending)
5. **Raw severity**: ``CRITICAL`` > ``HIGH`` > ``MEDIUM`` > ``LOW`` > ``INFO``
"""

from __future__ import annotations

from ravel.models import Finding, Reachability
from ravel.scanners.normalize import LocatedFinding

_REACHABILITY_WEIGHT: dict[Reachability, int] = {
    Reachability.REACHABLE: 3,
    Reachability.UNKNOWN: 2,
    Reachability.UNREACHABLE: 1,
}

_VERDICT_WEIGHT: dict[str, int] = {
    "real": 3,
    "needs_review": 2,
    "false_positive": 1,
    "unreachable": 0,
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


def _verdict_rank(finding: Finding) -> int:
    if not finding.verdict:
        return 0
    return _VERDICT_WEIGHT.get(finding.verdict.lower(), 0)


def _blast_radius(finding: Finding) -> int:
    if finding.static_evidence is None:
        return 0
    return finding.static_evidence.blast_radius


def rank_findings[F: (Finding, LocatedFinding)](findings: list[F]) -> list[F]:
    """Sort findings by reachability tier, verdict, confidence, blast radius, and raw severity.

    Returns a new list containing the sorted findings.
    """

    def key_fn(item: F) -> tuple[int, int, float, int, int]:
        finding = item.finding if isinstance(item, LocatedFinding) else item
        return (
            _reachability_rank(finding),
            _verdict_rank(finding),
            float(finding.confidence or 0.0),
            _blast_radius(finding),
            _severity_rank(finding.raw_severity),
        )

    return sorted(findings, key=key_fn, reverse=True)
