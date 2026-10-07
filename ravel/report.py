"""A scan as one JSON document — the shape ``--json`` writes and the web view reads.

The CLI tables are for a terminal; this is the same report for machines. On top
of the normalized findings it carries what a reviewer needs to *check* a
verdict rather than trust it (PRODUCT.md §3, "traced paths"): every node a
traced path passes through, whether each hop was resolved or ``unknown``
(§6: unresolved edges are shown, never hidden), the flagged code, and its
in-repo callers. Coverage travels with it, because a reachability claim is only
as good as the map behind it.

Source is read from disk at report time only to show it; nothing here executes
or writes to the scanned repo.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ravel.graph.resolve import GraphResult
from ravel.models import EdgeKind, Node, NodeKind
from ravel.scanners.normalize import LocatedFinding, cross_scanner_duplicates
from ravel.scanners.run import ScanReport
from ravel.triage.provider import TokenBudget

REPORT_VERSION = 2  # 2: adds "graph_view", the whole code graph
_SNIPPET_MAX_LINES = 60
_FILE_WINDOW = 5  # lines either side of a module-level finding


def _node_info(node: Node) -> dict[str, Any]:
    return {
        "id": node.id,
        "kind": node.kind.value,
        "name": node.qualified_name,
        "file": node.file_path,
        "line": node.start_line,
        "end_line": node.end_line,
    }


def _source_lines(root: Path, rel_path: str) -> list[str]:
    try:
        return (root / rel_path).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _snippet(root: Path, lf: LocatedFinding) -> dict[str, Any] | None:
    """The flagged function (or a window around a module-level line), capped in length."""
    if lf.raw.package is not None:
        return None
    if lf.node is not None and lf.node.kind is not NodeKind.FILE:
        start, end = lf.node.start_line, lf.node.end_line
    else:
        start = max(1, lf.raw.line - _FILE_WINDOW)
        end = lf.raw.line + _FILE_WINDOW
    end = min(end, start + _SNIPPET_MAX_LINES - 1)
    lines = _source_lines(root, lf.raw.rel_path)
    if not lines:
        return None
    end = min(end, len(lines))
    return {
        "file": lf.raw.rel_path,
        "start_line": start,
        "lines": lines[start - 1 : end],
        "highlight": [lf.raw.line, lf.raw.end_line],
    }


def _hop_resolved(graph: GraphResult, src: str, dst: str) -> bool:
    """A hop is resolved only if some edge between the pair is, and neither end is unknown."""
    if src.startswith("unknown::") or dst.startswith("unknown::"):
        return False
    data = graph.graph.get_edge_data(src, dst) or {}
    return any(attrs.get("resolved", True) for attrs in data.values())


def _hop_kind(graph: GraphResult, src: str, dst: str) -> str:
    data = graph.graph.get_edge_data(src, dst) or {}
    kinds = sorted({str(attrs.get("kind", key)) for key, attrs in data.items()})
    return "+".join(kinds) if kinds else "unknown"


def _finding_entry(
    lf: LocatedFinding, graph: GraphResult, root: Path, nodes: dict[str, Node]
) -> dict[str, Any]:
    ev = lf.finding.static_evidence
    path = ev.path if ev else []
    hops = [
        {"src": a, "dst": b, "resolved": _hop_resolved(graph, a, b), "kind": _hop_kind(graph, a, b)}
        for a, b in zip(path, path[1:], strict=False)
    ]
    callers: list[str] = []
    if lf.node is not None and lf.node.id in graph.graph:
        # Only real callers: a file "defines" its functions, it does not call them.
        callers = sorted(
            p
            for p in graph.graph.predecessors(lf.node.id)
            if p in nodes and graph.graph.has_edge(p, lf.node.id, key=EdgeKind.CALLS.value)
        )
    return {
        **lf.finding.model_dump(),
        "file": lf.raw.rel_path,
        "line": lf.raw.line,
        "end_line": lf.raw.end_line,
        "severity": lf.raw.severity.value,
        "scanner_confidence": lf.raw.confidence,
        "verdict": lf.finding.verdict,
        "reasoning": lf.finding.reasoning,
        "message": lf.raw.message,
        "package": lf.raw.package,
        "package_version": lf.raw.package_version,
        "fixed_in": lf.raw.fixed_in,
        "aliases": list(lf.raw.aliases),
        "anchors": [n.id for n in lf.anchors],
        "via": list(lf.via),
        "node_name": lf.node.qualified_name if lf.node is not None else None,
        "path_hops": hops,
        "callers": callers,
        "code": _snippet(root, lf),
    }


def _graph_view(graph: GraphResult, findings: list[LocatedFinding]) -> dict[str, Any]:
    """The whole code graph, for the web view's graph tab.

    Every file, class and function, with the edges between them. A call that
    could not be resolved points at an ``unknown`` node and is marked
    ``resolved: false`` — shown, never hidden (§6). Each node carries the
    findings anchored on it and the most reachable of them.
    """
    order = {"reachable": 0, "unknown": 1, "unreachable": 2}
    per_node: dict[str, list[tuple[str, str]]] = {}
    for lf in findings:
        ev = lf.finding.static_evidence
        reach = ev.reachable.value if ev else "unknown"
        targets = [lf.node.id] if lf.node is not None else [a.id for a in lf.anchors]
        for nid in targets:
            per_node.setdefault(nid, []).append((lf.finding.id, reach))
    entry = {ep.node_id for ep in graph.entry_points}
    nodes_out: list[dict[str, Any]] = []
    for n in graph.nodes:
        hits = per_node.get(n.id, [])
        nodes_out.append(
            {
                **_node_info(n),
                "entry_point": n.id in entry,
                "findings": [fid for fid, _ in hits],
                "worst_reach": min((r for _, r in hits), key=order.__getitem__, default=None),
            }
        )
    known = {n.id for n in graph.nodes}
    unknown_ids: set[str] = set()
    edges_out: list[dict[str, Any]] = []
    for u, v, key, data in graph.graph.edges(keys=True, data=True):
        if u not in known:
            continue
        if v not in known:
            if not str(v).startswith("unknown::"):
                continue
            unknown_ids.add(str(v))
        edges_out.append(
            {
                "src": u,
                "dst": v,
                "kind": str(data.get("kind", key)),
                "resolved": bool(data.get("resolved", True)),
            }
        )
    for uid in sorted(unknown_ids):
        nodes_out.append(
            {
                "id": uid,
                "kind": "unknown",
                "name": uid.removeprefix("unknown::") or "?",
                "file": "",
                "line": 0,
                "end_line": 0,
                "entry_point": False,
                "findings": [],
                "worst_reach": None,
            }
        )
    return {"nodes": nodes_out, "edges": edges_out}


def build_report(
    report: ScanReport, root: Path | str, budget: TokenBudget | None = None
) -> dict[str, Any]:
    """Serialize a scan, with the evidence needed to review each finding."""
    root = Path(root).resolve()
    graph = report.graph
    nodes = {n.id: n for n in graph.nodes}
    m = report.mapping
    cov = graph.coverage

    findings = [_finding_entry(lf, graph, root, nodes) for lf in report.findings]
    # Every node a finding mentions — its anchor, path, callers, importers — so a
    # reader never has to rebuild the graph to label what it sees.
    referenced: set[str] = set()
    for lf, entry in zip(report.findings, findings, strict=True):
        referenced.add(lf.finding.node_id)
        referenced.update(entry["anchors"])
        referenced.update(entry["callers"])
        ev = lf.finding.static_evidence
        if ev is not None:
            referenced.update(ev.path)
    referenced.update(ep.node_id for ep in graph.entry_points)

    payload: dict[str, Any] = {
        "report_version": REPORT_VERSION,
        "repo": root.name,
        "graph": {
            "nodes": len(graph.nodes),
            "edges": len(graph.edges),
            "coverage": {
                "ratio": cov.ratio,
                "total": cov.total,
                "internal": cov.internal,
                "external": cov.external,
                "unresolved": cov.unresolved,
            },
            "environment": graph.environment.describe(),
        },
        "entry_points": [
            {"node_id": ep.node_id, "kind": ep.kind.value, "trust": ep.trust.value}
            for ep in graph.entry_points
        ],
        "nodes": {nid: _node_info(nodes[nid]) for nid in sorted(referenced) if nid in nodes},
        "scanners": [
            {
                "source": r.source.value,
                "status": r.status.value,
                "version": r.version,
                "errors": r.errors,
                "detail": r.detail,
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
            "to_package": m.to_package,
            "via_dependency": m.via_dependency,
            "unused_dependency": m.unused_dependency,
            "dependency_unknown": m.dependency_unknown,
            "ratio": m.ratio,
        },
        "cross_scanner_duplicates": cross_scanner_duplicates(report.groups),
        "graph_view": _graph_view(graph, report.findings),
        "findings": findings,
    }
    if report.triage_stats is not None:
        ts = report.triage_stats
        payload["triage_stats"] = {
            "total": ts.total,
            "survivors_evaluated": ts.survivors_evaluated,
            "cached_hits": ts.cached_hits,
            "llm_calls": ts.llm_calls,
            "unreachable_skipped": ts.unreachable_skipped,
            "budget_exhausted": ts.budget_exhausted,
            "real_count": ts.real_count,
            "false_positive_count": ts.false_positive_count,
            "needs_review_count": ts.needs_review_count,
        }
        if budget is not None:
            payload["triage_stats"]["tokens_used"] = budget.total
            payload["triage_stats"]["token_limit"] = budget.limit
    return payload
