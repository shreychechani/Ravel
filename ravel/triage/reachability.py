"""Reachability analysis engine — Ravel's core contribution (PRODUCT.md §3, §4, §6).

Filters findings by tracing directed call/import/defines/inherits paths from
untrusted ``EntryPoint`` nodes to the target node(s) holding each finding.

Crucial non-negotiables (PRODUCT.md §6):
1. **Deterministic, no LLM.**
2. **Unresolved edges are marked unknown, never dropped.**
   A path traversing an edge with ``resolved=False`` or through an ``unknown::``
   node yields ``Reachability.UNKNOWN`` — never ``UNREACHABLE``.
3. Report ``reachable`` status, traced ``path`` (node IDs), and ``blast_radius``.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Protocol

import networkx as nx

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult
from ravel.models import EdgeKind, Finding, NodeKind, Reachability, StaticEvidence, Trust
from ravel.scanners.normalize import LocatedFinding

log = get_logger("ravel.triage.reachability")


def _build_subgraphs(
    graph: nx.MultiDiGraph,
) -> tuple[nx.DiGraph, nx.DiGraph]:
    """Construct directed graphs for reachability traversal.

    Returns:
        (resolved_graph, full_graph):
        - ``resolved_graph``: contains only edges with ``resolved=True`` and
          excluding any ``unknown::`` nodes.
        - ``full_graph``: contains all edges (both resolved and unresolved).
    """
    resolved_g = nx.DiGraph()
    full_g = nx.DiGraph()

    # Add all nodes to full_g
    for node_id in graph.nodes:
        full_g.add_node(node_id)
        if not str(node_id).startswith("unknown::"):
            resolved_g.add_node(node_id)

    # Add edges
    for u, v, _k, data in graph.edges(keys=True, data=True):
        is_resolved = data.get("resolved", True)
        u_str, v_str = str(u), str(v)

        full_g.add_edge(u, v)

        if is_resolved and not u_str.startswith("unknown::") and not v_str.startswith("unknown::"):
            resolved_g.add_edge(u, v)

    return resolved_g, full_g


def evaluate_node_reachability(
    target_node_ids: list[str],
    untrusted_ep_ids: set[str],
    resolved_graph: nx.DiGraph,
    full_graph: nx.DiGraph,
) -> StaticEvidence:
    """Determine reachability, path, and blast radius for a set of target nodes."""
    # A finding with no node in the graph (non-Python file, unmapped, unused or
    # unknown dependency) has nothing to trace: unknown, never unreachable (§6).
    if not any(t in full_graph for t in target_node_ids):
        return StaticEvidence(
            reachable=Reachability.UNKNOWN,
            path=[],
            blast_radius=0,
        )

    if not untrusted_ep_ids:
        return StaticEvidence(
            reachable=Reachability.UNREACHABLE,
            path=[],
            blast_radius=0,
        )

    # 1. Check if any target node is directly an untrusted entry point
    for target in target_node_ids:
        if target in untrusted_ep_ids:
            return StaticEvidence(
                reachable=Reachability.REACHABLE,
                path=[target],
                blast_radius=1,
            )

    # 2. Search for fully resolved paths
    best_resolved_path: list[str] | None = None
    all_reaching_eps: set[str] = set()

    for target in target_node_ids:
        if target not in full_graph:
            continue
        for ep_id in untrusted_ep_ids:
            if ep_id not in full_graph:
                continue

            # Check full graph reachability for blast radius
            if nx.has_path(full_graph, ep_id, target):
                all_reaching_eps.add(ep_id)

            # Check resolved graph for clean reachable paths
            if (
                ep_id in resolved_graph
                and target in resolved_graph
                and nx.has_path(resolved_graph, ep_id, target)
            ):
                try:
                    path = nx.shortest_path(resolved_graph, ep_id, target)
                    if best_resolved_path is None or len(path) < len(best_resolved_path):
                        best_resolved_path = path
                except nx.NetworkXNoPath:
                    pass

    if best_resolved_path is not None:
        return StaticEvidence(
            reachable=Reachability.REACHABLE,
            path=best_resolved_path,
            blast_radius=len(all_reaching_eps),
        )

    # 3. If no resolved path, check for unresolved/unknown paths
    if all_reaching_eps:
        # Find shortest path in full_graph
        best_unknown_path: list[str] | None = None
        for target in target_node_ids:
            if target not in full_graph:
                continue
            for ep_id in all_reaching_eps:
                if ep_id in full_graph and nx.has_path(full_graph, ep_id, target):
                    try:
                        path = nx.shortest_path(full_graph, ep_id, target)
                        if best_unknown_path is None or len(path) < len(best_unknown_path):
                            best_unknown_path = path
                    except nx.NetworkXNoPath:
                        pass

        return StaticEvidence(
            reachable=Reachability.UNKNOWN,
            path=best_unknown_path or [],
            blast_radius=len(all_reaching_eps),
        )

    # 4. No path exists from any untrusted entry point
    return StaticEvidence(
        reachable=Reachability.UNREACHABLE,
        path=[],
        blast_radius=0,
    )


class Tracer(Protocol):
    def __call__(self, ids: list[str], *, imported: bool = False) -> StaticEvidence: ...


def reachability_tracer(graph_result: GraphResult) -> Tracer:
    """Trace any set of nodes back to the untrusted entry points.

    The same rules :func:`analyze_reachability` applies to findings, for
    callers that trace other things (the deps report traces the code that
    calls a deprecated API). The traversal graphs are built once.
    ``imported=True`` marks targets that *import* a package rather than call
    it — see :func:`_import_in_use`.
    """
    untrusted_eps = {ep.node_id for ep in graph_result.entry_points if ep.trust is Trust.UNTRUSTED}
    resolved_g, full_g = _build_subgraphs(graph_result.graph)
    file_ids = {n.file_path: n.id for n in graph_result.nodes if n.kind is NodeKind.FILE}
    # Per file, the defs in it that make at least one call we could not resolve.
    blind: dict[str, list[str]] = defaultdict(list)
    unresolved_callers = {
        e.src_id for e in graph_result.edges if e.kind is EdgeKind.CALLS and not e.resolved
    }
    for n in graph_result.nodes:
        if n.kind is not NodeKind.FILE and n.id in unresolved_callers and n.file_path in file_ids:
            blind[file_ids[n.file_path]].append(n.id)

    def trace(ids: list[str], *, imported: bool = False) -> StaticEvidence:
        # No entry points detected at all means detection found no way in, not
        # that there is none: "unreachable" would be a guess, so it is unknown.
        if not graph_result.entry_points:
            return StaticEvidence(reachable=Reachability.UNKNOWN, path=[], blast_radius=0)
        evidence = evaluate_node_reachability(ids, untrusted_eps, resolved_g, full_g)
        if not imported or evidence.reachable is not Reachability.UNREACHABLE:
            return evidence
        return _import_in_use(ids, blind, untrusted_eps, resolved_g, full_g) or evidence

    return trace


def _import_in_use(
    target_ids: list[str],
    blind: dict[str, list[str]],
    untrusted_eps: set[str],
    resolved_graph: nx.DiGraph,
    full_graph: nx.DiGraph,
) -> StaticEvidence | None:
    """A package imported by a module whose request-reachable code we can't fully see.

    A dependency finding is anchored on the files importing the package and
    on the functions with a *resolved* call into it. Nothing calls a file, so
    a file anchor is never on a traced path. That is right when every call in
    the file is resolved — we then know which functions use the package. But
    a call we could not resolve (every call into a package missing from the
    environment) may be a call into it; if a function making one is reached
    from untrusted input, "unreachable" would demote the advisory on missing
    evidence — the §6 failure mode. So it is ``unknown``, with the path to
    that function. Only a resolved call earns ``reachable``.
    """
    candidates = [m for t in target_ids for m in blind.get(t, [])]
    if not candidates:
        return None
    inner = evaluate_node_reachability(candidates, untrusted_eps, resolved_graph, full_graph)
    if inner.reachable is Reachability.UNREACHABLE:
        return None
    return StaticEvidence(
        reachable=Reachability.UNKNOWN, path=inner.path, blast_radius=inner.blast_radius
    )


def analyze_reachability[F: (Finding, LocatedFinding)](
    graph_result: GraphResult,
    findings: list[F],
) -> list[F]:
    """Compute reachability for every finding against the graph's entry points.

    Mutates and returns the input findings with ``static_evidence`` attached.
    Supports both ``LocatedFinding`` and raw ``Finding`` models.
    """
    trace = reachability_tracer(graph_result)
    if not graph_result.entry_points:
        log.warning("reachability: no entry points detected; all findings marked unknown")

    for item in findings:
        finding = item.finding if isinstance(item, LocatedFinding) else item

        # Identify target node IDs to trace
        target_ids: list[str] = []
        if isinstance(item, LocatedFinding):
            if item.node is not None:
                target_ids.append(item.node.id)
            elif item.anchors:
                target_ids.extend(n.id for n in item.anchors)
        elif finding.node_id:
            target_ids.append(finding.node_id)

        # A dependency finding's anchors are its importers (and callers).
        imported = isinstance(item, LocatedFinding) and item.node is None and bool(item.anchors)
        finding.static_evidence = trace(target_ids, imported=imported)

    reachable_count = 0
    unknown_count = 0
    unreachable_count = 0
    for item in findings:
        f = item.finding if isinstance(item, LocatedFinding) else item
        if f.static_evidence is not None:
            if f.static_evidence.reachable is Reachability.REACHABLE:
                reachable_count += 1
            elif f.static_evidence.reachable is Reachability.UNKNOWN:
                unknown_count += 1
            elif f.static_evidence.reachable is Reachability.UNREACHABLE:
                unreachable_count += 1

    log.info(
        "reachability: %d total findings -> %d reachable, %d unknown, %d unreachable",
        len(findings),
        reachable_count,
        unknown_count,
        unreachable_count,
    )

    return findings
