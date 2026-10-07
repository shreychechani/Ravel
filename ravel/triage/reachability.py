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

import networkx as nx

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult
from ravel.models import Finding, Reachability, StaticEvidence, Trust
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


def analyze_reachability[F: (Finding, LocatedFinding)](
    graph_result: GraphResult,
    findings: list[F],
) -> list[F]:
    """Compute reachability for every finding against the graph's entry points.

    Mutates and returns the input findings with ``static_evidence`` attached.
    Supports both ``LocatedFinding`` and raw ``Finding`` models.
    """
    untrusted_eps = {ep.node_id for ep in graph_result.entry_points if ep.trust is Trust.UNTRUSTED}

    resolved_g, full_g = _build_subgraphs(graph_result.graph)

    # No entry points detected at all means detection found no way in, not that
    # there is none: "unreachable" would then be a guess, so everything is unknown.
    no_entry_points = not graph_result.entry_points
    if no_entry_points:
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

        if no_entry_points:
            evidence = StaticEvidence(reachable=Reachability.UNKNOWN, path=[], blast_radius=0)
        else:
            evidence = evaluate_node_reachability(target_ids, untrusted_eps, resolved_g, full_g)
        finding.static_evidence = evidence

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
