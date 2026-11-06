"""Selective reachability path invalidation for incremental updates.

Per PRODUCT.md §8 and research/02:
- Path check: Invalidate any finding whose stored path contains a dirty node.
- Edge check: Invalidate paths when a new edge into the path appears.
- Untouched paths: 100% reuse of reachability classification, blast radius, and triage.
"""

from __future__ import annotations

from dataclasses import dataclass

from ravel.core.logging import get_logger
from ravel.graph.resolve import GraphResult
from ravel.incremental.ast_diff import NodeDiffResult
from ravel.models import NodeKind, Reachability
from ravel.scanners.normalize import LocatedFinding
from ravel.triage.reachability import reachability_tracer

log = get_logger("ravel.incremental.invalidation")


@dataclass
class IncrementalReachabilityResult:
    """Outcome of incremental reachability evaluation."""

    findings: list[LocatedFinding]
    reused_count: int = 0
    invalidated_count: int = 0
    new_count: int = 0


def should_invalidate_path(
    path: list[str],
    dirty_node_ids: set[str],
    new_edges_by_dst: dict[str, list[str]],
) -> bool:
    """Check if an execution path has been invalidated by code or edge modifications."""
    if not path:
        return True

    # 1. Check if any node on the path is dirty
    for node_id in path:
        if node_id in dirty_node_ids:
            return True

    # 2. Check if a newly added edge enters this path from outside
    path_nodes = set(path)
    for node_id in path:
        incoming_sources = new_edges_by_dst.get(node_id, [])
        for src in incoming_sources:
            if src not in path_nodes:
                return True  # New external edge entered the path

    return False


def update_reachability_incrementally(
    graph: GraphResult,
    previous_findings: list[LocatedFinding],
    diff: NodeDiffResult,
    new_findings: list[LocatedFinding] | None = None,
) -> IncrementalReachabilityResult:
    """Selectively re-evaluate reachability only for invalidated paths and new findings."""
    trace = reachability_tracer(graph)
    dirty_node_ids = set(diff.dirty_node_ids)
    deleted_ids = {n.id for n in diff.deleted_nodes}

    # Track incoming new edges by destination node
    new_edges_by_dst: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.src_id in dirty_node_ids:
            new_edges_by_dst.setdefault(edge.dst_id, []).append(edge.src_id)

    dirty_files = {
        n.file_path for n in [*diff.modified_nodes, *diff.added_nodes] if n.kind is NodeKind.FILE
    }
    reused: list[LocatedFinding] = []
    to_recalculate: list[LocatedFinding] = []

    # 1. Process previous findings
    for lf in previous_findings:
        # If the file was rescanned, new_findings replaces the old findings for this file
        if new_findings is not None and lf.raw.rel_path in dirty_files:
            continue

        f = lf.finding
        curr_node_id = f.node_id or (lf.node.id if lf.node else None)

        if not curr_node_id:
            to_recalculate.append(lf)
            continue

        # Remap node_id if renamed
        mapped_node_id = diff.rename_map.get(curr_node_id, curr_node_id)
        if mapped_node_id in deleted_ids:
            # Finding code was deleted in this revision
            continue

        f.node_id = mapped_node_id
        if lf.node and lf.node.id in diff.rename_map:
            # Replaced with renamed node
            new_node_id = diff.rename_map[lf.node.id]
            for n in graph.nodes:
                if n.id == new_node_id:
                    lf = LocatedFinding(
                        finding=f,
                        raw=lf.raw,
                        node=n,
                        anchors=lf.anchors,
                        via=lf.via,
                    )
                    break

        ev = f.static_evidence
        if ev is None:
            to_recalculate.append(lf)
            continue

        if ev.reachable is Reachability.UNREACHABLE:
            # Unreachable findings have path=[].
            # Only invalidate if the node itself is dirty or has new incoming edges
            if mapped_node_id in dirty_node_ids or mapped_node_id in new_edges_by_dst:
                to_recalculate.append(lf)
            else:
                reused.append(lf)
            continue

        # Remap path node IDs for REACHABLE and UNKNOWN findings
        remapped_path = [diff.rename_map.get(nid, nid) for nid in ev.path]
        ev.path = remapped_path

        if should_invalidate_path(remapped_path, dirty_node_ids, new_edges_by_dst):
            to_recalculate.append(lf)
        else:
            reused.append(lf)

    # 2. Add newly discovered findings from changed code
    if new_findings:
        to_recalculate.extend(new_findings)

    # 3. Recalculate reachability only for invalidated/new findings
    for lf in to_recalculate:
        f = lf.finding
        target_ids: list[str] = []
        if lf.node is not None:
            target_ids.append(lf.node.id)
        elif lf.anchors:
            target_ids.extend(n.id for n in lf.anchors)
        elif f.node_id:
            target_ids.append(f.node_id)

        imported = lf.node is None and bool(lf.anchors)
        f.static_evidence = trace(target_ids, imported=imported)

    all_findings = [*reused, *to_recalculate]
    log.info(
        "incremental reachability: %d reused (%.1f%%), %d re-evaluated, %d total",
        len(reused),
        (len(reused) / len(all_findings) * 100) if all_findings else 0.0,
        len(to_recalculate),
        len(all_findings),
    )

    return IncrementalReachabilityResult(
        findings=all_findings,
        reused_count=len(reused),
        invalidated_count=len(to_recalculate) - len(new_findings or []),
        new_count=len(new_findings or []),
    )
