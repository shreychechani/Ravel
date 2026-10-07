"""Assemble deep graph context for reachability-filtered findings (PRODUCT.md §3, §8).

Provides the LLM with:
1. Flagged code snippet (the target function/class/line).
2. Traced reachability path from the untrusted entry point to the target.
3. In-repo callers of the target node.
4. Module context / docstring.

Also generates the deterministic ``context_hash`` (SHA-256) of the assembled context,
which acts as the cache key primitive per PRODUCT.md §8.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ravel.core.hashing import content_hash
from ravel.graph.resolve import GraphResult
from ravel.models import Finding, Node, NodeKind
from ravel.scanners.normalize import LocatedFinding


@dataclass(frozen=True)
class AssembledContext:
    """Complete graph and source context assembled for one finding."""

    finding_id: str
    scanner: str
    rule_id: str
    cwe: str | None
    severity: str
    message: str
    target_node_name: str
    target_code: str
    traced_path: list[str]
    callers: list[str]
    module_docstring: str | None
    canonical_text: str
    context_hash: str


def _get_node_source(root: Path, file_path: str, start_line: int, end_line: int) -> str:
    """Extract source lines for a node from disk."""
    full_path = root / file_path
    try:
        lines = full_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    start = max(0, start_line - 1)
    end = min(len(lines), end_line)
    return "\n".join(lines[start:end])


def assemble_finding_context(
    finding: LocatedFinding | Finding,
    graph_result: GraphResult,
    root: Path | str,
) -> AssembledContext:
    """Extract code, trace path, callers, and docstring to form assembled context."""
    root_path = Path(root).resolve()
    actual_finding = finding.finding if isinstance(finding, LocatedFinding) else finding
    raw = finding.raw if isinstance(finding, LocatedFinding) else None

    nodes_by_id = {n.id: n for n in graph_result.nodes}
    target_node: Node | None = None

    if isinstance(finding, LocatedFinding) and finding.node is not None:
        target_node = finding.node
    elif actual_finding.node_id and actual_finding.node_id in nodes_by_id:
        target_node = nodes_by_id[actual_finding.node_id]

    target_name = target_node.qualified_name if target_node else "module_level"
    target_code = ""
    module_docstring: str | None = None

    if target_node is not None:
        if target_node.kind is NodeKind.FILE:
            # File/module level finding: extract small window around flagged line if known
            line = raw.line if raw else target_node.start_line
            target_code = _get_node_source(
                root_path, target_node.file_path, max(1, line - 5), line + 5
            )
        else:
            target_code = _get_node_source(
                root_path,
                target_node.file_path,
                target_node.start_line,
                target_node.end_line,
            )
        # Find file node for module docstring
        file_node_id = f"{target_node.file_path}::<file>"
        if file_node_id in nodes_by_id:
            module_docstring = nodes_by_id[file_node_id].docstring
    elif isinstance(finding, LocatedFinding) and finding.anchors:
        # Package finding: summarize anchors
        anchor_names = [a.qualified_name for a in finding.anchors]
        target_name = f"package:{raw.package if raw else 'unknown'}"
        target_code = "# Imported by:\n" + "\n".join(f"#  - {a}" for a in anchor_names)

    # Reconstruct path descriptions
    path_nodes: list[str] = []
    if actual_finding.static_evidence and actual_finding.static_evidence.path:
        for nid in actual_finding.static_evidence.path:
            if nid in nodes_by_id:
                n = nodes_by_id[nid]
                path_nodes.append(f"{n.qualified_name} ({n.file_path}:{n.start_line})")
            else:
                path_nodes.append(nid)

    # In-repo callers
    callers: list[str] = []
    if target_node and target_node.id in graph_result.graph:
        for pred in graph_result.graph.predecessors(target_node.id):
            if pred in nodes_by_id:
                pn = nodes_by_id[pred]
                callers.append(f"{pn.qualified_name} ({pn.file_path}:{pn.start_line})")

    cwe_str = actual_finding.cwe or "None"
    parts: list[str] = [
        f"FINDING: {actual_finding.source.value} | {actual_finding.rule_id} | CWE: {cwe_str}",
        f"SEVERITY: {actual_finding.raw_severity}",
        f"MESSAGE: {raw.message if raw else ''}",
        f"TARGET: {target_name}",
        f"CODE:\n{target_code.strip()}",
        "TRACED_PATH:\n"
        + ("\n".join(f"  -> {p}" for p in path_nodes) if path_nodes else "  (none)"),
        "CALLERS:\n" + ("\n".join(f"  - {c}" for c in callers) if callers else "  (none)"),
        f"MODULE_DOCSTRING:\n{module_docstring or '(none)'}",
    ]
    canonical_text = "\n\n".join(parts)
    ctx_hash = content_hash(canonical_text)

    return AssembledContext(
        finding_id=actual_finding.id,
        scanner=actual_finding.source.value,
        rule_id=actual_finding.rule_id,
        cwe=actual_finding.cwe,
        severity=actual_finding.raw_severity,
        message=raw.message if raw else "",
        target_node_name=target_name,
        target_code=target_code,
        traced_path=path_nodes,
        callers=callers,
        module_docstring=module_docstring,
        canonical_text=canonical_text,
        context_hash=ctx_hash,
    )
