"""Graph splicing and selective edge reconstruction for incremental updates.

Per PRODUCT.md §8:
- Unchanged hash -> retain edges and node metadata.
- Renamed node -> remap edge endpoints using rename_map.
- Changed/Added hash -> rebuild edges only for dirty files.
"""

from __future__ import annotations

from collections import defaultdict
from functools import partial
from pathlib import Path

import jedi
import networkx as nx

from ravel.core.logging import get_logger
from ravel.graph.entrypoints import detect_entrypoints
from ravel.graph.environment import discover_env, jedi_sys_path
from ravel.graph.resolve import (
    _DYNAMIC_EXEC,
    Coverage,
    GraphResult,
    _add_unknown,
    _call_sites,
    _def_node,
    _defines_edges,
    _enclosing,
    _relpath,
    _target,
)
from ravel.incremental.ast_diff import NodeDiffResult, load_single_source
from ravel.ingest.loader import SourceFile
from ravel.models import Edge, EdgeKind, EntryPoint, ExternalRef, Node, NodeKind

log = get_logger("ravel.incremental.splicing")


def splice_graph(
    repo_root: Path | str,
    old_graph: GraphResult,
    diff: NodeDiffResult,
    venv: Path | None = None,
) -> GraphResult:
    """Incrementally update an existing GraphResult with new/modified nodes and edges."""
    root = Path(repo_root).resolve()
    env = discover_env(root, venv or old_graph.environment.venv)

    # 1. Assemble the updated node set
    all_nodes: list[Node] = [
        *diff.unchanged_nodes,
        *diff.modified_nodes,
        *diff.added_nodes,
    ]
    node_by_id: dict[str, Node] = {n.id: n for n in all_nodes}
    nodes_by_file: dict[str, list[Node]] = defaultdict(list)
    file_nodes: dict[str, Node] = {}
    for n in all_nodes:
        nodes_by_file[n.file_path].append(n)
        if n.kind is NodeKind.FILE:
            file_nodes[n.file_path] = n

    # 2. Retain and remap existing edges from untouched subgraphs
    dirty_ids = set(diff.dirty_node_ids)
    deleted_ids = {n.id for n in diff.deleted_nodes}
    retained_edges: list[Edge] = []

    for edge in old_graph.edges:
        # Remap IDs first if endpoints were renamed
        src = diff.rename_map.get(edge.src_id, edge.src_id)
        dst = diff.rename_map.get(edge.dst_id, edge.dst_id)

        # Skip if either endpoint was deleted and not renamed
        if src in deleted_ids or dst in deleted_ids:
            continue

        # Skip if either endpoint is dirty (modified/added) and was not a pure rename
        if (src in dirty_ids and edge.src_id not in diff.rename_map) or (
            dst in dirty_ids and edge.dst_id not in diff.rename_map
        ):
            continue

        retained_edges.append(
            Edge(src_id=src, dst_id=dst, kind=edge.kind, resolved=edge.resolved)
        )

    # 3. Retain external refs and entry points from untouched files
    dirty_files = {n.file_path for n in [*diff.modified_nodes, *diff.added_nodes]}
    retained_refs: list[ExternalRef] = []
    for ref in old_graph.external_refs:
        mapped_node = diff.rename_map.get(ref.node_id, ref.node_id)
        if mapped_node in node_by_id and node_by_id[mapped_node].file_path not in dirty_files:
            if mapped_node != ref.node_id:
                retained_refs.append(
                    ExternalRef(
                        node_id=mapped_node,
                        package=ref.package,
                        version=ref.version,
                        symbol=ref.symbol,
                    )
                )
            else:
                retained_refs.append(ref)

    retained_eps: list[EntryPoint] = []
    for ep in old_graph.entry_points:
        mapped_node = diff.rename_map.get(ep.node_id, ep.node_id)
        if mapped_node in node_by_id and node_by_id[mapped_node].file_path not in dirty_files:
            retained_eps.append(EntryPoint(node_id=mapped_node, kind=ep.kind, trust=ep.trust))

    # 4. Resolve edges and entry points for dirty/modified/added files ONLY
    project = jedi.Project(str(root), sys_path=jedi_sys_path(env))
    new_edges: list[Edge] = list(retained_edges)
    new_refs: list[ExternalRef] = list(retained_refs)
    new_eps: list[EntryPoint] = list(retained_eps)
    cov = Coverage(
        total=old_graph.coverage.total,
        internal=old_graph.coverage.internal,
        external=old_graph.coverage.external,
        unresolved=old_graph.coverage.unresolved,
    )

    dirty_sources: list[SourceFile] = []
    for fpath in dirty_files:
        source_file = load_single_source(root, fpath)
        if source_file is not None:
            dirty_sources.append(source_file)

    for source in dirty_sources:
        local = nodes_by_file[source.rel_path]
        fn = file_nodes.get(source.rel_path)
        if fn is not None:
            new_edges.extend(_defines_edges(local, fn))
        new_eps.extend(detect_entrypoints(source, local))

        script = partial(jedi.Script, code=source.content, path=str(source.path), project=project)
        for site in _call_sites(source):
            definition = None
            if site.kind == "raise":
                definition = _target(script, site, source.rel_path, root)
                if definition is None or definition.type != "class":
                    continue
            src_node = (
                _enclosing(local, site.line, {NodeKind.FUNCTION})
                or file_nodes.get(source.rel_path)
            )
            if src_node is None:
                continue

            if site.col < 0:
                _add_unknown(new_edges, cov, src_node, site.name)
                continue

            definition = definition or _target(script, site, source.rel_path, root)
            if definition is None or (
                definition.name in _DYNAMIC_EXEC and definition.in_builtin_module()
            ):
                _add_unknown(new_edges, cov, src_node, site.name)
                continue

            rel = _relpath(definition.module_path, root)
            if rel is not None and rel in nodes_by_file:
                target_node = _def_node(nodes_by_file[rel], definition)
                if target_node is not None:
                    new_edges.append(Edge(src_id=src_node.id, dst_id=target_node.id, kind=EdgeKind.CALLS))
                    continue
                continue

            package = (definition.module_name or "").split(".")[0]
            if package and not definition.in_builtin_module() and package != "builtins":
                new_refs.append(ExternalRef(node_id=src_node.id, package=package, symbol=site.name))

    # 5. Build NetworkX graph
    g = nx.MultiDiGraph()
    for n in all_nodes:
        g.add_node(n.id, kind=n.kind, file_path=n.file_path, qname=n.qualified_name)
    for e in new_edges:
        g.add_edge(e.src_id, e.dst_id, kind=e.kind, resolved=e.resolved)

    return GraphResult(
        graph=g,
        nodes=all_nodes,
        edges=new_edges,
        external_refs=new_refs,
        entry_points=new_eps,
        coverage=cov,
        environment=env,
    )
