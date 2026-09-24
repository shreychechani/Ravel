"""Resolve call sites into a call graph — the Phase 1 quality bar.

tree-sitter finds *every* call site; Jedi resolves each callee to a real
definition with scope awareness. This replaces Arcflow's name+import heuristic
(BUILD-PLAN §1) — the biggest accuracy gap in that engine.

A call site is **resolved** if Jedi can say what it refers to: an internal
function/class (→ a ``calls`` edge), or a third-party / stdlib symbol
(→ an ``ExternalRef``). A call site Jedi cannot pin down is **not dropped** —
it becomes a ``calls`` edge to a ``unknown::<name>`` target with
``resolved=False`` (PRODUCT.md §6). Coverage = resolved / total call sites.

``imports`` edges (file → file) come from :mod:`ravel.graph.imports`.
``inherits`` edges (class → base) are resolved the same way; an unresolvable
base becomes an ``unknown::<name>`` inherits edge. Bases don't count toward
call coverage — that metric is call sites only.

Structural ``defines`` edges (file → top-level def, class → method, function →
nested def) come straight from the parse tree and are always resolved.

Note: tree-sitter columns are byte offsets, Jedi columns are character
offsets — identical for ASCII source; a known v1 caveat for non-ASCII.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jedi
import networkx as nx

from ravel.core.logging import get_logger
from ravel.graph.entrypoints import detect_entrypoints
from ravel.graph.imports import build_import_edges
from ravel.graph.parse import parse_file, parse_to_tree
from ravel.ingest.loader import SourceFile, discover
from ravel.models import Edge, EdgeKind, EntryPoint, ExternalRef, Node, NodeKind

log = get_logger("ravel.graph.resolve")

_CALLABLE_KINDS = {NodeKind.FUNCTION, NodeKind.CLASS}


@dataclass(frozen=True)
class CallSite:
    """One call expression: where its callee name sits, for Jedi to resolve."""

    line: int  # 1-based line of the callee name
    col: int  # 0-based column of the callee name; -1 => no resolvable position
    name: str  # callee text, e.g. "get_user" or "find"


@dataclass
class Coverage:
    """Call-resolution quality — reported as a first-class metric (PRODUCT.md §6)."""

    total: int = 0
    internal: int = 0  # resolved to an internal node (a calls edge)
    external: int = 0  # resolved to third-party / stdlib / builtin
    unresolved: int = 0  # Jedi could not determine the target

    @property
    def resolved(self) -> int:
        return self.internal + self.external

    @property
    def ratio(self) -> float:
        return self.resolved / self.total if self.total else 1.0


@dataclass
class GraphResult:
    """The built call graph plus everything the CLI and later phases consume."""

    graph: nx.MultiDiGraph  # keyed by edge kind: a pair can both call and define
    nodes: list[Node]
    edges: list[Edge]
    external_refs: list[ExternalRef] = field(default_factory=list)
    entry_points: list[EntryPoint] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)


def _pt(point: Any) -> tuple[int, int]:
    """tree-sitter Point → (row, column), supporting attr and index forms."""
    if hasattr(point, "row"):
        return int(point.row), int(point.column)
    return int(point[0]), int(point[1])


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _callee(fn: Any, data: bytes) -> tuple[int, int, str] | None:
    """Return (row, col, name) of the callee name, or None if unresolvable.

    Handles the two common callee shapes: a bare ``identifier`` (``foo()``)
    and an ``attribute`` (``obj.method()`` — we point Jedi at ``method``).
    """
    if fn.type == "identifier":
        row, col = _pt(fn.start_point)
        return row, col, _text(fn, data)
    if fn.type == "attribute":
        attr = fn.child_by_field_name("attribute")
        if attr is not None:
            row, col = _pt(attr.start_point)
            return row, col, _text(attr, data)
    return None


def _call_sites(source: SourceFile) -> list[CallSite]:
    """Walk the tree and collect every call expression in the file."""
    root, data = parse_to_tree(source)
    out: list[CallSite] = []

    def walk(node: Any) -> None:
        for child in node.named_children:
            if child.type == "call":
                fn = child.child_by_field_name("function")
                if fn is not None:
                    info = _callee(fn, data)
                    if info is None:
                        row, _ = _pt(fn.start_point)
                        out.append(CallSite(row + 1, -1, _text(fn, data)[:60]))
                    else:
                        row, col, name = info
                        out.append(CallSite(row + 1, col, name))
            walk(child)

    walk(root)
    return out


def _base_sites(source: SourceFile) -> list[tuple[int, CallSite]]:
    """``(class_def_line, base)`` for every base class expression in the file.

    ``Generic[T]`` resolves via its subscripted value; ``metaclass=`` and other
    keyword arguments are not bases. Anything else (e.g. ``make_base()``) gets
    ``col=-1`` and becomes an honest ``unknown`` edge.
    """
    root, data = parse_to_tree(source)
    out: list[tuple[int, CallSite]] = []

    def walk(node: Any) -> None:
        for child in node.named_children:
            if child.type == "class_definition":
                class_line = _pt(child.start_point)[0] + 1
                supers = child.child_by_field_name("superclasses")
                for base in supers.named_children if supers is not None else []:
                    if base.type == "keyword_argument":
                        continue
                    expr = base.child_by_field_name("value") if base.type == "subscript" else base
                    info = _callee(expr, data) if expr is not None else None
                    if info is None:
                        row, _ = _pt(base.start_point)
                        out.append((class_line, CallSite(row + 1, -1, _text(base, data)[:60])))
                    else:
                        row, col, name = info
                        out.append((class_line, CallSite(row + 1, col, name)))
            walk(child)

    walk(root)
    return out


def _goto(script: Any, site: CallSite, rel_path: str) -> list[Any]:
    """Jedi goto at a call/base site, following imports to the real definition."""
    try:
        return list(
            script.goto(site.line, site.col, follow_imports=True, follow_builtin_imports=True)
        )
    except Exception as exc:  # Jedi can raise on pathological positions
        log.debug("jedi goto failed at %s:%d: %s", rel_path, site.line, exc)
        return []


def _file_node(source: SourceFile) -> Node:
    """A FILE node so module-level call sites (decorators, ``x = f()``) have a home."""
    module = source.rel_path[:-3] if source.rel_path.endswith(".py") else source.rel_path
    module = module.replace("/", ".")
    if module.endswith(".__init__"):
        module = module[: -len(".__init__")]
    return Node(
        id=f"{source.rel_path}::<file>",
        kind=NodeKind.FILE,
        qualified_name=module or source.rel_path,
        file_path=source.rel_path,
        start_line=1,
        end_line=max(source.lines, 1),
        source_hash=source.content_hash,
    )


def _enclosing(nodes: list[Node], line: int, kinds: set[NodeKind]) -> Node | None:
    """Innermost node of ``kinds`` whose span contains ``line`` (latest start wins)."""
    best: Node | None = None
    for n in nodes:
        if (
            n.kind in kinds
            and n.start_line <= line <= n.end_line
            and (best is None or n.start_line > best.start_line)
        ):
            best = n
    return best


def _def_node(nodes: list[Node], line: int) -> Node | None:
    """Map a Jedi definition line back to our node (its def line == node start)."""
    for n in nodes:
        if n.start_line == line and n.kind in _CALLABLE_KINDS:
            return n
    return _enclosing(nodes, line, _CALLABLE_KINDS)


def _relpath(module_path: Any, root: Path) -> str | None:
    """Return the repo-relative POSIX path if ``module_path`` is inside ``root``."""
    if module_path is None:
        return None
    try:
        return Path(module_path).resolve().relative_to(root).as_posix()
    except (ValueError, OSError):
        return None


def build_graph(root: Path | str) -> GraphResult:
    """Discover, parse, and resolve a Python repo into a call graph."""
    root = Path(root).resolve()
    files = discover(root)

    nodes: list[Node] = []
    file_nodes: dict[str, Node] = {}
    nodes_by_file: dict[str, list[Node]] = defaultdict(list)
    for source in files:
        fnode = _file_node(source)
        file_nodes[source.rel_path] = fnode
        nodes.append(fnode)
        nodes_by_file[source.rel_path].append(fnode)
        for node in parse_file(source):
            nodes.append(node)
            nodes_by_file[source.rel_path].append(node)

    entry_points: list[EntryPoint] = []
    for source in files:
        entry_points.extend(detect_entrypoints(source, nodes_by_file[source.rel_path]))

    project = jedi.Project(str(root))
    edges: list[Edge] = [
        edge
        for rel, local in nodes_by_file.items()
        for edge in _defines_edges(local, file_nodes[rel])
    ]
    imports = build_import_edges(files, root)
    edges.extend(imports.edges)
    external_refs: list[ExternalRef] = list(imports.external_refs)
    cov = Coverage()

    for source in files:
        script = jedi.Script(code=source.content, path=str(source.path), project=project)
        local_nodes = nodes_by_file[source.rel_path]
        for site in _call_sites(source):
            cov.total += 1
            src_node = (
                _enclosing(local_nodes, site.line, {NodeKind.FUNCTION})
                or file_nodes[source.rel_path]
            )

            if site.col < 0:
                _add_unknown(edges, cov, src_node, site.name)
                continue

            defs = _goto(script, site, source.rel_path)
            if not defs:
                _add_unknown(edges, cov, src_node, site.name)
                continue

            definition = defs[0]
            rel = _relpath(definition.module_path, root)
            if rel is not None and rel in nodes_by_file:
                dst = _def_node(nodes_by_file[rel], definition.line or 0)
                if dst is not None:
                    cov.internal += 1
                    edges.append(Edge(src_id=src_node.id, dst_id=dst.id, kind=EdgeKind.CALLS))
                    continue
                # Internal but resolves to a non-callable (module var, alias): still
                # resolved, just no edge to draw.
                cov.external += 1
                continue

            # Third-party or stdlib — record the external reference.
            cov.external += 1
            package = (definition.module_name or "").split(".")[0]
            if package and not definition.in_builtin_module() and package != "builtins":
                external_refs.append(
                    ExternalRef(node_id=src_node.id, package=package, symbol=site.name)
                )

        for class_line, base in _base_sites(source):
            cls = next(
                (n for n in local_nodes if n.kind is NodeKind.CLASS and n.start_line == class_line),
                None,
            )
            if cls is None:
                continue
            defs = _goto(script, base, source.rel_path) if base.col >= 0 else []
            if not defs:
                edges.append(
                    Edge(
                        src_id=cls.id,
                        dst_id=f"unknown::{base.name}",
                        kind=EdgeKind.INHERITS,
                        resolved=False,
                    )
                )
                continue
            definition = defs[0]
            rel = _relpath(definition.module_path, root)
            if rel is not None and rel in nodes_by_file:
                dst = _def_node(nodes_by_file[rel], definition.line or 0)
                if dst is not None and dst.kind is NodeKind.CLASS:
                    edges.append(Edge(src_id=cls.id, dst_id=dst.id, kind=EdgeKind.INHERITS))
                continue
            package = (definition.module_name or "").split(".")[0]
            if package and not definition.in_builtin_module() and package != "builtins":
                external_refs.append(ExternalRef(node_id=cls.id, package=package, symbol=base.name))

    graph = nx.MultiDiGraph()
    for node in nodes:
        graph.add_node(node.id, kind=node.kind.value, qualified_name=node.qualified_name)
    for edge in edges:
        graph.add_edge(
            edge.src_id,
            edge.dst_id,
            key=edge.kind.value,
            kind=edge.kind.value,
            resolved=edge.resolved,
        )

    log.info(
        "graph: %d nodes, %d edges (%d resolved calls), %d entry points, coverage %.1f%%",
        len(nodes),
        len(edges),
        cov.internal,
        len(entry_points),
        cov.ratio * 100,
    )
    return GraphResult(
        graph=graph,
        nodes=nodes,
        edges=edges,
        external_refs=external_refs,
        entry_points=entry_points,
        coverage=cov,
    )


def _defines_edges(local: list[Node], file_node: Node) -> list[Edge]:
    """Structural containment edges for one file: parent → each def it contains.

    The parent is the def whose qualified name is the child's prefix and whose
    span encloses it (so same-named redefinitions don't cross-link); top-level
    defs hang off the FILE node.
    """
    out: list[Edge] = []
    for node in local:
        if node.kind not in _CALLABLE_KINDS:
            continue
        parent = file_node
        if "." in node.qualified_name:
            parent_qname = node.qualified_name.rsplit(".", 1)[0]
            parent = next(
                (
                    p
                    for p in local
                    if p.qualified_name == parent_qname
                    and p.kind in _CALLABLE_KINDS
                    and p.start_line <= node.start_line
                    and node.end_line <= p.end_line
                ),
                file_node,
            )
        out.append(Edge(src_id=parent.id, dst_id=node.id, kind=EdgeKind.DEFINES))
    return out


def _add_unknown(edges: list[Edge], cov: Coverage, src: Node, name: str) -> None:
    """Record an unresolved call as an honest ``unknown`` edge, never dropped."""
    cov.unresolved += 1
    edges.append(
        Edge(src_id=src.id, dst_id=f"unknown::{name}", kind=EdgeKind.CALLS, resolved=False)
    )
