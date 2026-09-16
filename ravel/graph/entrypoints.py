"""Detect HTTP-route entry points — where untrusted input enters the graph.

Reachability (Phase 3) traces a finding back to an **untrusted** entry point;
this module is what marks those entry points. We port the framework route
knowledge from ``reference/Arcflow/js/analysis/parser-routes.js`` (its Python
FastAPI/Flask patterns) but replace its line-by-line regex with tree-sitter:
we look at the *decorator* on each function definition, so ``@app.get("/x")`` /
``@router.post(...)`` / ``@bp.route(..., methods=[...])`` are matched
structurally rather than by string shape.

**Trust classification.** Every HTTP route is ``untrusted``: it accepts input
from outside the system. We deliberately do *not* port the reference's
``authProtected`` down-grade — an authenticated endpoint is still reachable by
an authenticated attacker, so treating auth as "trusted" would silently demote
real vulnerabilities, the worst failure mode we have (PRODUCT.md §6). Auth is a
finding attribute, never a reason to stop tracing.

Scope (v1): decorator-based frameworks (FastAPI, Flask). Django ``urlpatterns``
maps a route to a view *by reference*, needing cross-module resolution — a
separate increment.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ravel.core.logging import get_logger
from ravel.graph.parse import parse_to_tree
from ravel.ingest.loader import SourceFile
from ravel.models import EntryPoint, EntryPointKind, Node, NodeKind, Trust

log = get_logger("ravel.graph.entrypoints")

# Decorator attribute names that denote an HTTP route handler. ``route`` is
# Flask's generic form; the verbs are FastAPI's and Flask 2.0+'s shorthands.
# Ported from parser-routes.js (Python branch); ``websocket`` added for FastAPI.
ROUTE_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "head", "options", "trace", "route", "websocket"}
)


@dataclass(frozen=True)
class _RouteHit:
    """A route decorator matched on a function def — pre node-mapping."""

    def_line: int  # 1-based line of the handler's ``def`` (== its Node.start_line)
    handler: str  # function name, for logging
    method: str  # decorator verb, e.g. "get" / "route"
    path: str | None  # first string arg of the decorator, if any


def _row(point: Any) -> int:
    return int(point.row) if hasattr(point, "row") else int(point[0])


def _text(node: Any, data: bytes) -> str:
    return data[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _first_string_arg(call: Any, data: bytes) -> str | None:
    """The literal value of a call's first string argument (the route path)."""
    args = call.child_by_field_name("arguments")
    if args is None:
        return None
    for arg in args.named_children:
        if arg.type == "string":
            raw = _text(arg, data)
            return raw.strip("\"'")
        # A route path is positional-first; stop at the first non-string arg.
        return None
    return None


def _decorator_method(decorator: Any, data: bytes) -> tuple[str, Any] | None:
    """If ``decorator`` is ``@<obj>.<verb>(...)``, return ``(verb, call_node)``.

    Route decorators are always *called* (``@app.get("/x")``), so we require a
    ``call`` whose function is an attribute access — this excludes bare
    decorators (``@login_required``) and property forms (``@x.setter``).
    """
    for child in decorator.named_children:
        if child.type != "call":
            continue
        fn = child.child_by_field_name("function")
        if fn is not None and fn.type == "attribute":
            attr = fn.child_by_field_name("attribute")
            if attr is not None:
                return _text(attr, data).lower(), child
    return None


def _route_hits(root: Any, data: bytes) -> list[_RouteHit]:
    """Every function definition carrying an HTTP-route decorator, in file order."""
    hits: list[_RouteHit] = []

    def walk(node: Any) -> None:
        for child in node.named_children:
            if child.type == "decorated_definition":
                _collect(child, data, hits)
            walk(child)

    walk(root)
    return hits


def _collect(dec_def: Any, data: bytes, hits: list[_RouteHit]) -> None:
    definition = dec_def.child_by_field_name("definition")
    if definition is None or definition.type != "function_definition":
        return  # class-based views resolve differently — out of scope for v1
    name_node = definition.child_by_field_name("name")
    if name_node is None:
        return
    handler = _text(name_node, data)
    def_line = _row(definition.start_point) + 1

    for child in dec_def.named_children:
        if child.type != "decorator":
            continue
        matched = _decorator_method(child, data)
        if matched is None:
            continue
        method, call = matched
        if method in ROUTE_METHODS:
            hits.append(
                _RouteHit(def_line, handler, method, _first_string_arg(call, data))
            )


def detect_entrypoints(source: SourceFile, file_nodes: list[Node]) -> list[EntryPoint]:
    """Find HTTP-route entry points in one file, mapped to their handler nodes.

    ``file_nodes`` is that file's parsed nodes; each route handler is matched to
    its function node by def-line (a handler's ``def`` line is its node's
    ``start_line``). A route whose handler node is missing is logged, not
    silently dropped — an unmapped entry point can't seed a reachability trace.
    """
    root, data = parse_to_tree(source)
    func_by_line = {n.start_line: n for n in file_nodes if n.kind is NodeKind.FUNCTION}

    entry_points: list[EntryPoint] = []
    seen: set[str] = set()
    for hit in _route_hits(root, data):
        node = func_by_line.get(hit.def_line)
        if node is None:
            log.debug(
                "route handler not mapped to a node: %s %s at %s:%d",
                hit.method,
                hit.path or "?",
                source.rel_path,
                hit.def_line,
            )
            continue
        if node.id in seen:  # multiple route decorators on one handler → one entry point
            continue
        seen.add(node.id)
        entry_points.append(
            EntryPoint(
                node_id=node.id,
                kind=EntryPointKind.HTTP_ROUTE,
                trust=Trust.UNTRUSTED,
            )
        )
    return entry_points
