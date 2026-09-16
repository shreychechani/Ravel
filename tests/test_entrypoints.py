"""Entry-point detection tests (BUILD-PLAN §1).

Every HTTP route handler must surface as an ``untrusted`` entry point mapped to
its real function node — that mapping is what reachability (Phase 3) seeds its
back-trace from. Undecorated helpers must never be flagged. Fixtures are real
Flask/FastAPI apps, not synthetic strings (AGENTS.md §5).
"""

from __future__ import annotations

from pathlib import Path

from ravel.graph.resolve import GraphResult, build_graph
from ravel.models import EntryPointKind, NodeKind, Trust

FIXTURES = Path(__file__).parent.parent / "eval" / "fixtures"
FASTAPI = FIXTURES / "sample_app"
FLASK = FIXTURES / "flask_app"


def _handlers(result: GraphResult) -> set[tuple[str, EntryPointKind, Trust]]:
    """(handler_qname, kind, trust) for every detected entry point."""
    by_id = {n.id: n for n in result.nodes}
    return {(by_id[ep.node_id].qualified_name, ep.kind, ep.trust) for ep in result.entry_points}


def test_fastapi_routes_are_untrusted_entrypoints() -> None:
    handlers = _handlers(build_graph(FASTAPI))
    assert ("read_user", EntryPointKind.HTTP_ROUTE, Trust.UNTRUSTED) in handlers
    assert ("add_user", EntryPointKind.HTTP_ROUTE, Trust.UNTRUSTED) in handlers


def test_fastapi_has_exactly_the_two_routes() -> None:
    assert len(build_graph(FASTAPI).entry_points) == 2


def test_non_route_functions_are_not_entrypoints() -> None:
    qnames = {q for q, _, _ in _handlers(build_graph(FASTAPI))}
    assert "get_user" not in qnames  # called by a route, but not itself an entry point
    assert "create_user" not in qnames
    assert "slugify" not in qnames
    assert "UserService.find" not in qnames


def test_flask_route_shapes_all_detected() -> None:
    handlers = _handlers(build_graph(FLASK))
    qnames = {q for q, _, _ in handlers}
    assert qnames == {"index", "login", "health"}  # @app.route, methods=[...], @app.get
    assert all(k is EntryPointKind.HTTP_ROUTE and t is Trust.UNTRUSTED for _, k, t in handlers)


def test_undecorated_helper_is_not_an_entrypoint() -> None:
    qnames = {q for q, _, _ in _handlers(build_graph(FLASK))}
    assert "_helper" not in qnames


def test_entrypoints_map_to_real_function_nodes() -> None:
    result = build_graph(FLASK)
    by_id = {n.id: n for n in result.nodes}
    assert result.entry_points  # guard against a silently empty result
    for ep in result.entry_points:
        assert ep.node_id in by_id
        assert by_id[ep.node_id].kind is NodeKind.FUNCTION
