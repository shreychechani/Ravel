"""Resolution tests — the Phase 1 quality bar (BUILD-PLAN §1).

The sample app has a hand-checkable call graph; we assert the resolver draws
exactly those in-repo edges, and that anything it cannot pin down is kept as an
``unknown`` edge rather than dropped (PRODUCT.md §6).
"""

from __future__ import annotations

from pathlib import Path

from ravel.graph.resolve import GraphResult, build_graph
from ravel.models import EdgeKind, NodeKind

FIXTURE = Path(__file__).parent.parent / "eval" / "fixtures" / "sample_app"


def _resolved_pairs(result: GraphResult, kind: EdgeKind = EdgeKind.CALLS) -> set[tuple[str, str]]:
    """(src_qname, dst_qname) for every resolved internal edge of ``kind``."""
    by_id = {n.id: n.qualified_name for n in result.nodes}
    return {
        (by_id[e.src_id], by_id[e.dst_id])
        for e in result.edges
        if e.kind is kind and e.resolved and e.src_id in by_id and e.dst_id in by_id
    }


def test_internal_call_edges_resolve_correctly() -> None:
    pairs = _resolved_pairs(build_graph(FIXTURE))
    assert ("read_user", "get_user") in pairs
    assert ("add_user", "create_user") in pairs
    assert ("create_user", "slugify") in pairs
    assert ("get_user", "UserService.find") in pairs
    assert ("get_user", "UserService") in pairs  # constructor call → class node


def test_all_in_repo_calls_resolve() -> None:
    # Every call to in-repo code resolves — internal resolution is exact here.
    assert build_graph(FIXTURE).coverage.internal == 5


def test_unresolved_calls_are_kept_not_dropped() -> None:
    unknown = [e for e in build_graph(FIXTURE).edges if not e.resolved]
    assert all(e.dst_id.startswith("unknown::") for e in unknown)
    assert all(e.kind in {EdgeKind.CALLS, EdgeKind.INHERITS} for e in unknown)


def test_coverage_accounting_is_consistent() -> None:
    cov = build_graph(FIXTURE).coverage
    assert cov.total == cov.internal + cov.external + cov.unresolved
    unknown = sum(
        1 for e in build_graph(FIXTURE).edges if e.kind is EdgeKind.CALLS and not e.resolved
    )
    assert unknown == cov.unresolved
    assert 0.0 <= cov.ratio <= 1.0


def test_file_nodes_exist_for_every_source() -> None:
    files = [n for n in build_graph(FIXTURE).nodes if n.kind is NodeKind.FILE]
    assert {n.file_path for n in files} == {
        "__init__.py",
        "app.py",
        "services.py",
        "utils.py",
    }


def test_dead_function_has_no_incoming_edge() -> None:
    result = build_graph(FIXTURE)
    by_id = {n.id: n for n in result.nodes}
    helper = next(n for n in result.nodes if n.qualified_name == "unused_helper")
    incoming = [e for e in result.edges if e.dst_id == helper.id and e.kind is EdgeKind.CALLS]
    assert incoming == []  # never called — a dead-code candidate for later phases
    assert helper.id in by_id


def test_defines_edges_follow_containment() -> None:
    pairs = _resolved_pairs(build_graph(FIXTURE), EdgeKind.DEFINES)
    assert pairs == {
        ("app", "UserIn"),
        ("app", "UserNotFound"),
        ("app", "read_user"),
        ("app", "add_user"),
        ("services", "UserService"),
        ("services", "AdminService"),
        ("UserService", "UserService.find"),
        ("services", "get_user"),
        ("services", "create_user"),
        ("utils", "slugify"),
        ("utils", "unused_helper"),
    }


def test_every_def_has_exactly_one_parent() -> None:
    result = build_graph(FIXTURE)
    defines = [e for e in result.edges if e.kind is EdgeKind.DEFINES]
    defs = [n for n in result.nodes if n.kind is not NodeKind.FILE]
    assert sorted(e.dst_id for e in defines) == sorted(n.id for n in defs)


def test_calls_and_defines_coexist_in_graph() -> None:
    result = build_graph(FIXTURE)
    kinds = {k for _, _, k in result.graph.edges(keys=True)}
    assert {EdgeKind.CALLS.value, EdgeKind.DEFINES.value} <= kinds


def test_internal_base_class_is_an_inherits_edge() -> None:
    pairs = _resolved_pairs(build_graph(FIXTURE), EdgeKind.INHERITS)
    assert pairs == {("AdminService", "UserService")}


def test_third_party_base_class_is_an_external_ref() -> None:
    result = build_graph(FIXTURE)
    by_id = {n.id: n.qualified_name for n in result.nodes}
    refs = {(by_id[r.node_id], r.package, r.symbol) for r in result.external_refs}
    assert ("UserIn", "pydantic", "BaseModel") in refs


def test_unresolvable_base_class_is_kept_as_unknown() -> None:
    # fastapi is not installed in Ravel's env, so Jedi cannot see HTTPException —
    # the base must survive as an unknown inherits edge, not vanish (PRODUCT.md §6).
    result = build_graph(FIXTURE)
    by_id = {n.id: n.qualified_name for n in result.nodes}
    unknown = {
        (by_id[e.src_id], e.dst_id)
        for e in result.edges
        if e.kind is EdgeKind.INHERITS and not e.resolved
    }
    assert unknown == {("UserNotFound", "unknown::HTTPException")}


def test_base_classes_do_not_count_as_call_sites() -> None:
    cov = build_graph(FIXTURE).coverage
    unknown_calls = [
        e for e in build_graph(FIXTURE).edges if e.kind is EdgeKind.CALLS and not e.resolved
    ]
    assert cov.unresolved == len(unknown_calls)
