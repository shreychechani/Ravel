"""The JSON report carries the evidence a reviewer needs, on a real fixture."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from ravel.report import REPORT_VERSION, build_report
from ravel.scanners.run import scan_repo

SHOP = Path(__file__).parent.parent / "eval" / "fixtures" / "vuln_shop"


@pytest.fixture(scope="module")
def report() -> dict[str, Any]:
    return build_report(scan_repo(SHOP), SHOP)


def _by_node(report: dict[str, Any], name: str) -> dict[str, Any]:
    return next(f for f in report["findings"] if f["node_name"] == name)


def test_report_header_carries_coverage_and_entry_points(report: dict[str, Any]) -> None:
    assert report["report_version"] == REPORT_VERSION
    assert report["repo"] == "vuln_shop"
    assert 0.0 <= report["graph"]["coverage"]["ratio"] <= 1.0
    routes = {report["nodes"][ep["node_id"]]["name"] for ep in report["entry_points"]}
    assert routes == {"search", "search_safe", "ping", "load_cart"}
    assert all(ep["trust"] == "untrusted" for ep in report["entry_points"])


def test_reachable_finding_has_path_hops_code_and_callers(report: dict[str, Any]) -> None:
    sqli = _by_node(report, "find_product")
    assert sqli["static_evidence"]["reachable"] == "reachable"
    path = sqli["static_evidence"]["path"]
    assert [report["nodes"][n]["name"] for n in path] == ["search", "find_product"]
    assert sqli["path_hops"] == [
        {"src": path[0], "dst": path[1], "resolved": True, "kind": "calls"}
    ]
    assert any("SELECT" in line for line in sqli["code"]["lines"])
    assert sqli["code"]["highlight"][0] == sqli["line"]
    callers = {report["nodes"][c]["name"] for c in sqli["callers"]}
    assert callers == {"search"}  # the defining file (shop.db) is not a caller


def test_unreachable_finding_has_no_path(report: dict[str, Any]) -> None:
    backup = _by_node(report, "backup")
    assert backup["static_evidence"]["reachable"] == "unreachable"
    assert backup["path_hops"] == []


def test_every_referenced_node_is_labelled(report: dict[str, Any]) -> None:
    for f in report["findings"]:
        for nid in [*f["static_evidence"]["path"], *f["callers"], f["node_id"]]:
            assert nid in report["nodes"], nid


def test_graph_view_carries_the_whole_code_graph(report: dict[str, Any]) -> None:
    view = report["graph_view"]
    by_name = {n["name"]: n for n in view["nodes"]}
    assert {"search", "find_product", "backup", "shop.app"} <= set(by_name)
    assert by_name["search"]["entry_point"] and not by_name["find_product"]["entry_point"]
    assert by_name["find_product"]["worst_reach"] == "reachable"
    assert by_name["backup"]["worst_reach"] == "unreachable"
    assert by_name["find_product_safe"]["findings"] == []
    ids = {n["id"] for n in view["nodes"]}
    assert all(e["src"] in ids and e["dst"] in ids for e in view["edges"])
    calls = {(e["src"], e["dst"]) for e in view["edges"] if e["kind"] == "calls"}
    assert (by_name["search"]["id"], by_name["find_product"]["id"]) in calls
    # unresolved calls stay visible as unknown nodes, never dropped (§6)
    assert any(n["kind"] == "unknown" for n in view["nodes"])
    assert all(not e["resolved"] for e in view["edges"] if e["dst"].startswith("unknown::"))
