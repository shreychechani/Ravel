"""``ravel serve``'s API, against a real scan of the planted-bug fixture."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from ravel.api.server import ReportStore, ScanSettings, Workspace, create_app, load_report
from ravel.report import build_report
from ravel.scanners.bandit import BanditScanner
from ravel.scanners.run import scan_repo
from ravel.triage.provider import MockProvider, TokenBudget

SHOP = Path(__file__).parent.parent / "eval" / "fixtures" / "vuln_shop"


def _scan(triage: bool) -> dict[str, Any]:
    budget = TokenBudget() if triage else None
    report = scan_repo(
        SHOP, triage_provider=MockProvider() if triage else None, token_budget=budget
    )
    return build_report(report, SHOP, budget)


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app(ReportStore(scan=_scan)))


def test_report_endpoint_serves_the_scan(client: TestClient) -> None:
    data = client.get("/api/report").json()
    assert data["repo"] == "vuln_shop"
    reach = {f["static_evidence"]["reachable"] for f in data["findings"]}
    assert reach == {"reachable", "unreachable"}
    assert "triage_stats" not in data  # first scan has no triage


def test_rescan_with_triage_judges_only_survivors(client: TestClient) -> None:
    data = client.post("/api/scan", json={"triage": True}).json()
    stats = data["triage_stats"]
    assert stats["survivors_evaluated"] == 3  # the three reachable findings
    assert stats["unreachable_skipped"] == 5
    health = client.get("/api/health").json()
    assert health["ok"] and health["can_rescan"] and not health["can_open"]


def test_report_file_mode_refuses_rescan(tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(_scan(False)), encoding="utf-8")
    client = TestClient(create_app(ReportStore(report=load_report(path))))
    assert client.get("/api/report").json()["repo"] == "vuln_shop"
    assert client.post("/api/scan", json={"triage": False}).status_code == 409


def test_not_a_report_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "other.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="not a Ravel scan report"):
        load_report(path)


def test_serves_built_ui_or_explains_how_to_build_it(tmp_path: Path) -> None:
    store = ReportStore(report={"findings": []})
    bare = TestClient(create_app(store, ui_dir=tmp_path / "missing"))
    assert "npm --prefix web run build" in bare.get("/").text
    (tmp_path / "index.html").write_text("<p>ravel ui</p>", encoding="utf-8")
    built = TestClient(create_app(store, ui_dir=tmp_path))
    assert "ravel ui" in built.get("/").text


def _workspace_client() -> TestClient:
    workspace = Workspace(ScanSettings(scanners=[BanditScanner()]))
    return TestClient(create_app(ReportStore(workspace=workspace)))


def test_page_can_open_a_repo_typed_by_the_user() -> None:
    client = _workspace_client()
    assert client.get("/api/report").status_code == 404  # nothing opened yet
    assert client.get("/api/health").json()["can_open"] is True

    opened = client.post("/api/open", json={"target": str(SHOP)})
    assert opened.status_code == 200, opened.text
    data = opened.json()
    assert data["target"] == str(SHOP) and data["repo"] == "vuln_shop"
    assert client.get("/api/health").json()["target"] == str(SHOP)
    assert client.post("/api/scan", json={"triage": False}).status_code == 200


def test_open_reports_bad_targets_as_400() -> None:
    client = _workspace_client()
    bad = client.post("/api/open", json={"target": "/no/such/folder"})
    assert bad.status_code == 400
    assert "not a directory or a git URL" in bad.json()["detail"]
    ref = client.post("/api/open", json={"target": str(SHOP), "ref": "main"})
    assert ref.status_code == 400


def test_write_endpoints_take_json_only() -> None:
    client = _workspace_client()
    form = client.post(
        "/api/open", content=f"target={SHOP}", headers={"content-type": "text/plain"}
    )
    assert form.status_code in (415, 422)
