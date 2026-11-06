"""End-to-end integration test suite for incremental updates (Phase 5)."""

from __future__ import annotations

from pathlib import Path

from git import Repo
from ravel.models import Reachability
from ravel.scanners.run import scan_repo, scan_repo_incremental


def test_incremental_workflow_end_to_end(tmp_path: Path) -> None:
    repo = Repo.init(tmp_path)
    repo.git.config("user.email", "tester@ravel.dev")
    repo.git.config("user.name", "Ravel Tester")

    # Commit 1: Initial vulnerable app
    # route_fn calls vulnerable_sink -> REACHABLE
    # helper.py has isolated finding -> UNREACHABLE (untouched baseline)
    routes_py = tmp_path / "routes.py"
    routes_py.write_text(
        "from fastapi import FastAPI\n"
        "from service import vulnerable_sink\n"
        "\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/vuln')\n"
        "def route_fn():\n"
        "    return vulnerable_sink()\n",
        encoding="utf-8",
    )
    service_py = tmp_path / "service.py"
    service_py.write_text(
        "def vulnerable_sink():\n    assert False, 'vulnerability trigger'\n",
        encoding="utf-8",
    )
    helper_py = tmp_path / "helper.py"
    helper_py.write_text(
        "def untouched_helper():\n    assert False, 'isolated helper assert'\n",
        encoding="utf-8",
    )
    (tmp_path / "__init__.py").touch()
    repo.index.add(["routes.py", "service.py", "helper.py", "__init__.py"])
    c1 = repo.index.commit("Initial baseline commit")

    # Baseline scan
    r1 = scan_repo(tmp_path)
    assert len(r1.findings) >= 2

    # Verify initial reachability
    v_finding = next(
        f for f in r1.findings if f.node and f.node.qualified_name == "vulnerable_sink"
    )
    assert v_finding.finding.static_evidence is not None
    assert v_finding.finding.static_evidence.reachable is Reachability.REACHABLE

    # Commit 2: Modify service.py without touching helper.py
    # helper.py finding MUST be reused
    service_py.write_text(
        "# Added comment\ndef vulnerable_sink():\n    assert False, 'vulnerability trigger'\n",
        encoding="utf-8",
    )
    repo.index.add(["service.py"])
    c2 = repo.index.commit("Add comments to service")

    r2 = scan_repo_incremental(tmp_path, base_ref=c1.hexsha, previous_report=r1)
    assert r2.incremental_stats is not None
    # helper.py was untouched: finding path reused!
    assert r2.incremental_stats.reused_count >= 1

    # Commit 3: Cut the call edge from route_fn
    routes_py.write_text(
        "from fastapi import FastAPI\n"
        "\n"
        "app = FastAPI()\n"
        "\n"
        "@app.get('/vuln')\n"
        "def route_fn():\n"
        "    return {'safe': True}\n",
        encoding="utf-8",
    )
    repo.index.add(["routes.py"])
    repo.index.commit("Disconnect route from vulnerable_sink")

    r3 = scan_repo_incremental(tmp_path, base_ref=c2.hexsha, previous_report=r2)
    assert r3.incremental_stats is not None

    # Check vulnerable_sink now: the dirty route path was invalidated!
    v_finding_3 = next(
        f for f in r3.findings if f.node and f.node.qualified_name == "vulnerable_sink"
    )
    assert v_finding_3.finding.static_evidence is not None
    # Now it is unreachable because route_fn no longer calls it!
    assert v_finding_3.finding.static_evidence.reachable is Reachability.UNREACHABLE
