"""Bandit wrapper (Phase 2), on the real flaskr fixture."""

from __future__ import annotations

from pathlib import Path

import pytest
from ravel.models import FindingSource
from ravel.scanners import bandit
from ravel.scanners.bandit import BanditScanner, parse_report
from ravel.scanners.base import ScanStatus

FLASKR = Path(__file__).parent.parent / "eval" / "fixtures" / "flaskr"


def test_bandit_reports_findings_with_cwe_and_version() -> None:
    result = BanditScanner().scan(FLASKR, ["flaskr/__init__.py", "tests/conftest.py"])
    assert result.source is FindingSource.BANDIT
    assert result.status is ScanStatus.OK
    assert result.version
    rules = {(f.rel_path, f.rule_id, f.line, f.cwe) for f in result.findings}
    assert ("flaskr/__init__.py", "B106", 11, "CWE-259") in rules
    assert ("tests/conftest.py", "B107", 51, "CWE-259") in rules


def test_missing_bandit_is_reported_as_not_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bandit, "_version", lambda: None)
    result = BanditScanner().scan(FLASKR, ["flaskr/db.py"])
    assert result.status is ScanStatus.NOT_INSTALLED
    assert result.findings == []


def test_report_entries_outside_the_repo_are_ignored(tmp_path: Path) -> None:
    report = {
        "results": [
            {
                "filename": "/elsewhere/x.py",
                "test_id": "B101",
                "line_number": 1,
                "issue_severity": "LOW",
            }
        ],
        "errors": [{"filename": "bad.py", "reason": "syntax error"}],
    }
    findings, errors = parse_report(report, tmp_path)
    assert findings == []
    assert errors == ["bad.py: syntax error"]
