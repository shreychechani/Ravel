"""gitleaks wrapper (Phase 2): default rules, redacted values, skipped venvs.

The end-to-end test needs ``gitleaks`` on PATH and is skipped without it.
Its fake token is generated at test time so no secret-shaped string is ever
committed.
"""

from __future__ import annotations

import secrets
import string
from pathlib import Path

import pytest
from ravel.models import FindingSource
from ravel.scanners.base import ScanStatus, Severity
from ravel.scanners.gitleaks import GitleaksScanner, find_gitleaks, parse_report, skip_config


def test_parse_report_keeps_location_and_rule_never_the_secret(tmp_path: Path) -> None:
    report = [
        {
            "RuleID": "github-pat",
            "Description": "GitHub Personal Access Token",
            "File": str(tmp_path / "app" / "settings.py"),
            "StartLine": 3,
            "EndLine": 3,
            "Secret": "the-secret-value",
            "Match": "TOKEN = the-secret-value",
        }
    ]
    (finding,) = parse_report(report, tmp_path)
    assert finding.source is FindingSource.GITLEAKS
    assert (finding.rule_id, finding.rel_path, finding.line) == ("github-pat", "app/settings.py", 3)
    assert finding.cwe == "CWE-798" and finding.severity is Severity.HIGH
    assert "the-secret-value" not in repr(finding)


def test_skip_config_extends_the_default_rules() -> None:
    cfg = skip_config()
    assert "useDefault = true" in cfg
    assert "\\.venv" in cfg and "node_modules" in cfg


@pytest.mark.skipif(find_gitleaks() is None, reason="gitleaks not installed")
def test_finds_a_token_in_code_but_not_in_a_venv(tmp_path: Path) -> None:
    body = "".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(36))
    line = f'GITHUB_TOKEN = "ghp_{body}"\n'
    (tmp_path / "app.py").write_text(f"import os\n{line}", encoding="utf-8")
    (tmp_path / ".venv").mkdir()
    (tmp_path / ".venv" / "vendored.py").write_text(line, encoding="utf-8")

    result = GitleaksScanner().scan(tmp_path, ["app.py"])
    assert result.status is ScanStatus.OK, result.errors
    assert [(f.rel_path, f.line) for f in result.findings] == [("app.py", 2)]
    assert body not in repr(result)


def test_missing_binary_is_reported_not_skipped(tmp_path: Path) -> None:
    result = GitleaksScanner(binary=tmp_path / "no-gitleaks").scan(tmp_path, [])
    assert result.status is ScanStatus.NOT_INSTALLED
