"""Semgrep wrapper (Phase 2) — user-supplied local rules only, no network.

Ravel ships no Semgrep rules, so the end-to-end test needs a local Semgrep
and a rules directory the tester chose::

    RAVEL_SEMGREP_BIN=/path/to/semgrep RAVEL_SEMGREP_RULES=/path/to/rules uv run pytest

Without them it is skipped (and says so); everything else runs offline.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest
from ravel.models import FindingSource
from ravel.scanners.base import ScanStatus, Severity
from ravel.scanners.run import scan_repo
from ravel.scanners.semgrep import (
    SemgrepScanner,
    check_local_config,
    parse_report,
    rule_id,
)

FLASKR = Path(__file__).parent.parent / "eval" / "fixtures" / "flaskr"


@pytest.mark.parametrize("config", ["p/python", "auto", "r/python.lang", "https://x/rules.yml"])
def test_network_configs_are_refused(config: str) -> None:
    with pytest.raises(ValueError, match="local-first"):
        check_local_config(config)


def test_missing_local_config_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        check_local_config(str(tmp_path / "nope"))


def test_rule_ids_drop_the_rules_on_disk_location() -> None:
    prefixes = ["home.me.rules."]
    assert rule_id("home.me.rules.python.lang.x", prefixes) == "python.lang.x"
    assert rule_id("other.rule", prefixes) == "other.rule"


def test_parse_report(tmp_path: Path) -> None:
    # Shape as emitted by semgrep 1.178.0 --json (fields trimmed).
    report = {
        "results": [
            {
                "check_id": "rules.python.flask.xss",
                "path": str(tmp_path / "app.py"),
                "start": {"line": 3, "col": 5},
                "end": {"line": 4, "col": 9},
                "extra": {
                    "message": "m",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-79: Improper Neutralization"], "confidence": "HIGH"},
                },
            },
            {
                "check_id": "rules.python.csrf",
                "path": str(tmp_path / "t.html"),
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"severity": "WARNING", "metadata": {"cwe": "CWE-352: CSRF"}},
            },
            {"check_id": "x", "path": "/elsewhere/a.py", "start": {"line": 1}, "end": {"line": 1}},
        ],
        "errors": [{"path": "bad.py", "type": "Syntax error", "message": "boom"}],
    }
    findings, errors = parse_report(report, tmp_path.resolve(), ["rules."])
    assert [(f.rule_id, f.rel_path, f.line, f.end_line) for f in findings] == [
        ("python.flask.xss", "app.py", 3, 4),
        ("python.csrf", "t.html", 1, 1),
    ]
    assert findings[0].cwe == "CWE-79"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].confidence == "HIGH"
    assert findings[1].cwe == "CWE-352"
    assert findings[1].severity is Severity.MEDIUM
    assert all(f.source is FindingSource.SEMGREP for f in findings)
    assert errors == ["bad.py: Syntax error: boom"]


def test_not_installed_when_the_binary_is_missing(tmp_path: Path) -> None:
    result = SemgrepScanner(binary=tmp_path / "semgrep").scan(FLASKR, [])
    assert result.status is ScanStatus.NOT_INSTALLED


def test_not_configured_without_rules(tmp_path: Path) -> None:
    exe = tmp_path / "semgrep"
    exe.write_text("#!/bin/sh\necho 1.0.0\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    result = SemgrepScanner(binary=exe).scan(FLASKR, [])
    assert result.status is ScanStatus.NOT_CONFIGURED  # reported, not silently skipped
    assert result.version == "1.0.0"
    assert result.findings == []


_BIN = os.environ.get("RAVEL_SEMGREP_BIN")
_RULES = os.environ.get("RAVEL_SEMGREP_RULES")


@pytest.mark.skipif(
    not (_BIN and _RULES), reason="set RAVEL_SEMGREP_BIN and RAVEL_SEMGREP_RULES to run"
)
def test_live_scan_anchors_python_findings_and_keeps_template_ones() -> None:
    assert _BIN and _RULES
    scanner = SemgrepScanner([_RULES], Path(_BIN))
    report = scan_repo(FLASKR, scanners=[scanner])
    (result,) = report.results
    assert result.status is ScanStatus.OK, result.errors
    assert report.mapping.unmapped == 0
    semgrep = [f for f in report.findings if f.finding.source is FindingSource.SEMGREP]
    assert semgrep, "expected the chosen rules to fire on flaskr"
    assert not any(f.finding.rule_id.startswith(("private.", "Users.", "home.")) for f in semgrep)
    for f in semgrep:
        assert (f.node is None) == (not f.raw.rel_path.endswith(".py"))
