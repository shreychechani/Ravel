"""OSV-Scanner wrapper (Phase 2) — offline database only.

The end-to-end test needs osv-scanner and a downloaded database::

    RAVEL_OSV_BIN=/path/to/osv-scanner RAVEL_OSV_DB=/path/to/db uv run pytest

(``ravel osv-db update --db ... --osv-bin ...`` creates the database.)
Without them it is skipped and says so; everything else runs offline.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path
from typing import Any

import pytest
from ravel.models import FindingSource
from ravel.scanners.base import ScanStatus, Severity
from ravel.scanners.osv import OsvScanner, _primary_id, fixed_in, parse_report, severity_from_score
from ravel.scanners.run import scan_repo

DJANGO = Path(__file__).parent.parent / "eval" / "fixtures" / "django_app"


def _vuln(vid: str, fixed: list[str], git: str | None = None) -> dict[str, Any]:
    ranges: list[dict[str, Any]] = [
        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, *({"fixed": f} for f in fixed)]}
    ]
    if git:
        ranges.append({"type": "GIT", "events": [{"introduced": "0"}, {"fixed": git}]})
    return {
        "id": vid,
        "summary": "SQL Injection in Django",
        "database_specific": {"cwe_ids": ["CWE-89"]},
        "affected": [{"package": {"name": "django", "ecosystem": "PyPI"}, "ranges": ranges}],
    }


def _report(root: Path, manifest: str = "requirements.txt") -> dict[str, Any]:
    # Shape as emitted by osv-scanner 2.6.0 --format json (fields trimmed);
    # CVE-2021-35042 as reported for Django 3.2, fixed in 3.2.5.
    return {
        "results": [
            {
                "source": {"path": str(root / manifest), "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "django", "version": "3.2", "ecosystem": "PyPI"},
                        "groups": [
                            {
                                "ids": ["GHSA-xpfp-f569-q3p2", "PYSEC-2021-111"],
                                "aliases": ["CVE-2021-35042", "GHSA-xpfp-f569-q3p2"],
                                "max_severity": "9.8",
                            }
                        ],
                        "vulnerabilities": [
                            _vuln("GHSA-xpfp-f569-q3p2", ["3.1.13", "3.2.5"], git="a3b8c7d"),
                            _vuln("PYSEC-2021-111", ["3.2.5"]),
                        ],
                    }
                ],
            }
        ]
    }


def test_parse_report_one_finding_per_vulnerability_group(tmp_path: Path) -> None:
    (finding,) = parse_report(_report(tmp_path), tmp_path.resolve())
    assert finding.source is FindingSource.OSV
    assert finding.rule_id == "CVE-2021-35042"  # the CVE id, not an internal alias
    assert set(finding.aliases) == {"CVE-2021-35042", "GHSA-xpfp-f569-q3p2", "PYSEC-2021-111"}
    assert (finding.package, finding.package_version) == ("django", "3.2")
    assert finding.rel_path == "requirements.txt"
    assert finding.line == 0
    assert finding.severity is Severity.CRITICAL
    assert finding.raw_severity == "9.8"
    assert finding.cwe == "CWE-89"
    assert finding.fixed_in == "3.2.5"
    assert "fixed in django 3.2.5" in finding.message


def test_same_package_in_two_manifests_is_reported_once(tmp_path: Path) -> None:
    report = _report(tmp_path)
    report["results"] += _report(tmp_path, "pyproject.toml")["results"]
    assert len(parse_report(report, tmp_path.resolve())) == 1


def test_fixed_in_ignores_git_commits_and_older_branches() -> None:
    vulns = [_vuln("A", ["3.1.13", "3.2.5"], git="c45d7c49ea75"), _vuln("B", ["3.2.4"])]
    # 3.1.13 is below the installed 3.2; the git hash is not a version; the group
    # needs the fix for *every* vuln in it, so 3.2.5 beats 3.2.4.
    assert fixed_in(vulns, "Django", "3.2") == "3.2.5"
    assert fixed_in([_vuln("C", [])], "django", "3.2") is None


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        ("9.8", Severity.CRITICAL),
        ("7.5", Severity.HIGH),
        ("6.1", Severity.MEDIUM),
        ("2.0", Severity.LOW),
        ("", Severity.LOW),
        (None, Severity.LOW),
        ("n/a", Severity.LOW),
    ],
)
def test_severity_bands(score: str | None, expected: Severity) -> None:
    assert severity_from_score(score) is expected


def test_primary_id_prefers_cve_then_ghsa() -> None:
    assert _primary_id(["PYSEC-1", "GHSA-a"], ["CVE-2021-1"]) == "CVE-2021-1"
    assert _primary_id(["PYSEC-1", "GHSA-a"], []) == "GHSA-a"
    assert _primary_id(["PYSEC-1"], []) == "PYSEC-1"


def _stub_osv(tmp_path: Path) -> Path:
    exe = tmp_path / "osv-scanner"
    exe.write_text("#!/bin/sh\necho 'osv-scanner version: 2.6.0'\n", encoding="utf-8")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    return exe


def test_not_installed_when_the_binary_is_missing(tmp_path: Path) -> None:
    result = OsvScanner(tmp_path / "db", tmp_path / "osv-scanner").scan(DJANGO, [])
    assert result.status is ScanStatus.NOT_INSTALLED


def test_no_offline_database_is_not_configured_never_a_download(tmp_path: Path) -> None:
    result = OsvScanner(tmp_path / "empty-db", _stub_osv(tmp_path)).scan(DJANGO, [])
    assert result.status is ScanStatus.NOT_CONFIGURED
    assert result.version == "2.6.0"
    assert result.detail is not None and "ravel osv-db update" in result.detail
    assert not (tmp_path / "empty-db").exists()  # nothing was fetched or created


_BIN = os.environ.get("RAVEL_OSV_BIN")
_DB = os.environ.get("RAVEL_OSV_DB")


@pytest.mark.skipif(not (_BIN and _DB), reason="set RAVEL_OSV_BIN and RAVEL_OSV_DB to run")
def test_live_offline_scan_of_the_django_fixture() -> None:
    assert _BIN and _DB
    report = scan_repo(DJANGO, scanners=[OsvScanner(Path(_DB), Path(_BIN))])
    (result,) = report.results
    assert result.status is ScanStatus.OK, result.errors
    assert result.detail is not None and result.detail.startswith("offline db ")
    packages = {f.raw.package for f in report.findings}
    assert {"django", "sqlparse"} <= packages
    sqli = next(f for f in report.findings if f.finding.rule_id == "CVE-2021-35042")
    assert sqli.raw.fixed_in == "3.2.5"
    assert sqli.anchors  # linked to the code that imports Django
