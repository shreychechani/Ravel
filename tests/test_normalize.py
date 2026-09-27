"""Finding normalization onto graph nodes + dedupe (Phase 2), on real fixtures.

flaskr (the Flask tutorial) and the Django fixture give real Bandit output:
function-level findings, a finding on a ``def`` line, repeated asserts in one
test function, and a module-level ``SECRET_KEY``.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest
from ravel.models import FindingSource, NodeKind
from ravel.scanners.base import RawFinding, ScanStatus, Severity
from ravel.scanners.normalize import (
    LocatedFinding,
    cross_scanner_duplicates,
    dedupe,
    normalize,
)
from ravel.scanners.run import NOT_YET_INTEGRATED, ScanReport, scan_repo

FIXTURES = Path(__file__).parent.parent / "eval" / "fixtures"
FLASKR = FIXTURES / "flaskr"
DJANGO = FIXTURES / "django_app"


@pytest.fixture(scope="module")
def flaskr() -> ScanReport:
    return scan_repo(FLASKR)


def _by_rule_line(report: ScanReport) -> dict[tuple[str, str, int], LocatedFinding]:
    return {(f.raw.rel_path, f.finding.rule_id, f.raw.line): f for f in report.findings}


def test_bandit_runs_and_reports_its_version(flaskr: ScanReport) -> None:
    result = next(r for r in flaskr.results if r.source is FindingSource.BANDIT)
    assert result.status is ScanStatus.OK
    assert result.version
    assert len(result.findings) > 0
    # Semgrep always reports a status — here, no rules were supplied.
    semgrep = next(r for r in flaskr.results if r.source is FindingSource.SEMGREP)
    assert semgrep.status in {ScanStatus.NOT_INSTALLED, ScanStatus.NOT_CONFIGURED}
    assert len(flaskr.findings) == sum(len(r.findings) for r in flaskr.results)


def test_unintegrated_scanners_are_reported_not_hidden(flaskr: ScanReport) -> None:
    assert set(flaskr.not_integrated) == set(NOT_YET_INTEGRATED)
    assert FindingSource.BANDIT not in flaskr.not_integrated


def test_every_finding_maps_to_a_node(flaskr: ScanReport) -> None:
    assert flaskr.mapping.total == len(flaskr.findings)
    assert flaskr.mapping.unmapped == 0
    assert flaskr.mapping.ratio == 1.0


def test_findings_anchor_on_the_innermost_def(flaskr: ScanReport) -> None:
    found = _by_rule_line(flaskr)
    # Hard-coded default password on a `def` line → that method, not its class.
    login = found[("tests/conftest.py", "B107", 51)]
    assert login.node is not None
    assert login.node.qualified_name == "AuthActions.login"
    assert login.finding.cwe == "CWE-259"
    # A keyword argument inside create_app's body.
    create_app = found[("flaskr/__init__.py", "B106", 11)].node
    assert create_app is not None and create_app.qualified_name == "create_app"
    assert all(f.node is not None and f.finding.node_id == f.node.id for f in flaskr.findings)


def test_module_level_finding_anchors_on_the_file_node() -> None:
    report = scan_repo(DJANGO)
    secret = next(f for f in report.findings if f.finding.rule_id == "B105")
    assert secret.raw.rel_path == "mysite/settings.py"
    assert secret.node is not None and secret.node.kind is NodeKind.FILE
    assert report.mapping.to_file >= 1


def test_ids_are_unique_even_for_repeated_identical_lines(flaskr: ScanReport) -> None:
    ids = [f.finding.id for f in flaskr.findings]
    assert len(ids) == len(set(ids))


def test_ids_survive_code_moving_but_change_with_the_code(tmp_path: Path) -> None:
    repo = tmp_path / "flaskr"
    shutil.copytree(FLASKR, repo)
    before = {
        f.finding.id for f in scan_repo(repo).findings if f.raw.rel_path == "tests/conftest.py"
    }

    conftest = repo / "tests" / "conftest.py"
    original = conftest.read_text(encoding="utf-8")
    conftest.write_text("\n\n\n" + original, encoding="utf-8")  # shift every line down
    moved = {
        f.finding.id for f in scan_repo(repo).findings if f.raw.rel_path == "tests/conftest.py"
    }
    assert moved == before  # content hash, not line number (PRODUCT.md §6)

    conftest.write_text(original.replace('password="test"', 'password="changed"'), encoding="utf-8")
    edited = {
        f.finding.id for f in scan_repo(repo).findings if f.raw.rel_path == "tests/conftest.py"
    }
    assert edited != before  # the flagged code changed, so its id must too


def test_cross_scanner_duplicates_are_grouped_not_dropped(flaskr: ScanReport) -> None:
    b107 = next(f for f in flaskr.findings if f.finding.rule_id == "B107")
    semgrep_twin = RawFinding(
        source=FindingSource.SEMGREP,
        rule_id="python.lang.security.hardcoded-password-default-argument",
        rel_path=b107.raw.rel_path,
        line=b107.raw.line,
        end_line=b107.raw.line,
        raw_severity="WARNING",
        severity=Severity.MEDIUM,
        confidence=None,
        cwe="CWE-259",
        message="hard-coded password default",
    )
    findings, _ = normalize([b107.raw, semgrep_twin], flaskr.graph.nodes, FLASKR)
    groups = dedupe(findings)
    assert len(findings) == 2  # both kept in the report
    assert cross_scanner_duplicates(groups) == 1  # but counted once for scoring


def test_same_scanner_on_different_lines_is_not_a_duplicate(flaskr: ScanReport) -> None:
    # Many B101 asserts in one test function: distinct lines, distinct findings.
    assert cross_scanner_duplicates(flaskr.groups) == 0


def test_non_python_findings_are_kept_but_outside_the_mapping_rate(flaskr: ScanReport) -> None:
    def template(path: str, line: int) -> RawFinding:
        return RawFinding(
            source=FindingSource.SEMGREP,
            rule_id="python.django.security.django-no-csrf-token",
            rel_path=path,
            line=line,
            end_line=line,
            raw_severity="WARNING",
            severity=Severity.MEDIUM,
            confidence="MEDIUM",
            cwe="CWE-352",
            message="form without csrf token",
        )

    raws = [
        template("flaskr/templates/auth/login.html", 8),
        template("flaskr/templates/auth/register.html", 8),  # same line, other file
        flaskr.findings[0].raw,
    ]
    findings, stats = normalize(raws, flaskr.graph.nodes, FLASKR)
    assert len(findings) == 3
    assert stats.non_python == 2
    assert stats.unmapped == 0
    assert stats.ratio == 1.0  # the one Python finding mapped
    assert [f.node for f in findings if f.raw.rel_path.endswith(".html")] == [None, None]
    assert len({f.finding.id for f in findings}) == 3
    # Same line + CWE in two different templates must not collapse into one group.
    assert cross_scanner_duplicates(dedupe(findings)) == 0
    assert len(dedupe(findings)) == 3


def _dep(package: str, rule: str, manifest: str = "requirements.txt") -> RawFinding:
    return RawFinding(
        source=FindingSource.OSV,
        rule_id=rule,
        rel_path=manifest,
        line=0,
        end_line=0,
        raw_severity="7.5",
        severity=Severity.HIGH,
        confidence=None,
        cwe="CWE-400",
        message="known vulnerability",
        package=package,
        package_version="1.0",
    )


def _site(tmp_path: Path, dists: dict[str, list[str]]) -> Path:
    """An environment's site-packages: dist-info METADATA with Requires-Dist."""
    site = tmp_path / "site-packages"
    for name, requires in dists.items():
        info = site / f"{name}-1.0.dist-info"
        info.mkdir(parents=True)
        lines = [f"Name: {name}", *(f"Requires-Dist: {r}" for r in requires)]
        (info / "METADATA").write_text("\n".join(lines) + "\n", encoding="utf-8")
        (info / "top_level.txt").write_text(name.lower() + "\n", encoding="utf-8")
    return site


def test_dependency_findings_link_once_to_every_importer(tmp_path: Path) -> None:
    report = scan_repo(DJANGO)
    raws = [_dep("Django", "CVE-A"), _dep("Django", "CVE-B")]
    findings, stats = normalize(
        raws, report.graph.nodes, DJANGO, external_refs=report.graph.external_refs
    )
    assert len(findings) == 2  # one per advisory — never one per importer
    assert stats.to_package == 2 and stats.ratio == 1.0
    anchors = findings[0].anchors
    assert anchors and all(n.file_path.endswith(".py") for n in anchors)
    assert findings[0].node is None and findings[0].finding.node_id == ""


def test_transitive_dependency_links_via_the_package_requiring_it(tmp_path: Path) -> None:
    # The Django app never imports sqlparse — but Django requires it, so it runs.
    report = scan_repo(DJANGO)
    site = _site(
        tmp_path,
        {
            "Django": ["sqlparse>=0.2.2", "argon2-cffi; extra == 'argon2'"],
            "sqlparse": [],
            "leftpad": [],
        },
    )
    raws = [_dep("sqlparse", "CVE-S"), _dep("leftpad", "CVE-L"), _dep("argon2-cffi", "CVE-X")]
    findings, stats = normalize(
        raws, report.graph.nodes, DJANGO, report.graph.external_refs, [site]
    )
    by_pkg = {f.raw.package: f for f in findings}
    assert by_pkg["sqlparse"].via == ("django",)
    assert by_pkg["sqlparse"].anchors  # Django's importers
    assert stats.via_dependency == 1
    # Nothing imports or requires leftpad; argon2-cffi is only an optional extra.
    assert not by_pkg["leftpad"].anchors and not by_pkg["argon2-cffi"].anchors
    assert stats.unused_dependency == 2
    assert stats.ratio == 1.0


def test_without_an_environment_unimported_deps_are_unknown_not_unused() -> None:
    report = scan_repo(DJANGO)
    findings, stats = normalize(
        [_dep("sqlparse", "CVE-S")], report.graph.nodes, DJANGO, report.graph.external_refs
    )
    assert stats.dependency_unknown == 1  # never claimed unused, never unreachable
    assert stats.unused_dependency == 0
    assert findings[0].anchors == ()


def test_dependency_ids_ignore_the_manifest_and_distinct_cves_never_merge() -> None:
    report = scan_repo(DJANGO)
    a, _ = normalize([_dep("Django", "CVE-A", "requirements.txt")], report.graph.nodes, DJANGO)
    b, _ = normalize([_dep("Django", "CVE-A", "pyproject.toml")], report.graph.nodes, DJANGO)
    assert a[0].finding.id == b[0].finding.id  # the bug, not where it was declared
    both, _ = normalize(
        [_dep("Django", "CVE-A"), _dep("Django", "CVE-B")], report.graph.nodes, DJANGO
    )
    assert len(dedupe(both)) == 2  # same CWE, different advisories: separate
