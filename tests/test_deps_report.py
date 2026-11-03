"""The dependency report, on the documented ``legacy_shop`` and Django fixtures.

Advisories come from a stand-in OSV scanner returning findings in the shape
the real wrapper produces (``tests/test_osv.py`` covers parsing real
osv-scanner output), so these tests need no database.
"""

from __future__ import annotations

from pathlib import Path

from ravel.deps.report import Urgency, build_deps_report, deps_payload
from ravel.models import FindingSource, Reachability
from ravel.scanners.base import RawFinding, ScanResult, ScanStatus, Severity
from ravel.scanners.run import scan_repo

FIXTURES = Path(__file__).parent.parent / "eval" / "fixtures"
LEGACY = FIXTURES / "legacy_shop"
DJANGO = FIXTURES / "django_app"


def _advisory(package: str, version: str, rule: str, fixed: str | None) -> RawFinding:
    return RawFinding(
        source=FindingSource.OSV,
        rule_id=rule,
        rel_path="requirements.txt",
        line=0,
        end_line=0,
        raw_severity="7.5",
        severity=Severity.HIGH,
        confidence=None,
        cwe="CWE-400",
        message=f"known vulnerability in {package}",
        package=package,
        package_version=version,
        fixed_in=fixed,
    )


class _FakeOsv:
    source = FindingSource.OSV

    def __init__(self, findings: list[RawFinding]) -> None:
        self.findings = findings

    def scan(self, root: Path, files: list[str]) -> ScanResult:
        return ScanResult(self.source, ScanStatus.OK, "test", list(self.findings), detail="test db")


# Flask's public shape, so legacy_shop's calls into it resolve (as in test_environment).
_FLASK = """
class Flask:
    def __init__(self, import_name): ...
    def route(self, rule, **options): ...

def jsonify(*args, **kwargs): ...
"""


def _site(tmp_path: Path, dists: dict[str, tuple[str, list[str]]]) -> Path:
    """A virtualenv whose site-packages holds dist-info for ``name: (version, requires)``,
    plus an importable ``flask``."""
    venv = tmp_path / "venv"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (venv / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (site / "flask").mkdir()
    (site / "flask" / "__init__.py").write_text(_FLASK, encoding="utf-8")
    for name, (version, requires) in dists.items():
        info = site / f"{name}-{version}.dist-info"
        info.mkdir()
        meta = [f"Name: {name}", *(f"Requires-Dist: {r}" for r in requires)]
        (info / "METADATA").write_text("\n".join(meta) + "\n", encoding="utf-8")
        (info / "top_level.txt").write_text(name.lower() + "\n", encoding="utf-8")
    return venv


def test_deprecated_calls_split_by_reachability_as_documented() -> None:
    report = build_deps_report(scan_repo(LEGACY, scanners=[]))
    apis = {a.symbol: a for p in report.packages for a in p.deprecated}
    assert set(apis) == {"datetime.datetime.utcnow", "locale.getdefaultlocale"}

    utcnow = apis["datetime.datetime.utcnow"]
    assert utcnow.reach.reachable is Reachability.REACHABLE
    names = [nid.split("::")[1] for nid in utcnow.reach.path]
    assert names == ["create_order", "placed_at"]  # POST /orders -> placed_at

    assert apis["locale.getdefaultlocale"].reach.reachable is Reachability.UNREACHABLE
    by_name = {p.name: p for p in report.packages}
    assert by_name["datetime"].stdlib and by_name["datetime"].urgency is Urgency.MIGRATE
    assert report.osv is None  # OSV not run: reported as such, not as "no advisories"


def test_advisories_rank_by_reachability_and_upgrade_to_the_highest_fix(tmp_path: Path) -> None:
    venv = _site(tmp_path, {"flask": ("2.2.2", ["Werkzeug>=2.2.2"]), "werkzeug": ("2.2.2", [])})
    osv = _FakeOsv(
        [
            _advisory("Flask", "2.2.2", "CVE-F1", "2.2.5"),
            _advisory("Flask", "2.2.2", "CVE-F2", "2.3.2"),
            _advisory("Werkzeug", "2.2.2", "CVE-W1", "2.2.3"),
            _advisory("Werkzeug", "2.2.2", "CVE-W2", None),
        ]
    )
    report = build_deps_report(scan_repo(LEGACY, venv=venv, scanners=[osv]))
    by_name = {p.name: p for p in report.packages}

    flask = by_name["flask"]
    assert flask.urgency is Urgency.URGENT  # route code calls into Flask
    assert flask.upgrade_to == "2.3.2" and flask.unfixed == 0
    assert flask.version == "2.2.2" and not flask.pin_is_stale

    werkzeug = by_name["werkzeug"]  # never imported, but Flask requires it
    assert werkzeug.via == ["flask"]
    assert werkzeug.urgency is Urgency.URGENT
    assert werkzeug.upgrade_to == "2.2.3" and werkzeug.unfixed == 1

    order = [p.urgency for p in report.packages]
    assert order == sorted(order, key=list(Urgency).index)
    payload = deps_payload(report)
    assert payload["summary"]["urgent"] == 2
    assert payload["osv"] == {"status": "ok", "detail": "test db"}
    assert "not the latest release" in payload["upgrade_note"]


def test_a_pin_older_than_the_installed_fix_is_flagged_stale(tmp_path: Path) -> None:
    venv = _site(tmp_path, {"flask": ("3.1.3", [])})
    osv = _FakeOsv([_advisory("Flask", "2.2.2", "CVE-F2", "2.3.2")])
    report = build_deps_report(scan_repo(LEGACY, venv=venv, scanners=[osv]))
    flask = next(p for p in report.packages if p.name == "flask")
    assert (flask.version, flask.declared) == ("3.1.3", "2.2.2")
    assert flask.pin_is_stale


def test_an_advisory_on_code_we_cannot_see_into_is_check() -> None:
    # No environment: the polls views' calls into Django are unresolved, so the
    # advisory's reachability is unknown (tests/test_reachability.py) → check.
    osv = _FakeOsv([_advisory("Django", "3.2", "CVE-2021-35042", "3.2.5")])
    django = next(
        p
        for p in build_deps_report(scan_repo(DJANGO, scanners=[osv])).packages
        if p.name == "django"
    )
    assert django.usage.reachable is Reachability.UNKNOWN
    assert django.urgency is Urgency.CHECK


def test_deprecation_check_reports_what_it_could_not_see() -> None:
    payload = deps_payload(build_deps_report(scan_repo(DJANGO, scanners=[])))
    check = payload["deprecation_check"]
    assert check["unresolved_calls"] > 0  # no env: calls into Django are invisible
    assert check["stdlib_python"] == "3.12"
