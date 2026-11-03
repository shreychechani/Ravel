"""``ravel scan`` end to end on the Django fixture."""

from __future__ import annotations

import json
from pathlib import Path

from ravel.cli.main import app
from typer.testing import CliRunner

DJANGO = Path(__file__).parent.parent / "eval" / "fixtures" / "django_app"


def test_scan_writes_normalized_findings_json(tmp_path: Path) -> None:
    out = tmp_path / "scan.json"
    result = CliRunner().invoke(app, ["scan", str(DJANGO), "--json", str(out)])
    assert result.exit_code == 0, result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["not_integrated"] == []
    gitleaks = next(s for s in payload["scanners"] if s["source"] == "gitleaks")
    assert gitleaks["status"] in {"not_installed", "ok"}  # reported either way, never hidden
    osv = next(s for s in payload["scanners"] if s["source"] == "osv")
    assert osv["status"] in {"not_installed", "not_configured", "ok"}
    semgrep = next(s for s in payload["scanners"] if s["source"] == "semgrep")
    assert semgrep["status"] in {"not_installed", "not_configured"}  # no rules given
    assert payload["mapping"]["ratio"] == 1.0
    (secret,) = [f for f in payload["findings"] if f["rule_id"] == "B105"]
    assert secret["file"] == "mysite/settings.py"
    assert secret["cwe"] == "CWE-259"
    assert secret["node_id"] == "mysite/settings.py::<file>"


def test_scan_with_triage_flag(tmp_path: Path) -> None:
    out = tmp_path / "scan_triage.json"
    cache_file = tmp_path / "triage_cache.json"
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(DJANGO),
            "--triage",
            "--llm-provider",
            "mock",
            "--triage-cache",
            str(cache_file),
            "--json",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert "LLM Triage" in result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert "findings" in payload
    for f in payload["findings"]:
        assert "verdict" in f
        assert f["verdict"] is not None
        # scanner_confidence is separate from the LLM triage confidence
        assert "scanner_confidence" in f
    # triage_stats must be in JSON output when --triage is active
    assert "triage_stats" in payload
    ts = payload["triage_stats"]
    assert ts["total"] > 0
    assert "llm_calls" in ts
    assert "cached_hits" in ts


def test_deps_reports_deprecated_calls_and_osv_status(tmp_path: Path) -> None:
    legacy = DJANGO.parent / "legacy_shop"
    out = tmp_path / "deps.json"
    # An empty --osv-db: OSV must be reported as not configured, never silently skipped.
    args = ["deps", str(legacy), "--osv-db", str(tmp_path / "no-db"), "--json", str(out)]
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 0, result.output
    assert "Deprecated APIs in use" in result.output
    payload = json.loads(out.read_text(encoding="utf-8"))
    apis = {a["symbol"] for p in payload["packages"] for a in p["deprecated"]}
    assert apis == {"datetime.datetime.utcnow", "locale.getdefaultlocale"}
    assert "unresolved_calls" in payload["deprecation_check"]  # the check's blind spot
    assert payload["osv"]["status"] in {"not_installed", "not_configured"}
    assert payload["summary"]["deprecated_calls_by_reach"]["reachable"] == 1
