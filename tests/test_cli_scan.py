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
    assert "not integrated yet" in result.output  # missing scanners are visible
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["not_integrated"] == ["gitleaks"]
    osv = next(s for s in payload["scanners"] if s["source"] == "osv")
    assert osv["status"] in {"not_installed", "not_configured", "ok"}
    semgrep = next(s for s in payload["scanners"] if s["source"] == "semgrep")
    assert semgrep["status"] in {"not_installed", "not_configured"}  # no rules given
    assert payload["mapping"]["ratio"] == 1.0
    (secret,) = [f for f in payload["findings"] if f["rule_id"] == "B105"]
    assert secret["file"] == "mysite/settings.py"
    assert secret["cwe"] == "CWE-259"
    assert secret["node_id"] == "mysite/settings.py::<file>"
