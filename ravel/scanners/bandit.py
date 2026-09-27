"""Bandit wrapper — Python-specific security linter (PyCQA, Apache-2.0).

Bandit parses source into an AST and never imports or executes it, so running
it on an untrusted repo is safe (PRODUCT.md §6: local, read-only). It runs as
a subprocess of Ravel's own interpreter, with Bandit's default rule set.

We pass Ravel's discovered file list rather than ``-r``, so Bandit scans
exactly the files the graph was built from (and skips venvs the same way).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from ravel.core.logging import get_logger
from ravel.models import FindingSource
from ravel.scanners.base import RawFinding, ScanResult, ScanStatus, Severity, normalize_cwe

log = get_logger("ravel.scanners.bandit")

_SEVERITY = {
    "LOW": Severity.LOW,
    "MEDIUM": Severity.MEDIUM,
    "HIGH": Severity.HIGH,
}


def _version() -> str | None:
    try:
        from importlib.metadata import version

        return version("bandit")
    except Exception:
        return None


def parse_report(report: dict[str, Any], root: Path) -> tuple[list[RawFinding], list[str]]:
    """Bandit JSON report → raw findings + per-file errors."""
    findings: list[RawFinding] = []
    for r in report.get("results", []):
        try:
            rel = Path(r["filename"]).resolve().relative_to(root).as_posix()
        except ValueError:
            continue  # outside the repo — never ours to map
        line = int(r["line_number"])
        lines = r.get("line_range") or [line]
        raw_sev = str(r.get("issue_severity", "")).upper()
        findings.append(
            RawFinding(
                source=FindingSource.BANDIT,
                rule_id=str(r["test_id"]),
                rel_path=rel,
                line=line,
                end_line=max(int(x) for x in lines),
                raw_severity=raw_sev,
                severity=_SEVERITY.get(raw_sev, Severity.LOW),
                confidence=r.get("issue_confidence"),
                cwe=normalize_cwe((r.get("issue_cwe") or {}).get("id")),
                message=str(r.get("issue_text", "")),
            )
        )
    errors = [f"{e.get('filename')}: {e.get('reason')}" for e in report.get("errors", [])]
    return findings, errors


class BanditScanner:
    source = FindingSource.BANDIT

    def scan(self, root: Path, files: list[str]) -> ScanResult:
        version = _version()
        if version is None:
            return ScanResult(self.source, ScanStatus.NOT_INSTALLED)
        if not files:
            return ScanResult(self.source, ScanStatus.OK, version)

        with tempfile.TemporaryDirectory(prefix="ravel-bandit-") as tmp:
            out = Path(tmp) / "report.json"
            cmd = [sys.executable, "-m", "bandit", "-q", "-f", "json", "-o", str(out)]
            proc = subprocess.run(
                [*cmd, *(str(root / f) for f in files)],
                cwd=root,
                capture_output=True,
                text=True,
            )
            # Bandit exits 1 when it finds issues; only a missing report is a failure.
            if not out.is_file():
                detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no report"]
                log.error("bandit failed (exit %d): %s", proc.returncode, detail[0])
                return ScanResult(self.source, ScanStatus.FAILED, version, errors=detail)
            report = json.loads(out.read_text(encoding="utf-8"))

        findings, errors = parse_report(report, root.resolve())
        for err in errors:
            log.warning("bandit: %s", err)
        return ScanResult(self.source, ScanStatus.OK, version, findings, errors)
