"""gitleaks wrapper — hard-coded secrets, with gitleaks' own default rules (MIT).

Ravel writes no detection rules (PRODUCT.md §6): gitleaks runs with its
built-in rule set. The only config Ravel adds is an allowlist of the same
directories the graph skips (``.venv``, ``node_modules``…), so a vendored
virtualenv's test keys are not reported as the repo's secrets. That is a path
filter, not a rule. Passing it means a repo's own ``.gitleaks.toml`` is not
read.

It scans the working tree (``gitleaks dir``), not git history, and runs with
``--redact``: a secret's value never enters Ravel's report, the JSON export or
the web view — only where it is and which rule matched. Local and read-only:
gitleaks makes no network call.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from ravel.core.logging import get_logger
from ravel.ingest.loader import SKIP_DIRS
from ravel.models import FindingSource
from ravel.scanners.base import RawFinding, ScanResult, ScanStatus, Severity

log = get_logger("ravel.scanners.gitleaks")

CWE_HARDCODED_CREDENTIALS = "CWE-798"


def find_gitleaks(explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        return explicit if explicit.is_file() else None
    found = shutil.which("gitleaks")
    return Path(found) if found else None


def skip_config() -> str:
    """gitleaks' default rules, plus Ravel's skipped directories as an allowlist."""
    alternatives = "|".join(sorted(d.replace(".", "\\.") for d in SKIP_DIRS))
    return (
        "[extend]\nuseDefault = true\n\n"
        "[allowlist]\n"
        'description = "directories Ravel does not index"\n'
        f"paths = ['''(^|/)({alternatives})(/|$)''']\n"
    )


def parse_report(report: list[dict[str, Any]], root: Path) -> list[RawFinding]:
    """gitleaks JSON → raw findings. ``Secret`` and ``Match`` are never read."""
    findings: list[RawFinding] = []
    for leak in report:
        try:
            rel = Path(leak["File"]).resolve().relative_to(root).as_posix()
        except (KeyError, ValueError):
            continue
        rule = str(leak.get("RuleID", "generic-secret"))
        findings.append(
            RawFinding(
                source=FindingSource.GITLEAKS,
                rule_id=rule,
                rel_path=rel,
                line=int(leak.get("StartLine", 0)),
                end_line=int(leak.get("EndLine", leak.get("StartLine", 0))),
                raw_severity="HIGH",
                severity=Severity.HIGH,
                confidence=None,
                cwe=CWE_HARDCODED_CREDENTIALS,
                message=f"{leak.get('Description') or rule} (value redacted)",
            )
        )
    return findings


class GitleaksScanner:
    source = FindingSource.GITLEAKS

    def __init__(self, binary: Path | None = None) -> None:
        self.binary = binary

    def _version(self, exe: Path) -> str | None:
        try:
            proc = subprocess.run([str(exe), "version"], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout.strip() or None

    def scan(self, root: Path, files: list[str]) -> ScanResult:
        exe = find_gitleaks(self.binary)
        if exe is None:
            return ScanResult(self.source, ScanStatus.NOT_INSTALLED)
        version = self._version(exe)
        root = root.resolve()
        with tempfile.NamedTemporaryFile("w", suffix=".toml", delete=False) as cfg:
            cfg.write(skip_config())
        try:
            proc = subprocess.run(
                [
                    str(exe),
                    "dir",
                    str(root),
                    "--config",
                    cfg.name,
                    "--report-format",
                    "json",
                    "--report-path",
                    "-",
                    "--redact",
                    "--no-banner",
                    "--exit-code",
                    "0",
                    "--log-level",
                    "error",
                ],
                capture_output=True,
                text=True,
            )
        finally:
            Path(cfg.name).unlink(missing_ok=True)
        try:
            report = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no report"]
            log.error("gitleaks failed (exit %d): %s", proc.returncode, detail[0])
            return ScanResult(self.source, ScanStatus.FAILED, version, errors=detail)
        if proc.returncode != 0:
            detail = proc.stderr.strip().splitlines()[-1:] or [f"exit {proc.returncode}"]
            return ScanResult(self.source, ScanStatus.FAILED, version, errors=detail)
        return ScanResult(self.source, ScanStatus.OK, version, parse_report(report, root))
