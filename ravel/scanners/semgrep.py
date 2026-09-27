"""Semgrep OSS wrapper — runs **user-supplied** rules only.

Ravel never writes detection rules (PRODUCT.md §6) and doesn't ship any
either: the public ``semgrep/semgrep-rules`` repo is under the Semgrep Rules
License, and registry configs (``p/python``, ``auto``) download rules from
semgrep.dev on every run. So Semgrep runs only against local rule files or
directories the user names (``--semgrep-config``); without one it is reported
``not_configured`` — never silently skipped. (Decision recorded 2026-09-27.)

Local-first: registry ids and URLs are refused, and every run disables
metrics and the version check, so a scan makes no network call.

Unlike Bandit, Semgrep scans the repo with its own target discovery, so rules
for templates and config files apply too; those findings are reported but
have no Python graph node to anchor on (see ``normalize``).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from ravel.core.logging import get_logger
from ravel.ingest.loader import SKIP_DIRS
from ravel.models import FindingSource
from ravel.scanners.base import RawFinding, ScanResult, ScanStatus, Severity, normalize_cwe

log = get_logger("ravel.scanners.semgrep")

# Semgrep's legacy (ERROR/WARNING/INFO) and newer (CRITICAL..LOW) severities.
_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "ERROR": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "INFO": Severity.LOW,
    "LOW": Severity.LOW,
}

_NO_NETWORK_ENV = {"SEMGREP_ENABLE_VERSION_CHECK": "0", "SEMGREP_SEND_METRICS": "off"}


def find_semgrep(explicit: Path | None = None) -> Path | None:
    """``explicit``, else ``semgrep`` next to Ravel's interpreter, else on PATH."""
    if explicit is not None:
        return explicit if explicit.is_file() else None
    sibling = Path(sys.executable).parent / "semgrep"
    if sibling.is_file():
        return sibling
    found = shutil.which("semgrep")
    return Path(found) if found else None


def check_local_config(config: str) -> Path:
    """Accept only a local rules file/dir; refuse anything Semgrep would download."""
    if config in {"auto"} or config.startswith(("p/", "r/", "s/", "http://", "https://")):
        raise ValueError(
            f"semgrep config {config!r} is fetched from the network; Ravel runs only "
            "local rules (local-first) — download a rule pack yourself and pass its path"
        )
    path = Path(config).expanduser().resolve()
    if not path.exists():
        raise ValueError(f"semgrep config {config!r} does not exist")
    return path


def _cwe(metadata: dict[str, Any]) -> str | None:
    raw = metadata.get("cwe")
    first = raw[0] if isinstance(raw, list) and raw else raw
    return normalize_cwe(first)


def _location_prefixes(configs: list[Path]) -> list[str]:
    """Semgrep prefixes each ``check_id`` with the rules' directory as a dotted
    path (``home.me.rules.python.lang.x`` for ``/home/me/rules/python``). That
    prefix says where the rules live on disk, not what they are — and rule ids
    feed content-hash finding ids, which must not depend on paths (§6)."""
    return sorted(
        {str(c.parent).strip("/").replace("/", ".") + "." for c in configs if c.parent != c},
        key=len,
        reverse=True,
    )


def rule_id(check_id: str, prefixes: list[str]) -> str:
    """``check_id`` minus the rules' on-disk location: ``python.lang.x``."""
    for prefix in prefixes:
        if check_id.startswith(prefix):
            return check_id[len(prefix) :]
    return check_id


def parse_report(
    report: dict[str, Any], root: Path, prefixes: list[str] | None = None
) -> tuple[list[RawFinding], list[str]]:
    """Semgrep JSON report → raw findings + errors."""
    findings: list[RawFinding] = []
    for r in report.get("results", []):
        try:
            rel = Path(r["path"]).resolve().relative_to(root).as_posix()
        except ValueError:
            continue
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {}) or {}
        raw_sev = str(extra.get("severity", "")).upper()
        findings.append(
            RawFinding(
                source=FindingSource.SEMGREP,
                rule_id=rule_id(str(r["check_id"]), prefixes or []),
                rel_path=rel,
                line=int(r["start"]["line"]),
                end_line=int(r["end"]["line"]),
                raw_severity=raw_sev,
                severity=_SEVERITY.get(raw_sev, Severity.LOW),
                confidence=metadata.get("confidence"),
                cwe=_cwe(metadata),
                message=str(extra.get("message", "")),
            )
        )
    errors = [
        f"{e.get('path', '-')}: {e.get('type', 'error')}: {str(e.get('message', ''))[:200]}"
        for e in report.get("errors", [])
    ]
    return findings, errors


class SemgrepScanner:
    source = FindingSource.SEMGREP

    def __init__(self, configs: list[str] | None = None, binary: Path | None = None) -> None:
        self.configs = [check_local_config(c) for c in configs or []]
        self.binary = binary

    def _version(self, exe: Path) -> str | None:
        try:
            proc = subprocess.run(
                [str(exe), "--version"],
                capture_output=True,
                text=True,
                env={**os.environ, **_NO_NETWORK_ENV},
                timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        return proc.stdout.strip() or None

    def scan(self, root: Path, files: list[str]) -> ScanResult:
        exe = find_semgrep(self.binary)
        if exe is None:
            return ScanResult(self.source, ScanStatus.NOT_INSTALLED)
        version = self._version(exe)
        if not self.configs:
            return ScanResult(self.source, ScanStatus.NOT_CONFIGURED, version)

        cmd = [str(exe), "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check"]
        for config in self.configs:
            cmd += ["--config", str(config)]
        for skip in sorted(SKIP_DIRS):
            cmd += ["--exclude", skip]
        proc = subprocess.run(
            [*cmd, str(root)],
            cwd=root,
            capture_output=True,
            text=True,
            env={**os.environ, **_NO_NETWORK_ENV},
        )
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            detail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no report"]
            log.error("semgrep failed (exit %d): %s", proc.returncode, detail[0])
            return ScanResult(self.source, ScanStatus.FAILED, version, errors=detail)

        findings, errors = parse_report(report, root.resolve(), _location_prefixes(self.configs))
        for err in errors:
            log.warning("semgrep: %s", err)
        return ScanResult(self.source, ScanStatus.OK, version, findings, errors)
