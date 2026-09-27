"""OSV-Scanner wrapper — known vulnerabilities in declared dependencies, **offline**.

OSV-Scanner (Google, Apache-2.0) matches the packages a repo declares
(``requirements.txt``, ``pyproject.toml``, lockfiles) against the OSV
vulnerability database. *Decided 2026-09-27: offline database only.* Querying
api.osv.dev on every scan would send the repo's dependency list off the
machine (PRODUCT.md §6, local-first). Instead:

- ``ravel osv-db update`` is the **one explicit, user-run network step**: it
  downloads the PyPI database into Ravel's own directory (``RAVEL_OSV_DB``,
  default ``~/.cache/ravel/osv``);
- every scan runs ``--offline --offline-vulnerabilities`` against that copy
  and reports the copy's date, since an old copy misses newer advisories;
- with no database, OSV is reported ``not_configured`` — Ravel never
  downloads behind the user's back, and never silently skips.

OSV groups aliases of one bug (CVE / GHSA / PYSEC ids) itself; each group is
one finding. Severity bands and the "fixed in" suggestion are ported from
``reference/Arcflow/js/analysis/osv-scan.js`` (``osvGetSeverity``) and
``reference/CodeClean/js/analysis/dep-scan.js`` (``getUpgradeSuggestion``),
fixed to read only real version ranges — Arcflow also took git commit hashes
as "fixed versions".
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from ravel.core.logging import get_logger
from ravel.ingest.loader import SKIP_DIRS
from ravel.models import FindingSource
from ravel.scanners.base import RawFinding, ScanResult, ScanStatus, Severity

log = get_logger("ravel.scanners.osv")

_DB_ENV = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"  # where osv-scanner keeps its offline DB
_VERSION_RANGES = {"ECOSYSTEM", "SEMVER"}  # GIT ranges carry commit hashes, not versions


def default_db_dir() -> Path:
    return Path(os.environ.get("RAVEL_OSV_DB", "~/.cache/ravel/osv")).expanduser()


def db_file(db_dir: Path) -> Path:
    return db_dir / "osv-scalibr" / "PyPI" / "all.zip"


def db_date(db_dir: Path) -> dt.date | None:
    path = db_file(db_dir)
    return dt.date.fromtimestamp(path.stat().st_mtime) if path.is_file() else None


def find_osv(explicit: Path | None = None) -> Path | None:
    if explicit is not None:
        return explicit if explicit.is_file() else None
    found = shutil.which("osv-scanner")
    return Path(found) if found else None


def update_db(db_dir: Path, binary: Path | None = None) -> dt.date:
    """Download the PyPI OSV database — the only step that touches the network.

    osv-scanner downloads databases for the ecosystems it sees, so it is shown
    a throwaway one-line ``requirements.txt``; no repo data is sent.
    """
    exe = find_osv(binary)
    if exe is None:
        raise FileNotFoundError("osv-scanner is not installed (or not at --osv-bin)")
    db_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="ravel-osv-") as tmp:
        (Path(tmp) / "requirements.txt").write_text("pip==0.1\n", encoding="utf-8")
        proc = subprocess.run(
            [
                str(exe),
                "scan",
                "source",
                "--offline-vulnerabilities",
                "--download-offline-databases",
                "--format",
                "json",
                tmp,
            ],
            capture_output=True,
            text=True,
            env={**os.environ, _DB_ENV: str(db_dir)},
        )
    date = db_date(db_dir)
    if date is None:
        tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no output"]
        raise RuntimeError(f"OSV database download failed: {tail[0]}")
    return date


def severity_from_score(score: str | None) -> Severity:
    """CVSS base score → band (Arcflow ``osvGetSeverity``); unscored → LOW."""
    try:
        value = float(score) if score else 0.0
    except ValueError:
        return Severity.LOW
    if value >= 9:
        return Severity.CRITICAL
    if value >= 7:
        return Severity.HIGH
    if value >= 4:
        return Severity.MEDIUM
    return Severity.LOW


def _canonical(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fixed_in(vulns: list[dict[str, Any]], package: str, version: str | None) -> str | None:
    """Smallest version that fixes every vuln in the group and is above ``version``.

    Only ECOSYSTEM/SEMVER ranges count — GIT ranges' "fixed" is a commit hash.
    """
    installed = _parse(version)
    best: Version | None = None
    for vuln in vulns:
        candidates: list[Version] = []
        for affected in vuln.get("affected", []):
            if _canonical(affected.get("package", {}).get("name", "")) != _canonical(package):
                continue
            for rng in affected.get("ranges", []):
                if rng.get("type") not in _VERSION_RANGES:
                    continue
                for event in rng.get("events", []):
                    fixed = _parse(event.get("fixed"))
                    if fixed is not None and (installed is None or fixed > installed):
                        candidates.append(fixed)
        if candidates:
            lowest = min(candidates)  # this vuln's nearest fix above the installed version
            best = lowest if best is None or lowest > best else best
    return str(best) if best is not None else None


def _parse(version: str | None) -> Version | None:
    if not version:
        return None
    try:
        return Version(version)
    except InvalidVersion:
        return None


def _primary_id(ids: list[str], aliases: list[str]) -> str:
    """Prefer the CVE id people search for, then GHSA, then whatever OSV gave."""
    everything = sorted(set(ids) | set(aliases))
    for prefix in ("CVE-", "GHSA-"):
        for vid in everything:
            if vid.startswith(prefix):
                return vid
    return everything[0] if everything else "OSV-UNKNOWN"


def _cwe(vulns: list[dict[str, Any]]) -> str | None:
    for vuln in vulns:
        ids = (vuln.get("database_specific") or {}).get("cwe_ids") or []
        if ids:
            return str(ids[0])
    return None


def parse_report(report: dict[str, Any], root: Path) -> list[RawFinding]:
    """OSV JSON report → one raw finding per (package, version, vulnerability group).

    A package declared in two manifests (``requirements.txt`` and
    ``pyproject.toml``) is still one set of findings — the first manifest wins.
    """
    findings: list[RawFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for result in report.get("results", []):
        try:
            rel = Path(result["source"]["path"]).resolve().relative_to(root).as_posix()
        except (KeyError, ValueError):
            continue
        for pkg in result.get("packages", []):
            meta = pkg.get("package", {})
            name, version = str(meta.get("name", "")), meta.get("version")
            vulns_by_id = {v["id"]: v for v in pkg.get("vulnerabilities", [])}
            for group in pkg.get("groups", []):
                ids = list(group.get("ids", []))
                aliases = list(group.get("aliases", []))
                primary = _primary_id(ids, aliases)
                key = (_canonical(name), str(version), primary)
                if key in seen:
                    continue
                seen.add(key)
                vulns = [vulns_by_id[i] for i in ids if i in vulns_by_id]
                summary = next((v["summary"] for v in vulns if v.get("summary")), "")
                fix = fixed_in(vulns, name, version)
                message = summary or f"known vulnerability in {name} {version}"
                message += f" — fixed in {name} {fix}" if fix else " — no fixed version listed"
                score = group.get("max_severity") or None
                findings.append(
                    RawFinding(
                        source=FindingSource.OSV,
                        rule_id=primary,
                        rel_path=rel,
                        line=0,
                        end_line=0,
                        raw_severity=str(score or ""),
                        severity=severity_from_score(score),
                        confidence=None,
                        cwe=_cwe(vulns),
                        message=message,
                        package=name,
                        package_version=str(version) if version else None,
                        fixed_in=fix,
                        aliases=tuple(sorted(set(ids) | set(aliases))),
                    )
                )
    return findings


class OsvScanner:
    source = FindingSource.OSV

    def __init__(self, db_dir: Path | None = None, binary: Path | None = None) -> None:
        self.db_dir = db_dir or default_db_dir()
        self.binary = binary

    def _version(self, exe: Path) -> str | None:
        try:
            out = subprocess.run(
                [str(exe), "--version"], capture_output=True, text=True, timeout=60
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            return None
        match = re.search(r"osv-scanner version: (\S+)", out)
        return match.group(1) if match else None

    def scan(self, root: Path, files: list[str]) -> ScanResult:
        exe = find_osv(self.binary)
        if exe is None:
            return ScanResult(self.source, ScanStatus.NOT_INSTALLED)
        version = self._version(exe)
        date = db_date(self.db_dir)
        if date is None:
            return ScanResult(
                self.source,
                ScanStatus.NOT_CONFIGURED,
                version,
                detail="no offline database — run `ravel osv-db update`",
            )
        detail = f"offline db {date.isoformat()}"

        cmd = [str(exe), "scan", "source", "--offline", "--offline-vulnerabilities"]
        cmd += ["--recursive", "--format", "json"]
        for skip in sorted(SKIP_DIRS):
            cmd += ["--experimental-exclude", skip]
        proc = subprocess.run(
            [*cmd, str(root)],
            capture_output=True,
            text=True,
            env={**os.environ, _DB_ENV: str(self.db_dir)},
        )
        # Exit 0: no vulns; 1: vulns found; 128: no manifests to scan — all fine.
        if proc.returncode == 128 or not proc.stdout.strip():
            detail += "; no pinned dependency manifests found"
            return ScanResult(self.source, ScanStatus.OK, version, detail=detail)
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-1:] or ["no report"]
            log.error("osv-scanner failed (exit %d): %s", proc.returncode, tail[0])
            return ScanResult(self.source, ScanStatus.FAILED, version, errors=tail, detail=detail)
        return ScanResult(
            self.source, ScanStatus.OK, version, parse_report(report, root.resolve()), detail=detail
        )
