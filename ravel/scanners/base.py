"""The scanner contract: run an existing tool, report what it said, honestly.

Ravel never writes detection rules (PRODUCT.md §6) — a scanner here is a thin
wrapper that runs a real tool (Bandit, Semgrep, gitleaks, OSV-Scanner) and
parses its report into :class:`RawFinding`s. Normalization onto the graph
lives in :mod:`ravel.scanners.normalize`.

A scanner that is not installed, or that fails, is **reported**, never
silently skipped: a missing scanner is lost recall, and the report must say so.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from ravel.models import FindingSource


class Severity(StrEnum):
    """Scanner severities mapped onto one scale — for ordering and the
    severity-only eval baseline. ``Finding.raw_severity`` keeps the original."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanStatus(StrEnum):
    OK = "ok"
    NOT_INSTALLED = "not_installed"
    NOT_CONFIGURED = "not_configured"  # installed, but needs input Ravel won't invent (rules)
    FAILED = "failed"


@dataclass(frozen=True)
class RawFinding:
    """One result exactly as a scanner reported it, before graph mapping."""

    source: FindingSource
    rule_id: str  # the scanner's own id, e.g. Bandit "B602"
    rel_path: str  # POSIX, relative to the repo root
    line: int  # 1-based start line
    end_line: int
    raw_severity: str
    severity: Severity
    confidence: str | None
    cwe: str | None  # normalized "CWE-<n>"
    message: str


@dataclass
class ScanResult:
    """Everything one scanner run produced — including why it produced nothing."""

    source: FindingSource
    status: ScanStatus
    version: str | None = None
    findings: list[RawFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)  # per-file problems the tool reported


class Scanner(Protocol):
    source: FindingSource

    def scan(self, root: Path, files: list[str]) -> ScanResult:
        """Scan ``files`` (repo-relative paths under ``root``); never raise."""
        ...


def normalize_cwe(value: object) -> str | None:
    """``78`` / ``"78"`` / ``"CWE-78"`` / ``"CWE-78: OS Command Injection"`` → ``"CWE-78"``."""
    if value is None:
        return None
    text = str(value).strip()
    if text.upper().startswith("CWE-"):
        text = text[4:]
    digits = ""
    for ch in text:
        if not ch.isdigit():
            break
        digits += ch
    return f"CWE-{digits}" if digits and int(digits) > 0 else None
