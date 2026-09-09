"""Ravel domain model — the shape of the code graph and findings.

Mirrors PRODUCT.md §4. The nullable post-v1 fields (``runtime_evidence``,
``graph_diff``, ``patch``) exist so we never have to migrate later — but no v1
logic populates them.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class NodeKind(StrEnum):
    FILE = "file"
    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"


class EdgeKind(StrEnum):
    CALLS = "calls"
    IMPORTS = "imports"
    INHERITS = "inherits"
    DEFINES = "defines"


class EntryPointKind(StrEnum):
    HTTP_ROUTE = "http_route"
    API_HANDLER = "api_handler"
    CRON = "cron"
    CLI = "cli"
    CELERY_TASK = "celery_task"


class Trust(StrEnum):
    """The critical distinction that drives reachability."""

    UNTRUSTED = "untrusted"
    INTERNAL = "internal"


class Reachability(StrEnum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


class FindingSource(StrEnum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    GITLEAKS = "gitleaks"
    OSV = "osv"


class Node(BaseModel):
    id: str
    kind: NodeKind
    qualified_name: str
    file_path: str
    start_line: int
    end_line: int
    source_hash: str  # content hash — drives all caching
    docstring: str | None = None
    summary: str | None = None  # generated lazily, later phase
    embedding: list[float] | None = None


class Edge(BaseModel):
    src_id: str
    dst_id: str
    kind: EdgeKind
    resolved: bool = True  # False => target could not be statically determined


class EntryPoint(BaseModel):
    node_id: str
    kind: EntryPointKind
    trust: Trust


class ExternalRef(BaseModel):
    """A reference into a third-party package.

    Must exist from day one — retrofitting means a full re-index (PRODUCT.md §4).
    """

    node_id: str
    package: str
    version: str | None = None
    symbol: str | None = None


class StaticEvidence(BaseModel):
    reachable: Reachability
    path: list[str] = Field(default_factory=list)  # node ids from entry point to sink
    blast_radius: int = 0


class Finding(BaseModel):
    id: str
    source: FindingSource
    node_id: str
    rule_id: str
    raw_severity: str
    cwe: str | None = None
    static_evidence: StaticEvidence | None = None

    # --- post-v1 placeholders: columns exist, no v1 logic populates them ---
    runtime_evidence: None = None  # Sentry integration — NOT v1
    graph_diff: None = None  # reachability-change detection — NOT v1

    verdict: str | None = None
    confidence: float | None = None
    reasoning: str | None = None

    patch: None = None  # NOT v1
