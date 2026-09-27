"""Scanner output → ``Finding``s anchored on graph nodes (PRODUCT.md §3, step 3).

Three jobs:

1. **Map** every raw finding to the innermost function/class whose span holds
   its start line, falling back to the file's FILE node for module-level code
   (``SECRET_KEY = "..."`` in settings.py). The mapping rate is a first-class
   metric (PRODUCT.md §9: ≥95%); so is how many landed only at file level,
   since reachability through a FILE node is coarser than through a function.
2. **Identify** each finding by a content hash — scanner, rule, the node's
   ``source_hash`` and the flagged line's text — never its path or line
   number (§6), so the id survives edits above it and file moves, and changes
   exactly when the code it depends on changes.
3. **Deduplicate** across scanners (research/02, Kang et al.): Semgrep and
   Bandit often flag the same line for the same weakness, and counting both
   inflates precision. Duplicates are grouped, never deleted — each scanner's
   finding stays in the report.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.hashing import content_hash
from ravel.core.logging import get_logger
from ravel.models import Finding, Node, NodeKind
from ravel.scanners.base import RawFinding

log = get_logger("ravel.scanners.normalize")

_DEF_KINDS = {NodeKind.FUNCTION, NodeKind.CLASS}


@dataclass(frozen=True)
class LocatedFinding:
    """A normalized ``Finding`` plus where/what the scanner said.

    The ``Finding`` schema (PRODUCT.md §4) carries no location — the node is
    its anchor — but a report needs the line, and dedupe needs it too.
    """

    finding: Finding
    raw: RawFinding
    node: Node


@dataclass
class MappingStats:
    total: int = 0
    to_def: int = 0  # anchored on a function/class node
    to_file: int = 0  # module-level: anchored on the FILE node only
    unmapped: int = 0  # file absent from the graph (not discovered / not Python)

    @property
    def mapped(self) -> int:
        return self.to_def + self.to_file

    @property
    def ratio(self) -> float:
        return self.mapped / self.total if self.total else 1.0


@dataclass
class DuplicateGroup:
    """Findings from different scanners on the same line for the same weakness."""

    key: tuple[str, str, int]  # (node id, CWE or rule, line)
    members: list[LocatedFinding] = field(default_factory=list)


def _innermost(nodes: list[Node], line: int) -> Node | None:
    best: Node | None = None
    for n in nodes:
        if (
            n.kind in _DEF_KINDS
            and n.start_line <= line <= n.end_line
            and (best is None or n.start_line >= best.start_line)
        ):
            best = n
    return best


def _line_text(root: Path, rel_path: str, line: int, cache: dict[str, list[str]]) -> str:
    if rel_path not in cache:
        try:
            cache[rel_path] = (root / rel_path).read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            cache[rel_path] = []
    lines = cache[rel_path]
    return lines[line - 1].strip() if 0 < line <= len(lines) else ""


def normalize(
    raw_findings: list[RawFinding], nodes: list[Node], root: Path
) -> tuple[list[LocatedFinding], MappingStats]:
    """Anchor raw findings on graph nodes and give each a content-hash id."""
    by_file: dict[str, list[Node]] = defaultdict(list)
    file_node: dict[str, Node] = {}
    for n in nodes:
        by_file[n.file_path].append(n)
        if n.kind is NodeKind.FILE:
            file_node[n.file_path] = n

    stats = MappingStats()
    text_cache: dict[str, list[str]] = {}
    occurrences: dict[str, int] = defaultdict(int)
    out: list[LocatedFinding] = []
    for raw in sorted(raw_findings, key=lambda r: (r.rel_path, r.line, r.source, r.rule_id)):
        stats.total += 1
        node = _innermost(by_file.get(raw.rel_path, []), raw.line)
        if node is not None:
            stats.to_def += 1
        elif raw.rel_path in file_node:
            node = file_node[raw.rel_path]
            stats.to_file += 1
        else:
            stats.unmapped += 1
            log.warning(
                "%s finding %s at %s:%d maps to no graph node — reported, not anchored",
                raw.source.value,
                raw.rule_id,
                raw.rel_path,
                raw.line,
            )
            continue

        text = _line_text(root, raw.rel_path, raw.line, text_cache)
        basis = "\x1f".join([raw.source.value, raw.rule_id, node.source_hash, text])
        # Identical flagged lines in one node (e.g. repeated asserts) stay distinct.
        occurrences[basis] += 1
        fid = content_hash(f"{basis}\x1f{occurrences[basis]}")
        finding = Finding(
            id=fid,
            source=raw.source,
            node_id=node.id,
            rule_id=raw.rule_id,
            raw_severity=raw.raw_severity,
            cwe=raw.cwe,
        )
        out.append(LocatedFinding(finding, raw, node))
    return out, stats


def dedupe(findings: list[LocatedFinding]) -> list[DuplicateGroup]:
    """Group findings that flag the same line of the same node for the same weakness.

    The weakness is the CWE when the scanner gives one (so Semgrep and Bandit
    agree across rule vocabularies), else the scanner's own rule id. Only
    groups spanning more than one scanner count as cross-scanner duplicates;
    a scanner repeating itself on one line is left alone.
    """
    groups: dict[tuple[str, str, int], DuplicateGroup] = {}
    for lf in findings:
        weakness = lf.finding.cwe or f"{lf.finding.source.value}:{lf.finding.rule_id}"
        key = (lf.finding.node_id, weakness, lf.raw.line)
        groups.setdefault(key, DuplicateGroup(key)).members.append(lf)
    return list(groups.values())


def cross_scanner_duplicates(groups: list[DuplicateGroup]) -> int:
    """How many findings are extra copies of one another across scanners."""
    return sum(len(g.members) - 1 for g in groups if len({m.finding.source for m in g.members}) > 1)
