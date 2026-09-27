"""Scanner output → ``Finding``s anchored on graph nodes (PRODUCT.md §3, step 3).

Three jobs:

1. **Map** every raw finding to the innermost function/class whose span holds
   its start line, falling back to the file's FILE node for module-level code
   (``SECRET_KEY = "..."`` in settings.py). The mapping rate is a first-class
   metric (PRODUCT.md §9: ≥95%); so is how many landed only at file level,
   since reachability through a FILE node is coarser than through a function.
   Findings in non-Python files (Semgrep scans templates too) have no node to
   land on by design: they are counted and kept, but outside the rate.
   Dependency findings (OSV) are about a *package*, not a line: each is one
   finding linked to every node that imports the package (``anchors``) —
   never one copy per importer, which would multiply one CVE into dozens of
   findings. A package the repo never imports may still run — Django imports
   sqlparse — so with the scanned environment available it is linked through
   whichever imported package requires it (``via``). Only a package nothing
   imports and nothing requires is an unused dependency; with no environment
   to tell, it is ``dependency_unknown``. Neither is ever called unreachable.
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
from ravel.deps.distributions import canonical, import_names, required_by, requirements_graph
from ravel.ingest.loader import PYTHON_SUFFIXES
from ravel.models import ExternalRef, Finding, Node, NodeKind
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
    node: Node | None  # None for non-Python files and package-level (OSV) findings
    # Package-level findings: every node that imports the vulnerable package —
    # or, for a transitive dependency, imports a package that requires it.
    # Reachability (Phase 3) asks whether *any* of them is reachable.
    anchors: tuple[Node, ...] = ()
    via: tuple[str, ...] = ()  # the imported packages a transitive dependency runs through


@dataclass
class MappingStats:
    total: int = 0
    to_def: int = 0  # anchored on a function/class node
    to_file: int = 0  # module-level: anchored on the FILE node only
    to_package: int = 0  # dependency finding linked to the nodes importing the package
    via_dependency: int = 0  # transitive dep, linked through the package requiring it
    unmapped: int = 0  # a Python file absent from the graph — a real mapping failure
    non_python: int = 0  # template / config file: no graph node exists to map to
    unused_dependency: int = 0  # nothing imports it and nothing installed requires it
    dependency_unknown: int = 0  # not imported by repo code; no environment to tell more

    @property
    def mapped(self) -> int:
        return self.to_def + self.to_file + self.to_package + self.via_dependency

    @property
    def mappable(self) -> int:
        return self.total - self.non_python - self.unused_dependency - self.dependency_unknown

    @property
    def ratio(self) -> float:
        """Mapped share of findings in Python files (the §9 gate)."""
        return self.mapped / self.mappable if self.mappable else 1.0


@dataclass
class DuplicateGroup:
    """Findings from different scanners on the same line for the same weakness."""

    key: tuple[str, str, int]  # (node id — or file, if non-Python — CWE or rule, line)
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


def _unanchored(raw: RawFinding, fid: str) -> LocatedFinding:
    """A finding in a non-Python file: kept in the report, anchored on nothing.

    Its id has no node ``source_hash`` to hash, so the file path stands in —
    the one place a path enters an id, because there is no content node.
    """
    finding = Finding(
        id=fid,
        source=raw.source,
        node_id="",
        rule_id=raw.rule_id,
        raw_severity=raw.raw_severity,
        cwe=raw.cwe,
    )
    return LocatedFinding(finding, raw, None)


def _importers_of(
    distribution: str, importers: dict[str, list[Node]], site_packages: list[Path]
) -> dict[str, Node]:
    modules = import_names(distribution, site_packages)
    return {n.id: n for m in sorted(modules) for n in importers.get(m, [])}


def _package_finding(
    raw: RawFinding,
    importers: dict[str, list[Node]],
    site_packages: list[Path],
    requires: dict[str, set[str]],
) -> LocatedFinding:
    """A dependency finding, linked to every node importing the package — or,
    if the repo doesn't import it, to the importers of packages requiring it."""
    assert raw.package is not None
    unique = _importers_of(raw.package, importers, site_packages)
    via: list[str] = []
    if not unique:
        for parent in sorted(required_by(raw.package, requires)):
            parent_importers = _importers_of(parent, importers, site_packages)
            if parent_importers:
                via.append(parent)
                unique.update(parent_importers)
    anchors = tuple(unique[k] for k in sorted(unique))
    # Identity is the bug in this package version — not which manifest listed it.
    basis = "\x1f".join(
        [raw.source.value, raw.rule_id, canonical(raw.package), raw.package_version or ""]
    )
    finding = Finding(
        id=content_hash(basis),
        source=raw.source,
        node_id="",
        rule_id=raw.rule_id,
        raw_severity=raw.raw_severity,
        cwe=raw.cwe,
    )
    return LocatedFinding(finding, raw, None, anchors, tuple(via))


def normalize(
    raw_findings: list[RawFinding],
    nodes: list[Node],
    root: Path,
    external_refs: list[ExternalRef] | None = None,
    site_packages: list[Path] | None = None,
) -> tuple[list[LocatedFinding], MappingStats]:
    """Anchor raw findings on graph nodes and give each a content-hash id.

    ``external_refs`` (which node imports which top-level package) and the
    scanned environment's ``site_packages`` (distribution → import names) are
    only needed for dependency findings.
    """
    by_file: dict[str, list[Node]] = defaultdict(list)
    file_node: dict[str, Node] = {}
    by_id: dict[str, Node] = {}
    for n in nodes:
        by_file[n.file_path].append(n)
        by_id[n.id] = n
        if n.kind is NodeKind.FILE:
            file_node[n.file_path] = n
    importers: dict[str, list[Node]] = defaultdict(list)
    for ref in external_refs or []:
        if ref.node_id in by_id:
            importers[ref.package].append(by_id[ref.node_id])

    sites = site_packages or []
    requires = requirements_graph(sites)

    stats = MappingStats()
    text_cache: dict[str, list[str]] = {}
    occurrences: dict[str, int] = defaultdict(int)
    out: list[LocatedFinding] = []
    for raw in sorted(raw_findings, key=lambda r: (r.rel_path, r.line, r.source, r.rule_id)):
        stats.total += 1
        if raw.package is not None:
            located = _package_finding(raw, importers, sites, requires)
            if located.via:
                stats.via_dependency += 1
            elif located.anchors:
                stats.to_package += 1
            elif requires:
                stats.unused_dependency += 1  # environment says nothing needs it
            else:
                stats.dependency_unknown += 1
            out.append(located)
            continue
        node = _innermost(by_file.get(raw.rel_path, []), raw.line)
        if node is not None:
            stats.to_def += 1
        elif raw.rel_path in file_node:
            node = file_node[raw.rel_path]
            stats.to_file += 1
        elif Path(raw.rel_path).suffix not in PYTHON_SUFFIXES:
            stats.non_python += 1
            text = _line_text(root, raw.rel_path, raw.line, text_cache)
            basis = "\x1f".join([raw.source.value, raw.rule_id, raw.rel_path, text])
            occurrences[basis] += 1
            out.append(_unanchored(raw, content_hash(f"{basis}\x1f{occurrences[basis]}")))
            continue
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
    a scanner repeating itself on one line is left alone. Dependency findings
    are keyed by package version + advisory: distinct CVEs in one package
    often share a CWE and must not merge.
    """
    groups: dict[tuple[str, str, int], DuplicateGroup] = {}
    for lf in findings:
        if lf.raw.package is not None:
            pkg = f"pkg:{canonical(lf.raw.package)}@{lf.raw.package_version}"
            key = (pkg, lf.finding.rule_id, 0)
            groups.setdefault(key, DuplicateGroup(key)).members.append(lf)
            continue
        weakness = lf.finding.cwe or f"{lf.finding.source.value}:{lf.finding.rule_id}"
        anchor = lf.finding.node_id or lf.raw.rel_path  # non-Python: no node, key by file
        key = (anchor, weakness, lf.raw.line)
        groups.setdefault(key, DuplicateGroup(key)).members.append(lf)
    return list(groups.values())


def cross_scanner_duplicates(groups: list[DuplicateGroup]) -> int:
    """How many findings are extra copies of one another across scanners."""
    return sum(len(g.members) - 1 for g in groups if len({m.finding.source for m in g.members}) > 1)
