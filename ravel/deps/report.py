"""The dependency report: what an upgrade would cost, and which ones are urgent.

PRODUCT.md §1 asks "what would this migration really cost?" — deprecated APIs
and outdated dependencies, **classified by reachability**. Everything here is
read off one scan; nothing new is detected:

- **advisories** are the OSV findings the scan already anchored and traced
  (offline database — Ravel never looks a dependency list up online);
- **deprecated APIs** are the external calls the graph builder resolved onto
  a definition its own library marks deprecated (:mod:`ravel.deps.deprecations`);
- **usage** is every reference the graph recorded into the package.

Per package that gives an **urgency**: a known advisory in a package whose
using code untrusted input reaches is *urgent*; unknown reachability is
*check* — never quietly downgraded (§6); advisories nothing untrusted reaches
are *routine*; no advisory but deprecated calls is *migrate*.

"Upgrade to" is the smallest release that fixes every fixable advisory. It is
not the latest release: finding that needs PyPI, i.e. sending the dependency
list off the machine (§6, local-first). The report says so.

Two limits are reported next to the results, never hidden: the deprecation
check only sees calls the graph resolved (unresolved call sites are counted),
and stdlib deprecations are judged against the Python running Ravel.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from packaging.version import InvalidVersion, Version

from ravel.deps.deprecations import DeprecatedUse, DeprecationCheck, DeprecationMarker
from ravel.deps.distributions import (
    canonical,
    import_names,
    installed_versions,
    module_distributions,
)
from ravel.models import FindingSource, Node, Reachability, StaticEvidence
from ravel.scanners.base import ScanResult, Severity
from ravel.scanners.normalize import LocatedFinding
from ravel.scanners.run import ScanReport
from ravel.triage.reachability import Tracer, reachability_tracer

_REACH_ORDER = {Reachability.REACHABLE: 0, Reachability.UNKNOWN: 1, Reachability.UNREACHABLE: 2}
_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3}


class Urgency(StrEnum):
    URGENT = "urgent"  # known advisory; untrusted input reaches the code using the package
    CHECK = "check"  # known advisory; whether untrusted input reaches it is unknown
    ROUTINE = "routine"  # known advisory; nothing untrusted reaches the code using it
    MIGRATE = "migrate"  # no advisory, but the repo calls APIs the package deprecates
    OK = "ok"


_URGENCY_ORDER = {u: i for i, u in enumerate(Urgency)}
_ADVISORY_URGENCY = {
    Reachability.REACHABLE: Urgency.URGENT,
    Reachability.UNKNOWN: Urgency.CHECK,
    Reachability.UNREACHABLE: Urgency.ROUTINE,
}


def _most_reachable(evidence: list[StaticEvidence]) -> StaticEvidence:
    """The most reachable of several traces; nothing to trace is unknown (§6)."""
    if not evidence:
        return StaticEvidence(reachable=Reachability.UNKNOWN)
    return min(evidence, key=lambda e: (_REACH_ORDER[e.reachable], len(e.path) or 1_000_000))


@dataclass
class DeprecatedCall:
    use: DeprecatedUse
    evidence: StaticEvidence


@dataclass
class DeprecatedApi:
    """One deprecated library API and every place the repo calls it."""

    symbol: str
    marker: DeprecationMarker
    calls: list[DeprecatedCall] = field(default_factory=list)

    @property
    def reach(self) -> StaticEvidence:
        return _most_reachable([c.evidence for c in self.calls])


@dataclass
class PackageEntry:
    name: str  # the distribution ("pillow") when known, else the import name ("PIL")
    modules: list[str]  # import names the repo uses it by
    version: str | None  # installed in the scanned environment
    declared: str | None  # the version a manifest pins, as OSV read it
    stdlib: bool
    users: list[str]  # nodes that import or call into it
    references: int  # imports + resolved calls + base classes into it
    usage: StaticEvidence  # how reachable the code using it is
    via: list[str] = field(default_factory=list)  # imported packages a transitive dep runs under
    advisories: list[LocatedFinding] = field(default_factory=list)
    upgrade_to: str | None = None  # smallest release fixing every fixable advisory
    unfixed: int = 0  # advisories with no fixed release listed
    deprecated: list[DeprecatedApi] = field(default_factory=list)
    urgency: Urgency = Urgency.OK

    @property
    def files(self) -> int:
        return len({u.split("::", 1)[0] for u in self.users})

    @property
    def pin_is_stale(self) -> bool:
        """The manifest pins a vulnerable release, but the environment already
        has one at or above the fix: the advisories apply to the pin, not to
        what is installed here."""
        installed, target = _version(self.version), _version(self.upgrade_to)
        return bool(self.declared and installed and target and installed >= target)

    @property
    def worst_severity(self) -> Severity | None:
        sevs = [lf.raw.severity for lf in self.advisories]
        return min(sevs, key=_SEVERITY_ORDER.__getitem__) if sevs else None

    @property
    def deprecated_calls(self) -> int:
        return sum(len(api.calls) for api in self.deprecated)


@dataclass
class DepsReport:
    packages: list[PackageEntry]
    osv: ScanResult | None  # None: the scan didn't run OSV at all
    check: DeprecationCheck
    unresolved_calls: int  # call sites the graph couldn't resolve: unseen by the check
    python: str  # the stdlib version deprecations are judged against

    @property
    def third_party(self) -> list[PackageEntry]:
        return [p for p in self.packages if not p.stdlib]

    def count(self, urgency: Urgency) -> int:
        return sum(1 for p in self.packages if p.urgency is urgency)


def _version(text: str | None) -> Version | None:
    try:
        return Version(text) if text else None
    except InvalidVersion:
        return None


def _upgrade(advisories: list[LocatedFinding]) -> tuple[str | None, int]:
    fixes = [_version(lf.raw.fixed_in) for lf in advisories]
    known = [v for v in fixes if v is not None]
    return (str(max(known)) if known else None), sum(1 for v in fixes if v is None)


@dataclass
class _Builder:
    name: str
    modules: set[str] = field(default_factory=set)
    users: dict[str, Node | None] = field(default_factory=dict)
    references: int = 0
    stdlib: bool = False
    advisories: list[LocatedFinding] = field(default_factory=list)
    deprecated: list[DeprecatedUse] = field(default_factory=list)


def build_deps_report(scan: ScanReport) -> DepsReport:
    """Group one scan's dependency facts by package and classify each by reachability."""
    graph = scan.graph
    sites = list(graph.environment.site_packages)
    owners = module_distributions(sites)
    installed = {canonical(d): d for d in owners.values()}  # spell names as installed
    versions = installed_versions(sites)
    stdlib_names = sys.stdlib_module_names
    trace = reachability_tracer(graph)

    builders: dict[str, _Builder] = {}

    def entry_for(module: str) -> _Builder:
        name = owners.get(module, module)
        key = canonical(name)
        builder = builders.setdefault(key, _Builder(name))
        builder.modules.add(module)
        builder.stdlib = module in stdlib_names and module not in owners
        return builder

    for ref in graph.external_refs:
        if ref.package in stdlib_names and ref.package not in owners:
            continue  # the stdlib is listed only when it deprecates something the repo calls
        builder = entry_for(ref.package)
        builder.references += 1
        builder.users.setdefault(ref.node_id, None)

    for use in graph.deprecated_uses:
        builder = entry_for(use.package)
        builder.deprecated.append(use)
        if builder.stdlib:
            builder.references += 1
            builder.users.setdefault(use.node_id, None)

    for lf in scan.findings:
        if lf.finding.source is not FindingSource.OSV or lf.raw.package is None:
            continue
        modules = sorted(import_names(lf.raw.package, sites))
        known = [m for m in modules if canonical(owners.get(m, m)) in builders]
        if known:
            builder = entry_for(known[0])
        else:
            key = canonical(lf.raw.package)
            builder = builders.setdefault(key, _Builder(installed.get(key, lf.raw.package)))
            builder.modules.update(modules)
        builder.advisories.append(lf)
        for node in lf.anchors:
            builder.users.setdefault(node.id, node)

    packages = [_finish(b, versions, trace) for b in builders.values()]
    packages.sort(
        key=lambda p: (
            _URGENCY_ORDER[p.urgency],
            -len(p.advisories),
            _SEVERITY_ORDER.get(p.worst_severity, 9) if p.worst_severity else 9,
            -p.deprecated_calls,
            -p.references,
            p.name.lower(),
        )
    )
    osv = next((r for r in scan.results if r.source is FindingSource.OSV), None)
    return DepsReport(
        packages=packages,
        osv=osv,
        check=graph.deprecation_check,
        unresolved_calls=graph.coverage.unresolved,
        python=f"{sys.version_info.major}.{sys.version_info.minor}",
    )


def _finish(b: _Builder, versions: dict[str, str], trace: Tracer) -> PackageEntry:
    modules = sorted(b.modules)
    version = next((versions[m] for m in modules if m in versions), None)
    declared = next((lf.raw.package_version for lf in b.advisories if lf.raw.package_version), None)
    via = sorted({v for lf in b.advisories for v in lf.via})
    users = sorted(b.users)

    apis: dict[str, DeprecatedApi] = {}
    for use in sorted(b.deprecated, key=lambda u: (u.symbol, u.node_id, u.line)):
        api = apis.setdefault(use.symbol, DeprecatedApi(use.symbol, use.marker))
        api.calls.append(DeprecatedCall(use, trace([use.node_id])))
    deprecated = sorted(
        apis.values(), key=lambda a: (_REACH_ORDER[a.reach.reachable], -len(a.calls), a.symbol)
    )

    # Nothing in the repo uses it (an unused pin): nothing to trace, so unknown.
    usage = trace(users, imported=True) if users else StaticEvidence(reachable=Reachability.UNKNOWN)
    upgrade_to, unfixed = _upgrade(b.advisories)
    if b.advisories:
        reach = _most_reachable(
            [lf.finding.static_evidence for lf in b.advisories if lf.finding.static_evidence]
        )
        urgency = _ADVISORY_URGENCY[reach.reachable]
    else:
        urgency = Urgency.MIGRATE if deprecated else Urgency.OK
    return PackageEntry(
        name=b.name,
        modules=modules,
        version=version,
        declared=declared,
        stdlib=b.stdlib,
        users=users,
        references=b.references,
        usage=usage,
        via=via,
        advisories=b.advisories,
        upgrade_to=upgrade_to,
        unfixed=unfixed,
        deprecated=deprecated,
        urgency=urgency,
    )


def _evidence(ev: StaticEvidence) -> dict[str, Any]:
    return {"reachable": ev.reachable.value, "path": ev.path, "blast_radius": ev.blast_radius}


def deps_payload(report: DepsReport) -> dict[str, Any]:
    """The dependency report as JSON — the ``dependencies`` key of a scan report."""
    osv = report.osv
    deprecated_calls = [c for p in report.packages for a in p.deprecated for c in a.calls]
    by_reach: dict[str, int] = defaultdict(int)
    for call in deprecated_calls:
        by_reach[call.evidence.reachable.value] += 1
    return {
        "summary": {
            "packages": len(report.third_party),
            **{u.value: report.count(u) for u in Urgency},
            "deprecated_apis": sum(len(p.deprecated) for p in report.packages),
            "deprecated_calls": len(deprecated_calls),
            "deprecated_calls_by_reach": {r.value: by_reach.get(r.value, 0) for r in Reachability},
        },
        "osv": {
            "status": osv.status.value if osv else "not_run",
            "detail": osv.detail if osv else None,
        },
        "deprecation_check": {
            "external_calls_checked": report.check.checked,
            "without_source": report.check.no_source,
            "unresolved_calls": report.unresolved_calls,
            "stdlib_python": report.python,
        },
        "upgrade_note": (
            "'upgrade_to' is the smallest release fixing every known advisory in the offline "
            "OSV database, not the latest release: looking that up would send the dependency "
            "list off this machine."
        ),
        "packages": [
            {
                "name": p.name,
                "modules": p.modules,
                "version": p.version,
                "declared": p.declared,
                "stdlib": p.stdlib,
                "urgency": p.urgency.value,
                "references": p.references,
                "files": p.files,
                "users": p.users,
                "usage": _evidence(p.usage),
                "via": p.via,
                "advisories": [
                    {
                        "finding_id": lf.finding.id,
                        "id": lf.finding.rule_id,
                        "aliases": list(lf.raw.aliases),
                        "severity": lf.raw.severity.value,
                        "summary": lf.raw.message,
                        "fixed_in": lf.raw.fixed_in,
                        "reachable": (
                            lf.finding.static_evidence.reachable.value
                            if lf.finding.static_evidence
                            else Reachability.UNKNOWN.value
                        ),
                    }
                    for lf in p.advisories
                ],
                "upgrade_to": p.upgrade_to,
                "unfixed": p.unfixed,
                "pin_is_stale": p.pin_is_stale,
                "deprecated": [
                    {
                        "symbol": a.symbol,
                        "kind": a.marker.kind.value,
                        "category": a.marker.category,
                        "message": a.marker.message,
                        "conditional": a.marker.conditional,
                        "reach": _evidence(a.reach),
                        "calls": [
                            {
                                "node_id": c.use.node_id,
                                "line": c.use.line,
                                **_evidence(c.evidence),
                            }
                            for c in a.calls
                        ],
                    }
                    for a in p.deprecated
                ],
            }
            for p in report.packages
        ],
    }
