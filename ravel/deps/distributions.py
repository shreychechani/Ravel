"""Which import names does a PyPI distribution provide? (read-only)

OSV reports vulnerable *distributions* (``PyYAML``, ``beautifulsoup4``); the
graph records the *modules* code imports (``yaml``, ``bs4``). The mapping
lives in each installed distribution's ``*.dist-info`` metadata, which we read
from the scanned repo's environment — never by importing anything
(PRODUCT.md §6).

With no environment, or a distribution that isn't installed, the fallback is
the normalized name (``Django`` → ``django``), which is right for most
packages and wrong for the renamed ones — callers should treat a miss as
"not proven imported", not "proven unused".
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path


def canonical(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _dist_name(dist_info: Path) -> str:
    # "Django-3.2.dist-info" → "Django"; the version never contains "-" (PEP 427).
    return dist_info.name[: -len(".dist-info")].rsplit("-", 1)[0]


def _from_metadata(dist_info: Path) -> set[str]:
    top_level = dist_info / "top_level.txt"
    if top_level.is_file():
        names = {ln.strip() for ln in top_level.read_text(encoding="utf-8").splitlines()}
        return {n for n in names if n}
    record = dist_info / "RECORD"
    if not record.is_file():
        return set()
    found: set[str] = set()
    for line in record.read_text(encoding="utf-8").splitlines():
        first = line.split(",", 1)[0].split("/", 1)
        head = first[0]
        if not head or head.endswith((".dist-info", ".data")) or head in {"..", "__pycache__"}:
            continue
        if len(first) == 1:  # a top-level module file
            if head.endswith(".py"):
                found.add(head[:-3])
        else:
            found.add(head)
    return found


def import_names(distribution: str, site_packages: Iterable[Path] = ()) -> set[str]:
    """Top-level import names ``distribution`` provides (fallback: its own name)."""
    wanted = canonical(distribution)
    for site in site_packages:
        for dist_info in site.glob("*.dist-info"):
            if canonical(_dist_name(dist_info)) == wanted:
                names = _from_metadata(dist_info)
                if names:
                    return names
    return {wanted.replace("-", "_")}


def installed_versions(site_packages: Iterable[Path]) -> dict[str, str]:
    """Top-level import name → the installed distribution's version.

    Read from ``*.dist-info`` directory names (``Flask-3.1.3.dist-info``), so
    ``ExternalRef.version`` says which release the code calls into — what the
    dependency report needs (PRODUCT.md §4). The first site-packages wins, as
    on ``sys.path``.
    """
    versions: dict[str, str] = {}
    for site in site_packages:
        for dist_info in sorted(site.glob("*.dist-info")):
            stem = dist_info.name[: -len(".dist-info")]
            if "-" not in stem:
                continue
            name, version = stem.rsplit("-", 1)
            names = _from_metadata(dist_info) or {canonical(name).replace("-", "_")}
            for module in names:
                versions.setdefault(module, version)
    return versions


_REQUIRES = re.compile(r"^Requires-Dist:\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def requirements_graph(site_packages: Iterable[Path]) -> dict[str, set[str]]:
    """Installed distribution → the distributions it requires (canonical names).

    Read from each ``METADATA``'s ``Requires-Dist`` lines. Requirements gated
    on an extra (``; extra == "bcrypt"``) are optional and skipped; platform
    markers are kept — conservatively, a maybe-required package is required.
    """
    graph: dict[str, set[str]] = {}
    for site in site_packages:
        for dist_info in site.glob("*.dist-info"):
            metadata = dist_info / "METADATA"
            if not metadata.is_file():
                continue
            needs: set[str] = set()
            for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
                match = _REQUIRES.match(line)
                if match and "extra ==" not in line.replace("'", '"'):
                    needs.add(canonical(match.group(1)))
            graph.setdefault(canonical(_dist_name(dist_info)), set()).update(needs)
    return graph


def required_by(distribution: str, graph: dict[str, set[str]]) -> set[str]:
    """Every installed distribution that (transitively) requires ``distribution``."""
    reverse: dict[str, set[str]] = {}
    for parent, children in graph.items():
        for child in children:
            reverse.setdefault(child, set()).add(parent)
    seen: set[str] = set()
    frontier = [canonical(distribution)]
    while frontier:
        for parent in reverse.get(frontier.pop(), set()):
            if parent not in seen:
                seen.add(parent)
                frontier.append(parent)
    return seen
