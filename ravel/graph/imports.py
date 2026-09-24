"""Build ``imports`` edges between files with Python's ``ast``.

Deliberately not grimp: grimp only graphs *packages*, so it cannot see loose
top-level modules (``manage.py``, a root ``app.py``) and it has to mutate the
process-wide ``sys.path``. Here we resolve against the files we already
discovered, so every layout — package, loose scripts, ``src/`` — works the same.

An import of an in-repo module becomes a FILE → FILE ``imports`` edge. An import
whose top-level name is in-repo but whose module doesn't exist (or a relative
import that climbs past the root) becomes an ``unknown::<module>`` edge with
``resolved=False`` — never dropped (PRODUCT.md §6). Everything else is a
third-party / stdlib ``ExternalRef``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.logging import get_logger
from ravel.ingest.loader import PYTHON_SUFFIXES, SourceFile
from ravel.models import Edge, EdgeKind, ExternalRef

log = get_logger("ravel.graph.imports")


@dataclass
class ImportResult:
    edges: list[Edge] = field(default_factory=list)
    external_refs: list[ExternalRef] = field(default_factory=list)


def module_name(rel_path: str) -> str:
    """``pkg/mod.py`` → ``pkg.mod``; ``pkg/__init__.py`` → ``pkg``; root ``__init__`` → ``""``."""
    stem = str(Path(rel_path).with_suffix("")).replace("\\", "/")
    parts = stem.split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def module_index(files: list[SourceFile], root: Path) -> dict[str, str]:
    """Map every importable module name to its file's repo-relative path.

    A ``src/`` layout is also importable without the ``src.`` prefix, and when
    the scan root is itself a package its modules are also importable under the
    root's name (``sample_app.services``). ``.py`` wins over a ``.pyi`` stub.
    """
    index: dict[str, str] = {}
    root_pkg = root.name if (root / "__init__.py").exists() and root.name.isidentifier() else None
    # .py before .pyi/.pyw so the real module claims the name first.
    for source in sorted(files, key=lambda f: (Path(f.rel_path).suffix != ".py", f.rel_path)):
        if Path(source.rel_path).suffix not in PYTHON_SUFFIXES:
            continue
        name = module_name(source.rel_path)
        aliases = [name]
        if name == "src" or name.startswith("src."):
            aliases.append(name[len("src.") :] if name != "src" else "")
        if root_pkg is not None:
            aliases.append(f"{root_pkg}.{name}" if name else root_pkg)
        for alias in aliases:
            index.setdefault(alias, source.rel_path)  # "" = a root-level __init__
    return index


def build_import_edges(files: list[SourceFile], root: Path) -> ImportResult:
    """Resolve every import statement in ``files`` into edges / external refs."""
    index = module_index(files, root)
    package_dirs = {
        str(Path(f.rel_path).parent) for f in files if Path(f.rel_path).stem == "__init__"
    }
    top_levels = {name.split(".")[0] for name in index if name}
    result = ImportResult()
    seen_edges: set[tuple[str, str]] = set()
    seen_refs: set[tuple[str, str, str | None]] = set()

    def edge(src_rel: str, dst_id: str, resolved: bool) -> None:
        src_id = f"{src_rel}::<file>"
        if (src_id, dst_id) in seen_edges:
            return
        seen_edges.add((src_id, dst_id))
        result.edges.append(
            Edge(src_id=src_id, dst_id=dst_id, kind=EdgeKind.IMPORTS, resolved=resolved)
        )

    def external(src_rel: str, module: str, symbol: str | None) -> None:
        package = module.split(".")[0]
        if package == "__future__" or (src_rel, package, symbol) in seen_refs:
            return
        seen_refs.add((src_rel, package, symbol))
        result.external_refs.append(
            ExternalRef(node_id=f"{src_rel}::<file>", package=package, symbol=symbol)
        )

    def target(src_rel: str, module: str, symbol: str | None, sibling: str | None) -> None:
        """Route one imported module to an edge, an unknown edge, or an external ref.

        ``sibling`` is the dotted dir of a script outside any package: running it
        puts its own directory on ``sys.path``, so ``import helpers`` there means
        the neighbouring ``helpers.py``.
        """
        if sibling and f"{sibling}.{module}" in index:
            module = f"{sibling}.{module}"
        if module in index:
            edge(src_rel, f"{index[module]}::<file>", resolved=True)
        elif module.split(".")[0] in top_levels:
            edge(src_rel, f"unknown::{module}", resolved=False)
        else:
            external(src_rel, module, symbol)

    for source in files:
        try:
            tree = ast.parse(source.content, filename=source.rel_path)
        except (SyntaxError, ValueError) as exc:
            log.warning("imports skipped for %s: unparsable (%s)", source.rel_path, exc)
            continue

        is_pkg = Path(source.rel_path).stem == "__init__"
        here = module_name(source.rel_path)
        package = here if is_pkg else here.rpartition(".")[0]
        parent_dir = str(Path(source.rel_path).parent)
        sibling = package if package and parent_dir not in package_dirs else None

        for stmt in ast.walk(tree):
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    target(source.rel_path, alias.name, None, sibling)
            elif isinstance(stmt, ast.ImportFrom):
                base = _absolute(package, stmt.module, stmt.level)
                near = sibling if stmt.level == 0 else None
                if base is None:  # relative import climbs past the repo root
                    edge(source.rel_path, f"unknown::{'.' * stmt.level}{stmt.module or ''}", False)
                    continue
                for alias in stmt.names:
                    # `from pkg import submodule` imports the submodule itself.
                    sub = f"{base}.{alias.name}" if base else alias.name
                    if alias.name != "*" and (sub in index or (near and f"{near}.{sub}" in index)):
                        target(source.rel_path, sub, None, near)
                    elif base:
                        symbol = None if alias.name == "*" else alias.name
                        target(source.rel_path, base, symbol, near)
                    elif "" in index:  # `from . import name` → the root __init__
                        edge(source.rel_path, f"{index['']}::<file>", resolved=True)
                    else:
                        edge(source.rel_path, f"unknown::{sub}", resolved=False)

    return result


def _absolute(package: str, module: str | None, level: int) -> str | None:
    """Resolve a (possibly relative) ``from`` import to an absolute module name."""
    if level == 0:
        return module or ""
    parts = package.split(".") if package else []
    if level - 1 > len(parts):
        return None
    base = parts[: len(parts) - (level - 1)]
    if module:
        base.append(module)
    return ".".join(base)
