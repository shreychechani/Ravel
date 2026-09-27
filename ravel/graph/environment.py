"""Find the *scanned* repo's Python environment so Jedi can see its dependencies.

Without this, Jedi resolves against Ravel's own interpreter: every third-party
call in the target (``django.shortcuts.render``, ``flask.request``) is invisible
and lands as ``unknown``, while packages that happen to be installed alongside
Ravel resolve against the wrong versions. The Phase 1 coverage gate is
meaningless until resolution runs against the target's own dependencies
(BUILD-PLAN §1).

Discovery is **static and read-only** (PRODUCT.md §6): we locate the
virtualenv's ``site-packages`` on disk and hand Jedi an explicit ``sys_path``.
We deliberately do *not* use ``jedi.Project(environment_path=...)`` — that
launches the environment's interpreter as a subprocess, i.e. executes a binary
shipped inside the repo under analysis.

The resulting sys.path is Ravel's **stdlib only** (Jedi also carries typeshed
stubs) + the target's ``site-packages`` + the source roots its ``.pth`` files
add (editable installs). Ravel's own ``site-packages`` is never on it.
"""

from __future__ import annotations

import sysconfig
from dataclasses import dataclass, field
from pathlib import Path

from ravel.core.logging import get_logger

log = get_logger("ravel.graph.environment")

# Conventional in-repo virtualenv directory names, checked in order. Kept in
# step with ``ravel.ingest.loader.SKIP_DIRS`` so a venv is never parsed as source.
VENV_DIRS = (".venv", "venv", "env")


@dataclass(frozen=True)
class PythonEnv:
    """Where a scanned repo's third-party code lives, for resolution only."""

    venv: Path | None  # None => no environment found; stdlib-only resolution
    site_packages: tuple[Path, ...] = ()
    pth_paths: tuple[Path, ...] = field(default=())  # editable-install source roots

    @property
    def found(self) -> bool:
        return self.venv is not None and bool(self.site_packages)

    def describe(self) -> str:
        """One-line provenance for the CLI: which deps resolution could see."""
        if not self.found:
            return "none found — third-party calls unresolvable (pass --venv)"
        return str(self.venv)


def _is_venv(path: Path) -> bool:
    return path.is_dir() and (path / "pyvenv.cfg").is_file()


def _site_packages(venv: Path) -> list[Path]:
    """``lib/python3.X/site-packages`` (POSIX) or ``Lib/site-packages`` (Windows)."""
    found = sorted(p for p in venv.glob("lib/python3*/site-packages") if p.is_dir())
    windows = venv / "Lib" / "site-packages"
    if windows.is_dir():
        found.append(windows)
    return found


def _pth_paths(site_packages: Path) -> list[Path]:
    """Directories added by ``.pth`` files — how editable installs expose source.

    Only plain path lines are honoured; ``import ...`` lines are code that the
    ``site`` module would execute, and we never execute anything from the repo.
    """
    out: list[Path] = []
    for pth in sorted(site_packages.glob("*.pth")):
        try:
            lines = pth.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#") or line.startswith(("import ", "import\t")):
                continue
            candidate = (site_packages / line).resolve()
            if candidate.is_dir():
                out.append(candidate)
    return out


def _stdlib_paths() -> list[str]:
    """Ravel's stdlib directories — never its ``site-packages``."""
    paths = sysconfig.get_paths()
    out: list[str] = []
    for key in ("stdlib", "platstdlib"):
        p = paths.get(key)
        if p and p not in out:
            out.append(p)
    dynload = Path(paths["stdlib"]) / "lib-dynload"
    if dynload.is_dir():
        out.append(str(dynload))
    return out


def discover_env(root: Path, venv: Path | None = None) -> PythonEnv:
    """Locate the environment to resolve ``root`` against.

    ``venv`` (the ``--venv`` flag) wins when given and must be a real
    virtualenv; otherwise the conventional in-repo directories are tried.
    Finding nothing is not an error — resolution degrades to stdlib-only and
    the coverage metric shows the cost honestly.
    """
    if venv is not None:
        venv = venv.resolve()
        if not _is_venv(venv):
            raise ValueError(f"{venv} is not a virtualenv (no pyvenv.cfg)")
        candidates = [venv]
    else:
        candidates = [root / name for name in VENV_DIRS if _is_venv(root / name)]

    for candidate in candidates:
        sites = _site_packages(candidate)
        if not sites:
            log.warning("virtualenv %s has no site-packages — skipping", candidate)
            continue
        pth = [p for site in sites for p in _pth_paths(site)]
        log.info("resolving against %s (%d site-packages dir(s))", candidate, len(sites))
        return PythonEnv(venv=candidate, site_packages=tuple(sites), pth_paths=tuple(pth))

    log.warning(
        "no virtualenv found in %s — third-party calls will be unresolved; pass --venv", root
    )
    return PythonEnv(venv=None)


def jedi_sys_path(env: PythonEnv) -> list[str]:
    """The explicit sys.path Jedi resolves against (the repo root is added by Jedi)."""
    return _stdlib_paths() + [str(p) for p in (*env.site_packages, *env.pth_paths)]
