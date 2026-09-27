"""Record the repo-internal calls a test suite actually makes — a dynamic oracle.

Run by ``eval/dynamic_recall.py`` with the *fixture's* interpreter (so its
dependencies are importable). Standalone and stdlib-only on purpose: Ravel is
not installed in that environment.

    <venv>/bin/python trace_calls.py <repo_root> <out.json> [pytest args...]

Every Python-level call whose caller *and* callee code live under
``repo_root`` is recorded as ``[caller, callee]``, each named
``"<rel_path>::<qualified_name>"`` to match Ravel's node naming:

- ``co_qualname`` with ``<locals>.`` removed (``f.<locals>.g`` → ``f.g``);
- ``<module>`` → the FILE node (``"<rel_path>::<file>"``);
- a lambda / genexpr / comprehension frame is named after its lexically
  enclosing def (Ravel attributes calls inside them there too); as a callee
  it is skipped — Ravel has no node for it;
- a class *body* is not a call: as a callee it is skipped, and as a caller
  (a decorator applied inside a class body) it is named after the enclosing
  def or file, which is where Ravel attributes class-body calls.

Calls made *by framework code* into the repo (Flask dispatching a view,
pytest calling a test) have a non-repo caller and are not recorded: they are
not edges of the repo's own call graph.

**Eval-only.** This executes the fixture's tests. Ravel itself never runs
scanned code (PRODUCT.md §6); this is run only on pinned, vendored fixtures,
on a throwaway copy.
"""

from __future__ import annotations

import inspect
import json
import os
import sys
import threading
from functools import cache
from pathlib import Path
from types import FrameType
from typing import Any


@cache
def _real(filename: str) -> str:
    # Resolve symlinks (macOS /var -> /private/var) so every module compares alike.
    return os.path.realpath(filename)


def _is_function(code: Any) -> bool:
    return bool(code.co_flags & inspect.CO_OPTIMIZED)


def _name(code: Any, root: str) -> str | None:
    # Only real Python source: skips "<frozen ...>" pseudo-files and Jinja's
    # compiled templates (their co_filename is the .html file).
    if code.co_filename.startswith("<") or not code.co_filename.endswith(".py"):
        return None
    filename = _real(code.co_filename)
    if not filename.startswith(root):
        return None
    rel = Path(filename).relative_to(root).as_posix()
    qual = code.co_qualname
    if not _is_function(code):
        # Module or class body: attribute to the enclosing def, else the file.
        qual = qual.rsplit(".<locals>.", 1)[0] if ".<locals>." in qual else "<module>"
    qual = qual.replace("<locals>.", "")
    if qual == "<module>":
        return f"{rel}::<file>"
    parts = [p for p in qual.split(".") if not p.startswith("<")]
    if not parts:  # a module-level lambda / genexpr
        return f"{rel}::<file>"
    return f"{rel}::{'.'.join(parts)}"


def main() -> int:
    root = _real(sys.argv[1]) + "/"
    out = Path(sys.argv[2])
    pytest_args = sys.argv[3:]
    pairs: set[tuple[str, str]] = set()

    def profile(frame: FrameType, event: str, arg: Any) -> None:
        if event != "call" or frame.f_back is None or not _is_function(frame.f_code):
            return  # module / class bodies are not calls
        if frame.f_code.co_qualname.rsplit(".", 1)[-1].startswith("<"):
            return  # lambda/genexpr callee: no Ravel node to match
        callee = _name(frame.f_code, root)
        if callee is None:
            return
        caller = _name(frame.f_back.f_code, root)
        if caller is not None:
            pairs.add((caller, callee))

    import pytest  # the fixture's pytest, from its own environment

    threading.setprofile(profile)
    sys.setprofile(profile)
    try:
        code = pytest.main(["-q", "-p", "no:cacheprovider", *pytest_args])
    finally:
        sys.setprofile(None)
        threading.setprofile(None)

    out.write_text(json.dumps({"exit": int(code), "pairs": sorted(pairs)}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
