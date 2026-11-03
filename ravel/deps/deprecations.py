"""Is a third-party function deprecated? Ask the library, not a rule list.

Ravel writes no detection rules (PRODUCT.md §6), and that includes a hand-kept
list of deprecated APIs. A library already says it, in code its authors wrote:

- a ``@deprecated`` decorator — PEP 702's ``warnings.deprecated`` /
  ``typing_extensions.deprecated`` (typeshed marks the stdlib this way) or a
  helper named like one (``@_deprecated``, ``@deprecate_kwarg``);
- a deprecation warning raised in the body — ``warnings.warn(msg,
  DeprecationWarning)``, a framework's own category (Django's
  ``RemovedInDjango40Warning``, SQLAlchemy's ``SADeprecationWarning``), or a
  helper such as the stdlib's ``warnings._deprecated`` / ``warn_deprecated``;
- either of those at the top of the module, which deprecates everything in it
  (``imp``, ``cgi``, ``distutils``).

When the call graph resolves a call into an installed package, the resolver
hands the definition's file and line here; we parse that file with ``ast``
(read, never imported or run) and look at that one definition. A warning
nested under an ``if`` / ``try`` / loop fires only for some arguments or
states, so it is reported as *conditional* rather than certain.

Known gaps, reported rather than hidden: a deprecation implemented through a
module ``__getattr__`` (Flask's ``flask.Markup``) is invisible, and so is any
deprecated call the graph could not resolve — the deps report states how many
external calls were checked next to the unresolved count.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from ravel.core.logging import get_logger

log = get_logger("ravel.deps.deprecations")

_MESSAGE_MAX = 240
# Warning categories that mean "this goes away": the stdlib's, plus framework
# conventions (``RemovedInDjango50Warning``, ``SADeprecationWarning``).
_CATEGORY = re.compile(r"(Deprecat\w*Warning|FutureWarning|RemovedIn\w*Warning)$")
_WARN_CALLS = {"warn", "warn_explicit"}
_DEF_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
# Statements whose bodies run only sometimes. A ``try`` / ``with`` body runs
# every time; only an ``except`` handler is conditional.
_BRANCHES = (ast.If, ast.IfExp, ast.For, ast.AsyncFor, ast.While, ast.Match, ast.ExceptHandler)
# Decorators that deprecate the whole definition; others named like them
# (``deprecate_kwarg``, ``_deprecate_positional_args``) cover only some calls.
_WHOLE_DECORATORS = {"deprecated", "_deprecated"}
# A helper *function* that raises the warning: ``warn_deprecated``,
# ``deprecate``. Lower-case, so classes (``_DeprecatedGenericAlias(...)``)
# don't match, and starting with the verb, so formatters
# (``_format_deprecated_label``) don't either.
_HELPER = re.compile(r"^_*(warn_)?deprecat(e|ed|ion)?(_warning|_function)?$")


class MarkerKind(StrEnum):
    DECORATOR = "decorator"  # @deprecated(...) on the definition
    WARNING = "warning"  # a deprecation warning raised in its body
    MODULE = "module"  # raised when the module is imported: everything in it


@dataclass(frozen=True)
class DeprecationMarker:
    kind: MarkerKind
    message: str | None
    category: str | None  # warning class or decorator name, e.g. "RemovedInDjango40Warning"
    conditional: bool  # raised only on some paths (some arguments / states)


def _terminal(expr: ast.expr) -> str:
    """``warnings.warn`` → ``warn``; ``deprecated("x")`` → ``deprecated``."""
    if isinstance(expr, ast.Call):
        expr = expr.func
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Name):
        return expr.id
    return ""


def _text(expr: ast.expr | None) -> str | None:
    """A readable message from a string literal, f-string or concatenation."""
    if expr is None:
        return None
    if isinstance(expr, ast.Constant) and isinstance(expr.value, str):
        text = expr.value
    elif isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Mod)):
        left = _text(expr.left)
        if left is None:
            return None
        right = _text(expr.right) if isinstance(expr.op, ast.Add) else None
        text = left + (right or "")
    elif isinstance(expr, ast.JoinedStr):
        text = ast.unparse(expr)[2:-1]  # f"..." → ...
    else:
        return None
    text = " ".join(text.split())
    return text[: _MESSAGE_MAX - 1] + "…" if len(text) > _MESSAGE_MAX else text


def _first_arg(call: ast.Call, keyword: str) -> ast.expr | None:
    if call.args:
        return call.args[0]
    return next((k.value for k in call.keywords if k.arg == keyword), None)


def _warning(call: ast.Call, conditional: bool, kind: MarkerKind) -> DeprecationMarker | None:
    """The marker a call raises, if it is a deprecation warning."""
    name = _terminal(call.func)
    if name in _WARN_CALLS:
        first = _first_arg(call, "message")
        if isinstance(first, ast.Call) and _CATEGORY.search(_terminal(first)):
            # warnings.warn(DeprecationWarning("...")): the category is the instance.
            message = _text(_first_arg(first, ""))
            return DeprecationMarker(kind, message, _terminal(first), conditional)
        category = call.args[1] if len(call.args) > 1 else None
        category = next((k.value for k in call.keywords if k.arg == "category"), category)
        label = _terminal(category) if category is not None else ""
        if not _CATEGORY.search(label):
            return None
        return DeprecationMarker(kind, _text(first), label, conditional)
    if name == "_deprecated":
        return DeprecationMarker(kind, _stdlib_message(call), name, conditional)
    if _HELPER.match(name):  # util.warn_deprecated(msg, ...), deprecate(msg)
        arg = next((k.value for k in call.keywords if k.arg in ("message", "msg")), None)
        if arg is None and call.args:
            arg = call.args[0]
        return DeprecationMarker(kind, _text(arg), name, conditional)
    return None


def _stdlib_message(call: ast.Call) -> str | None:
    """``warnings._deprecated(name, message=..., remove=(3, 15))``, as the stdlib renders it."""
    kw = {k.arg: k.value for k in call.keywords if k.arg}
    name = _text(call.args[0]) if call.args else _text(kw.get("name"))
    template = _text(call.args[1] if len(call.args) > 1 else kw.get("message"))
    template = template or "{name!r} is deprecated and slated for removal in Python {remove}"
    remove = kw.get("remove")
    try:
        version = ast.literal_eval(remove) if remove is not None else None
    except ValueError:
        version = None
    removal = ".".join(str(p) for p in version[:2]) if isinstance(version, tuple) else "a future"
    if name is None:
        # Usually `__name__`: the module deprecating itself.
        return f"deprecated and slated for removal in Python {removal}"
    return template.replace("{name!r}", repr(name)).replace("{remove}", removal)


def _scan_body(
    body: list[ast.stmt], kind: MarkerKind, conditional: bool = False
) -> DeprecationMarker | None:
    """The first deprecation warning raised by these statements, preferring
    an unconditional one. Nested functions and classes are not this body."""
    found: DeprecationMarker | None = None

    def visit(node: ast.AST, branched: bool) -> DeprecationMarker | None:
        nonlocal found
        if isinstance(node, (*_DEF_TYPES, ast.Lambda)):
            return None
        if isinstance(node, ast.Call):
            marker = _warning(node, branched, kind)
            if marker is not None:
                if not branched:
                    return marker
                found = found or marker
        inner = branched or isinstance(node, _BRANCHES)
        for child in ast.iter_child_nodes(node):
            # The test of an `if` runs every time; only its branches are conditional.
            hit = visit(child, branched if child is getattr(node, "test", None) else inner)
            if hit is not None:
                return hit
        return None

    for stmt in body:
        hit = visit(stmt, conditional)
        if hit is not None:
            return hit
    return found


def _decorator(
    defn: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> DeprecationMarker | None:
    for dec in defn.decorator_list:
        name = _terminal(dec)
        if "deprecat" in name.lower():
            message = _text(_first_arg(dec, "reason")) if isinstance(dec, ast.Call) else None
            partial = name not in _WHOLE_DECORATORS
            return DeprecationMarker(MarkerKind.DECORATOR, message, name, conditional=partial)
    return None


def _definition_marker(
    defn: ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef,
) -> DeprecationMarker | None:
    marker = _decorator(defn)
    if marker is not None:
        return marker
    if isinstance(defn, ast.ClassDef):
        # Instantiating a class runs its constructor: look there.
        for item in defn.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name in (
                "__init__",
                "__new__",
            ):
                marker = _decorator(item) or _scan_body(item.body, MarkerKind.WARNING)
                if marker is not None:
                    return marker
        return None
    return _scan_body(defn.body, MarkerKind.WARNING)


@dataclass
class _ParsedModule:
    by_line: dict[int, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef]
    module_marker: DeprecationMarker | None


class DeprecationReader:
    """Look up deprecation markers on library definitions, one parse per file.

    Lives for one graph build; libraries don't change mid-build, so files are
    memoized by path for that run only — nothing is persisted.
    """

    def __init__(self) -> None:
        self._modules: dict[Path, _ParsedModule | None] = {}
        self.files_read = 0
        self.files_unreadable = 0

    def _parse(self, path: Path) -> _ParsedModule | None:
        if path in self._modules:
            return self._modules[path]
        parsed: _ParsedModule | None = None
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (OSError, SyntaxError, ValueError) as exc:
            log.debug("cannot read %s for deprecation markers: %s", path, exc)
            self.files_unreadable += 1
        else:
            self.files_read += 1
            by_line = {n.lineno: n for n in ast.walk(tree) if isinstance(n, _DEF_TYPES)}
            parsed = _ParsedModule(by_line, _module_marker(tree))
        self._modules[path] = parsed
        return parsed

    def marker(self, module_path: Path | str, line: int | None) -> DeprecationMarker | None:
        """The deprecation marker on the definition at ``line`` of ``module_path``
        (its own, else its module's), or None if neither is marked."""
        parsed = self._parse(Path(module_path))
        if parsed is None:
            return None
        defn = parsed.by_line.get(line) if line is not None else None
        own = _definition_marker(defn) if defn is not None else None
        return own or parsed.module_marker


def _module_marker(tree: ast.Module) -> DeprecationMarker | None:
    """A deprecation warning every import of the module raises.

    Only an unconditional one counts: a module-level warning under ``if`` is
    about the environment (a missing C extension, an old Python), and would
    otherwise be pinned on every function the module defines.
    """
    top = [s for s in tree.body if not isinstance(s, (*_DEF_TYPES, ast.Import, ast.ImportFrom))]
    marker = _scan_body(top, MarkerKind.MODULE)
    return marker if marker is not None and not marker.conditional else None


@dataclass(frozen=True)
class DeprecatedUse:
    """One in-repo call (or base class) that lands on a deprecated library API."""

    node_id: str  # the calling function / class / file node
    line: int  # where the call is
    package: str  # top-level module the API lives in: "django", "datetime"
    symbol: str  # dotted name, e.g. "django.conf.urls.url"
    version: str | None  # installed release; None for the stdlib or without an env
    marker: DeprecationMarker


@dataclass
class DeprecationCheck:
    """How much of the external surface the deprecation check could actually see."""

    checked: int = 0  # resolved external call sites / bases looked up
    no_source: int = 0  # compiled with no stub, or the file couldn't be read
    deprecated: int = 0
