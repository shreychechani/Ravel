"""Deprecated APIs are read off the libraries themselves — never a list of ours.

The markers come from real code: the stdlib running these tests (Python 3.12,
pinned in ``.python-version``), the typeshed stubs Jedi bundles, and OWASP
PyGoat's real ``views.py`` calling them. The third-party package is a
``site-packages`` stand-in whose deprecated function is Pillow 10.3's own.
"""

from __future__ import annotations

import ast
import locale
import shutil
from pathlib import Path

import jedi
import pytest
from ravel.deps.deprecations import DeprecationReader, MarkerKind
from ravel.graph.resolve import build_graph

FIXTURES = Path(__file__).parent.parent / "eval" / "fixtures"
PYGOAT = FIXTURES / "pygoat_views"
TYPESHED = Path(jedi.__file__).parent / "third_party" / "typeshed" / "stdlib"

# Pillow 10.3.0, src/PIL/ImageMath.py (HPND licence), trimmed to the functions
# PyGoat touches: ``eval`` was deprecated in 10.3 via Pillow's own helper.
_IMAGEMATH = """
from ._deprecate import deprecate


def unsafe_eval(expression, options={}, **kw):
    return None


def eval(expression, _dict={}, **kw):
    deprecate(
        "ImageMath.eval",
        12,
        "ImageMath.lambda_eval or ImageMath.unsafe_eval",
    )
    return unsafe_eval(expression, _dict, **kw)
"""


def _def_line(path: Path, name: str) -> int:
    tree = ast.parse(path.read_bytes())
    return next(
        n.lineno
        for n in ast.walk(tree)
        if isinstance(n, ast.FunctionDef | ast.ClassDef) and n.name == name
    )


def test_stub_decorator_marks_a_compiled_stdlib_function() -> None:
    stub = TYPESHED / "datetime.pyi"
    marker = DeprecationReader().marker(stub, _def_line(stub, "utcnow"))
    assert marker is not None and marker.kind is MarkerKind.DECORATOR
    assert not marker.conditional
    assert "timezone-aware" in (marker.message or "")


def test_stdlib_warnings_deprecated_helper_is_rendered_readably() -> None:
    source = Path(locale.__file__)
    marker = DeprecationReader().marker(source, _def_line(source, "getdefaultlocale"))
    assert marker is not None and marker.kind is MarkerKind.WARNING
    assert marker.message is not None
    assert "'locale.getdefaultlocale' is deprecated" in marker.message
    assert "{remove}" not in marker.message  # formatted the way the stdlib formats it


def test_undeprecated_functions_carry_no_marker() -> None:
    source = Path(locale.__file__)
    reader = DeprecationReader()
    assert reader.marker(source, _def_line(source, "setlocale")) is None
    stub = TYPESHED / "datetime.pyi"
    assert reader.marker(stub, _def_line(stub, "now")) is None


def test_a_warning_on_one_branch_is_conditional(tmp_path: Path) -> None:
    # The shape of ssl.SSLContext.__new__ / pyjwt's decode: only some arguments warn.
    lib = tmp_path / "lib.py"
    lib.write_text(
        "import warnings\n"
        "def decode(token, verify=None):\n"
        "    if verify is not None:\n"
        "        warnings.warn('verify= is deprecated', DeprecationWarning)\n"
        "    return token\n",
        encoding="utf-8",
    )
    marker = DeprecationReader().marker(lib, 2)
    assert marker is not None and marker.conditional
    assert marker.category == "DeprecationWarning"


def test_lookalike_names_are_not_markers(tmp_path: Path) -> None:
    # typing.py calls a *class* named _DeprecatedGenericAlias; click has a
    # _format_deprecated_label formatter. Neither raises a warning.
    lib = tmp_path / "lib.py"
    lib.write_text(
        "class _DeprecatedGenericAlias: ...\n"
        "def _format_deprecated_label(x): return x\n"
        "Pattern = _DeprecatedGenericAlias()\n"
        "def label(x):\n"
        "    return _format_deprecated_label(x)\n",
        encoding="utf-8",
    )
    reader = DeprecationReader()
    assert reader.marker(lib, 4) is None  # no module-level marker either


def test_pygoat_utcnow_calls_are_found_and_now_is_not() -> None:
    graph = build_graph(PYGOAT)
    uses = [u for u in graph.deprecated_uses if u.symbol == "datetime.datetime.utcnow"]
    # views.py lines 1103-1104, both inside sec_misconfig_lab3.
    assert [u.line for u in uses] == [1103, 1104]
    assert {u.node_id.split("::")[1] for u in uses} == {"sec_misconfig_lab3"}
    assert all(u.package == "datetime" and u.version is None for u in uses)
    assert not any(u.symbol == "datetime.datetime.now" for u in graph.deprecated_uses)
    check = graph.deprecation_check
    assert check.checked > 0 and check.deprecated == len(graph.deprecated_uses)


@pytest.fixture
def pygoat_with_pillow(tmp_path: Path) -> Path:
    repo = tmp_path / "pygoat"
    shutil.copytree(PYGOAT, repo)
    site = repo / ".venv" / "lib" / "python3.12" / "site-packages"
    (site / "PIL").mkdir(parents=True)
    (repo / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (site / "PIL" / "__init__.py").write_text("", encoding="utf-8")
    (site / "PIL" / "Image.py").write_text("def open(fp): ...\n", encoding="utf-8")
    (site / "PIL" / "_deprecate.py").write_text(
        "def deprecate(deprecated, when, replacement=None): ...\n", encoding="utf-8"
    )
    (site / "PIL" / "ImageMath.py").write_text(_IMAGEMATH, encoding="utf-8")
    info = site / "pillow-10.3.0.dist-info"
    info.mkdir()
    (info / "top_level.txt").write_text("PIL\n", encoding="utf-8")
    return repo


def test_third_party_deprecation_carries_the_installed_version(pygoat_with_pillow: Path) -> None:
    graph = build_graph(pygoat_with_pillow)
    (use,) = [u for u in graph.deprecated_uses if u.package == "PIL"]
    assert use.symbol == "PIL.ImageMath.eval"
    assert use.line == 588  # `output = ImageMath.eval(function_str, ...)`
    assert use.version == "10.3.0"
    assert use.marker.category == "deprecate"
    assert not use.marker.conditional
