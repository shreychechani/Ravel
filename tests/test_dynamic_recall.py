"""Dynamic-oracle recall scoring (research/07 item 1.4).

The end-to-end run executes flaskr's test suite and needs Flask installed, so
it's manual (``uv run python -m eval.dynamic_recall --venv ...``; measured
2026-09-27: 39 observed, 35 recovered, 89.7%). These tests cover the scoring
and frame-naming logic offline, against the real flaskr static graph.
"""

from __future__ import annotations

from pathlib import Path

from eval.dynamic_recall import DEFAULT_FIXTURE, score
from eval.oracle.trace_calls import _name


def test_observed_calls_are_scored_against_the_static_graph() -> None:
    observed = {
        ("flaskr/blog.py::update", "flaskr/blog.py::get_post"),  # a plain static edge
        ("tests/conftest.py::auth", "tests/conftest.py::AuthActions.__init__"),  # constructor
        # Runtime dispatch through the decorator's `view` parameter: Ravel has
        # an unknown edge in wrapped_view, so the miss is flagged, not silent.
        ("flaskr/auth.py::login_required.wrapped_view", "flaskr/blog.py::create"),
        # A call the static graph has no trace of: `auth`'s only call resolves,
        # so there is no unknown edge in it to account for this one.
        ("tests/conftest.py::auth", "flaskr/blog.py::get_post"),
    }
    report = score(DEFAULT_FIXTURE, observed, venv=None)
    assert ("flaskr/blog.py::update", "flaskr/blog.py::get_post") in report.recovered
    assert ("tests/conftest.py::auth", "tests/conftest.py::AuthActions.__init__") in (
        report.recovered
    )
    assert report.misses == {
        ("flaskr/auth.py::login_required.wrapped_view", "flaskr/blog.py::create"): "unknown",
        ("tests/conftest.py::auth", "flaskr/blog.py::get_post"): "silent",
    }
    assert report.recall == 0.5


def test_frame_names_match_ravel_node_names(tmp_path: Path) -> None:
    source = tmp_path / "pkg" / "mod.py"
    source.parent.mkdir()
    source.write_text(
        "def outer():\n"
        "    def inner():\n"
        "        pass\n"
        "    return inner\n"
        "class K:\n"
        "    def m(self):\n"
        "        pass\n",
        encoding="utf-8",
    )
    module = compile(source.read_text(encoding="utf-8"), str(source), "exec")
    consts = {c.co_name: c for c in module.co_consts if hasattr(c, "co_name")}
    inner = next(c for c in consts["outer"].co_consts if hasattr(c, "co_name"))
    method = next(c for c in consts["K"].co_consts if hasattr(c, "co_name"))
    root = str(tmp_path.resolve()) + "/"

    assert _name(module, root) == "pkg/mod.py::<file>"
    assert _name(consts["outer"], root) == "pkg/mod.py::outer"
    assert _name(inner, root) == "pkg/mod.py::outer.inner"  # <locals> dropped
    assert _name(method, root) == "pkg/mod.py::K.m"
    assert _name(consts["K"], root) == "pkg/mod.py::<file>"  # class body → file


def test_non_source_frames_are_ignored(tmp_path: Path) -> None:
    root = str(tmp_path.resolve()) + "/"
    frozen = compile("x = 1", "<frozen posixpath>", "exec")
    template = compile("x = 1", str(tmp_path / "templates" / "base.html"), "exec")
    assert _name(frozen, root) is None
    assert _name(template, root) is None
