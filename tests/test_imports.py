"""Import-graph tests (BUILD-PLAN §1).

Each fixture exercises a real layout: a package using relative imports
(sample_app), a single loose script (flask_app), and a Django project with
absolute app imports, a sibling-importing script outside any package, and the
``try: from .local_settings import *`` idiom whose target is gitignored in real
projects (django_app). An in-repo import we cannot find must survive as an
``unknown`` edge, never be dropped (PRODUCT.md §6).
"""

from __future__ import annotations

from pathlib import Path

from ravel.graph.imports import module_name
from ravel.graph.resolve import GraphResult, build_graph
from ravel.models import EdgeKind

FIXTURES = Path(__file__).parent.parent / "eval" / "fixtures"


def _imports(result: GraphResult) -> set[tuple[str, str, bool]]:
    """(src_file, dst_file_or_unknown, resolved) for every imports edge."""
    return {
        (e.src_id.removesuffix("::<file>"), e.dst_id.removesuffix("::<file>"), e.resolved)
        for e in result.edges
        if e.kind is EdgeKind.IMPORTS
    }


def _file_refs(result: GraphResult) -> set[tuple[str, str, str | None]]:
    """(file, package, symbol) for external refs recorded at file level by imports."""
    return {
        (r.node_id.removesuffix("::<file>"), r.package, r.symbol)
        for r in result.external_refs
        if r.node_id.endswith("::<file>")
    }


def test_module_names_follow_python_rules() -> None:
    assert module_name("polls/views.py") == "polls.views"
    assert module_name("polls/__init__.py") == "polls"
    assert module_name("__init__.py") == ""


def test_relative_imports_in_a_package() -> None:
    assert _imports(build_graph(FIXTURES / "sample_app")) == {
        ("app.py", "services.py", True),
        ("services.py", "utils.py", True),
    }


def test_third_party_imports_become_external_refs() -> None:
    refs = _file_refs(build_graph(FIXTURES / "sample_app"))
    assert {
        ("app.py", "fastapi", "FastAPI"),
        ("app.py", "fastapi", "HTTPException"),
        ("app.py", "pydantic", "BaseModel"),
    } <= refs
    assert not any(pkg == "__future__" for _, pkg, _ in refs)


def test_loose_script_imports_are_external() -> None:
    result = build_graph(FIXTURES / "flask_app")
    assert _imports(result) == set()
    assert _file_refs(result) == {("app.py", "flask", "Flask"), ("app.py", "flask", "request")}


def test_django_project_imports() -> None:
    edges = _imports(build_graph(FIXTURES / "django_app"))
    assert ("polls/urls.py", "polls/views.py", True) in edges  # `from . import views`
    assert ("polls/views.py", "polls/models.py", True) in edges  # `from .models import ...`


def test_script_outside_a_package_imports_its_sibling() -> None:
    edges = _imports(build_graph(FIXTURES / "django_app"))
    assert ("scripts/load_polls.py", "scripts/seed_data.py", True) in edges


def test_missing_in_repo_module_is_unknown_not_dropped() -> None:
    edges = _imports(build_graph(FIXTURES / "django_app"))
    assert ("mysite/settings.py", "unknown::mysite.local_settings", False) in edges
    refs = _file_refs(build_graph(FIXTURES / "django_app"))
    assert not any(pkg == "mysite" for _, pkg, _ in refs)  # not misfiled as third-party


def test_stdlib_and_django_imports_are_external() -> None:
    refs = _file_refs(build_graph(FIXTURES / "django_app"))
    assert ("manage.py", "os", None) in refs
    assert ("polls/views.py", "django", "render") in refs
