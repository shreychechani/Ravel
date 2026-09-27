"""Distribution → import-name mapping and requirement graph, read from dist-info."""

from __future__ import annotations

from pathlib import Path

from ravel.deps.distributions import import_names, required_by, requirements_graph


def test_top_level_txt_names_renamed_packages(tmp_path: Path) -> None:
    info = tmp_path / "PyYAML-5.3.1.dist-info"
    info.mkdir()
    (info / "top_level.txt").write_text("_yaml\nyaml\n", encoding="utf-8")
    assert import_names("pyyaml", [tmp_path]) == {"yaml", "_yaml"}


def test_record_is_the_fallback_without_top_level(tmp_path: Path) -> None:
    info = tmp_path / "beautifulsoup4-4.12.0.dist-info"
    info.mkdir()
    (info / "RECORD").write_text(
        "bs4/__init__.py,sha256=x,1\nbs4/element.py,sha256=y,2\n"
        "beautifulsoup4-4.12.0.dist-info/METADATA,,\nsix.py,sha256=z,3\n",
        encoding="utf-8",
    )
    assert import_names("beautifulsoup4", [tmp_path]) == {"bs4", "six"}


def test_not_installed_falls_back_to_the_normalized_name() -> None:
    assert import_names("Django") == {"django"}
    assert import_names("typing-extensions") == {"typing_extensions"}


def test_required_by_is_transitive_and_skips_extras(tmp_path: Path) -> None:
    for name, reqs in {
        "app-kit": ["Django>=3"],
        "Django": ["sqlparse (>=0.2.2)", 'bcrypt; extra == "bcrypt"'],
        "sqlparse": [],
    }.items():
        info = tmp_path / f"{name}-1.0.dist-info"
        info.mkdir()
        body = "\n".join([f"Name: {name}", *(f"Requires-Dist: {r}" for r in reqs)])
        (info / "METADATA").write_text(body + "\n", encoding="utf-8")
    graph = requirements_graph([tmp_path])
    assert required_by("sqlparse", graph) == {"django", "app-kit"}
    assert required_by("bcrypt", graph) == set()  # only an optional extra
