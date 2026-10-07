"""Parser tests — assert we extract the right functions/classes/methods."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from ravel.graph.parse import parse_file
from ravel.ingest.loader import SourceFile
from ravel.models import NodeKind


def test_extracts_functions_and_classes(sample_files: dict[str, SourceFile]) -> None:
    nodes = parse_file(sample_files["services.py"])
    by_name = {n.qualified_name: n for n in nodes}

    assert "get_user" in by_name
    assert "create_user" in by_name
    assert "UserService" in by_name
    assert "UserService.find" in by_name  # method gets a qualified prefix

    assert by_name["UserService"].kind is NodeKind.CLASS
    assert by_name["UserService.find"].kind is NodeKind.FUNCTION


def test_docstring_captured(sample_files: dict[str, SourceFile]) -> None:
    nodes = parse_file(sample_files["utils.py"])
    helper = next(n for n in nodes if n.qualified_name == "unused_helper")
    assert helper.docstring is not None
    assert "dead-code" in helper.docstring


def test_line_spans_are_sane(sample_files: dict[str, SourceFile]) -> None:
    nodes = parse_file(sample_files["app.py"])
    for n in nodes:
        assert n.start_line >= 1
        assert n.end_line >= n.start_line


def test_real_django_views_parse_without_crashing() -> None:
    """tree-sitter 0.26.0 segfaulted on this file; run it in a subprocess so a crash fails here."""
    views = Path(__file__).parent.parent / "eval" / "fixtures" / "pygoat_views"
    code = (
        "from ravel.ingest.loader import discover\n"
        "from ravel.graph.parse import parse_file\n"
        f"(sf,) = [s for s in discover({str(views)!r}) if s.rel_path == 'views.py']\n"
        "print(len(parse_file(sf)))\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr[-500:]
    assert int(proc.stdout.strip()) > 50  # PyGoat's lab views
