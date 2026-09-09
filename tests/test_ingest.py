"""Ingest tests — run against the real sample fixture, not synthetic strings."""

from __future__ import annotations

from ravel.ingest.loader import SourceFile


def test_discover_finds_python_files(sample_files: dict[str, SourceFile]) -> None:
    assert "app.py" in sample_files
    assert "services.py" in sample_files
    assert "utils.py" in sample_files


def test_every_file_is_hashed(sample_files: dict[str, SourceFile]) -> None:
    for f in sample_files.values():
        assert len(f.content_hash) == 64  # sha-256 hex
        if f.content:  # empty files (e.g. __init__.py) legitimately have 0 lines
            assert f.lines > 0
