"""Shared test fixtures."""

from __future__ import annotations

import tempfile
from pathlib import Path

import jedi
import pytest
from ravel.ingest.loader import SourceFile, discover


def pytest_configure(config: pytest.Config) -> None:
    jedi.settings.cache_directory = tempfile.mkdtemp(prefix="ravel_jedi_test_cache_")


FIXTURE_ROOT = Path(__file__).parent.parent / "eval" / "fixtures" / "sample_app"


@pytest.fixture
def sample_files() -> dict[str, SourceFile]:
    """The sample app's files keyed by relative path."""
    return {f.rel_path: f for f in discover(FIXTURE_ROOT)}
