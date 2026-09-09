"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest
from ravel.ingest.loader import SourceFile, discover

FIXTURE_ROOT = Path(__file__).parent.parent / "eval" / "fixtures" / "sample_app"


@pytest.fixture
def sample_files() -> dict[str, SourceFile]:
    """The sample app's files keyed by relative path."""
    return {f.rel_path: f for f in discover(FIXTURE_ROOT)}
