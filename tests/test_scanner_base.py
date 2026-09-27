"""Scanner contract helpers (Phase 2)."""

from __future__ import annotations

import pytest
from ravel.scanners.base import normalize_cwe


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (78, "CWE-78"),
        ("78", "CWE-78"),
        ("CWE-89", "CWE-89"),
        ("CWE-79: Improper Neutralization of Input", "CWE-79"),
        (None, None),
        ("", None),
        ("CWE-0", None),
    ],
)
def test_normalize_cwe(value: object, expected: str | None) -> None:
    assert normalize_cwe(value) == expected
