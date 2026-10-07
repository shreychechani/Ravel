"""Tests for context-hash verdict caching."""

from pathlib import Path

from ravel.triage.cache import TriageCache


def test_triage_cache_set_get_and_persistence(tmp_path: Path) -> None:
    cache_file = tmp_path / "cache.json"
    cache = TriageCache(cache_file)

    key = TriageCache.compute_key("ctxhash123", "template-1", "mock-model")
    assert cache.get(key) is None

    cache.set(
        key=key,
        verdict="false_positive",
        confidence=0.88,
        reasoning="Validated as pre-sanitized.",
        template_id="template-1",
        model_name="mock-model",
    )
    cache.save()

    assert cache_file.is_file()

    # Reopen in new cache instance
    new_cache = TriageCache(cache_file)
    hit = new_cache.get(key)
    assert hit is not None
    assert hit.verdict == "false_positive"
    assert hit.confidence == 0.88
    assert hit.reasoning == "Validated as pre-sanitized."
    assert hit.model == "mock-model"
