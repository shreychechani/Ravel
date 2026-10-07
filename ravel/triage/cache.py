"""Content-hash based verdict caching (PRODUCT.md §6, §8).

Per PRODUCT.md §8:
"Known trap — verdict cache keys: triage verdicts depend on the flagged code
plus its callers plus the module summary. Key the verdict cache on a hash of
the assembled context, not just the node."
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

from ravel.core.hashing import content_hash
from ravel.core.logging import get_logger

log = get_logger("ravel.triage.cache")


@dataclass(frozen=True)
class CachedVerdict:
    verdict: str
    confidence: float
    reasoning: str
    template_id: str
    model: str
    timestamp: str


def default_cache_path() -> Path:
    override = os.environ.get("RAVEL_TRIAGE_CACHE")
    if override:
        return Path(override).expanduser()
    return Path("~/.cache/ravel/triage_cache.json").expanduser()


class TriageCache:
    """Persistent on-disk cache for LLM triage verdicts."""

    def __init__(self, cache_file: Path | None = None) -> None:
        self.cache_file = cache_file or default_cache_path()
        self._entries: dict[str, CachedVerdict] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self.cache_file.is_file():
            return
        try:
            data = json.loads(self.cache_file.read_text(encoding="utf-8"))
            for key, val in data.items():
                self._entries[key] = CachedVerdict(
                    verdict=str(val.get("verdict", "needs_review")),
                    confidence=float(val.get("confidence", 0.0)),
                    reasoning=str(val.get("reasoning", "")),
                    template_id=str(val.get("template_id", "")),
                    model=str(val.get("model", "")),
                    timestamp=str(val.get("timestamp", "")),
                )
            log.debug(
                "Loaded %d cached triage verdicts from %s", len(self._entries), self.cache_file
            )
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            log.warning("Could not read triage cache from %s: %s", self.cache_file, exc)

    def save(self) -> None:
        if not self._dirty:
            return
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)
            payload = {k: asdict(v) for k, v in self._entries.items()}
            self.cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self._dirty = False
            log.debug("Saved %d triage verdicts to %s", len(self._entries), self.cache_file)
        except OSError as exc:
            log.warning("Failed to persist triage cache to %s: %s", self.cache_file, exc)

    @staticmethod
    def compute_key(context_hash: str, template_id: str, model_name: str) -> str:
        basis = f"{context_hash}\x1f{template_id}\x1f{model_name}"
        return content_hash(basis)

    def get(self, key: str) -> CachedVerdict | None:
        return self._entries.get(key)

    def set(
        self,
        key: str,
        verdict: str,
        confidence: float,
        reasoning: str,
        template_id: str,
        model_name: str,
    ) -> None:
        self._entries[key] = CachedVerdict(
            verdict=verdict,
            confidence=confidence,
            reasoning=reasoning,
            template_id=template_id,
            model=model_name,
            timestamp=datetime.now(UTC).isoformat(),
        )
        self._dirty = True
