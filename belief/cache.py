"""
BELIEF — Belief Cache.

Inspired by Claude Code's history.ts: pending buffer + hash-based dedup.
Caches extracted beliefs per function content hash so unchanged functions
skip LLM extraction entirely on re-analysis.

Key patterns from Claude Code adapted here:
- Content hashing for deduplication (like pasteStore)
- Pending buffer with flush (like pendingEntries)
- Skip-set for invalidated entries (like skippedTimestamps)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .models import Belief

logger = logging.getLogger("belief.cache")

# Maximum beliefs stored per cache entry
MAX_CACHED_BELIEFS_PER_FUNCTION = 50

# Maximum total cached functions before LRU eviction
MAX_CACHE_ENTRIES = 5000


def _content_hash(content: str) -> str:
    """Compute a stable hash for function source code."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]


@dataclass
class CacheEntry:
    """A cached set of beliefs for a specific function."""

    content_hash: str           # hash of function source code
    function_name: str
    file_path: str
    beliefs: list[dict]         # serialized beliefs (to_dict format)
    timestamp: float = 0.0      # when this entry was created
    hit_count: int = 0          # how many times this cache entry was used

    def to_dict(self) -> dict:
        return {
            "content_hash": self.content_hash,
            "function_name": self.function_name,
            "file_path": self.file_path,
            "beliefs": self.beliefs,
            "timestamp": self.timestamp,
            "hit_count": self.hit_count,
        }

    @classmethod
    def from_dict(cls, data: dict) -> CacheEntry:
        return cls(
            content_hash=data["content_hash"],
            function_name=data.get("function_name", ""),
            file_path=data.get("file_path", ""),
            beliefs=data.get("beliefs", []),
            timestamp=data.get("timestamp", 0.0),
            hit_count=data.get("hit_count", 0),
        )


class BeliefCache:
    """
    Hash-based belief cache for avoiding redundant LLM extraction.

    When a function's source code hasn't changed (same hash), the cache
    returns previously extracted beliefs instead of calling the LLM again.
    This makes re-analysis of unchanged codebases near-instant.

    Inspired by Claude Code's history.ts patterns:
    - pendingEntries buffer → _pending dict
    - skippedTimestamps → _invalidated set
    - hashPastedText/storePastedText → content_hash dedup
    """

    def __init__(self, cache_dir: str | None = None):
        self._entries: dict[str, CacheEntry] = {}  # content_hash → entry
        self._pending: dict[str, CacheEntry] = {}  # not yet flushed to disk
        self._invalidated: set[str] = set()         # hashes to skip
        self._cache_dir = cache_dir
        self._dirty = False

        if cache_dir:
            self._load_from_disk()

    def get(self, source_code: str, function_name: str = "") -> list[Belief] | None:
        """
        Look up cached beliefs for a function's source code.
        Returns None if not cached (cache miss).
        """
        h = _content_hash(source_code)

        if h in self._invalidated:
            return None

        entry = self._entries.get(h) or self._pending.get(h)
        if entry is None:
            return None

        # Cache hit
        entry.hit_count += 1
        try:
            beliefs = [Belief.from_dict(b) for b in entry.beliefs]
            logger.debug(f"Cache HIT for {function_name or h} ({len(beliefs)} beliefs)")
            return beliefs
        except Exception:
            # Corrupt cache entry — invalidate and return miss
            self.invalidate(source_code)
            return None

    def put(
        self,
        source_code: str,
        beliefs: list[Belief],
        function_name: str = "",
        file_path: str = "",
    ):
        """Store extracted beliefs in the cache."""
        import time

        h = _content_hash(source_code)

        # Remove from invalidated if re-cached
        self._invalidated.discard(h)

        entry = CacheEntry(
            content_hash=h,
            function_name=function_name,
            file_path=file_path,
            beliefs=[b.to_dict() for b in beliefs[:MAX_CACHED_BELIEFS_PER_FUNCTION]],
            timestamp=time.time(),
            hit_count=0,
        )

        self._pending[h] = entry
        self._entries[h] = entry
        self._dirty = True

        # LRU eviction if too many entries
        if len(self._entries) > MAX_CACHE_ENTRIES:
            self._evict_lru()

        logger.debug(f"Cache PUT for {function_name or h} ({len(beliefs)} beliefs)")

    def invalidate(self, source_code: str):
        """Invalidate a cache entry (e.g., when source code changes)."""
        h = _content_hash(source_code)
        self._invalidated.add(h)
        self._entries.pop(h, None)
        self._pending.pop(h, None)
        self._dirty = True

    def invalidate_file(self, file_path: str):
        """Invalidate all cache entries for a given file."""
        to_remove = [
            h for h, e in self._entries.items()
            if e.file_path == file_path
        ]
        for h in to_remove:
            self._invalidated.add(h)
            self._entries.pop(h, None)
            self._pending.pop(h, None)
        self._dirty = True

    def flush(self):
        """Flush pending entries to disk."""
        if not self._cache_dir or not self._dirty:
            return

        cache_path = Path(self._cache_dir) / "belief_cache.json"
        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                "version": 1,
                "entries": {h: e.to_dict() for h, e in self._entries.items()},
                "invalidated": list(self._invalidated),
            }
            cache_path.write_text(json.dumps(data), encoding="utf-8")
            self._pending.clear()
            self._dirty = False
            logger.debug(f"Cache flushed: {len(self._entries)} entries")
        except Exception as e:
            logger.warning(f"Failed to flush belief cache: {e}")

    def clear(self):
        """Clear all cached beliefs."""
        self._entries.clear()
        self._pending.clear()
        self._invalidated.clear()
        self._dirty = True

    @property
    def stats(self) -> dict:
        """Cache statistics."""
        total_hits = sum(e.hit_count for e in self._entries.values())
        return {
            "total_entries": len(self._entries),
            "pending_entries": len(self._pending),
            "invalidated_entries": len(self._invalidated),
            "total_hits": total_hits,
            "total_beliefs_cached": sum(
                len(e.beliefs) for e in self._entries.values()
            ),
        }

    # ── Internal ──

    def _load_from_disk(self):
        """Load cache from disk."""
        if not self._cache_dir:
            return

        cache_path = Path(self._cache_dir) / "belief_cache.json"
        if not cache_path.exists():
            return

        try:
            data = json.loads(cache_path.read_text(encoding="utf-8"))
            if data.get("version") != 1:
                logger.warning("Cache version mismatch, ignoring")
                return

            for h, entry_data in data.get("entries", {}).items():
                try:
                    self._entries[h] = CacheEntry.from_dict(entry_data)
                except Exception:
                    continue

            self._invalidated = set(data.get("invalidated", []))
            logger.info(f"Loaded {len(self._entries)} cached belief entries")
        except Exception as e:
            logger.warning(f"Failed to load belief cache: {e}")

    def _evict_lru(self):
        """Evict least-recently-used entries until under the limit."""
        if len(self._entries) <= MAX_CACHE_ENTRIES:
            return

        # Sort by hit_count (ascending) then timestamp (ascending)
        sorted_entries = sorted(
            self._entries.items(),
            key=lambda x: (x[1].hit_count, x[1].timestamp),
        )

        # Remove bottom 20%
        to_remove = len(self._entries) - int(MAX_CACHE_ENTRIES * 0.8)
        for i in range(min(to_remove, len(sorted_entries))):
            h = sorted_entries[i][0]
            self._entries.pop(h, None)
            self._pending.pop(h, None)
