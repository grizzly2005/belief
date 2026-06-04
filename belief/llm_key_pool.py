"""
Groq API key rotation pool with per-key cooldown on 429 / quota errors.

Usage (minimal integration in belief/llm_client.py):

    from belief.llm_key_pool import GroqKeyPool

    _pool = GroqKeyPool()

    def call_groq(prompt, ...):
        last_err = None
        for _ in range(_pool.size() + 1):
            key = _pool.get()
            if key is None:
                break
            try:
                # replace with your actual Groq call
                return _do_groq_call(key, prompt, ...)
            except Exception as e:
                status = _classify(e)
                if status == "rate_limit":
                    _pool.penalize(key, seconds=60)
                elif status == "auth":
                    _pool.penalize(key, seconds=3600)
                elif status == "server":
                    pass  # don't penalize, just retry next key
                else:
                    raise
                last_err = e
        raise RuntimeError(
            f"All {_pool.size()} Groq keys exhausted. Last error: {last_err}"
        )

Environment variables (put them in a .env file or export them):

    GROQ_API_KEY=gsk_xxx...          # primary
    GROQ_API_KEY_2=gsk_yyy...        # optional
    GROQ_API_KEY_3=gsk_zzz...        # optional
    GROQ_API_KEY_4=gsk_www...        # optional

The pool auto-detects up to 10 slots (GROQ_API_KEY, GROQ_API_KEY_2..10).
Keys in cooldown are skipped until their cooldown expires. If all keys are
in cooldown, get() returns the key whose cooldown expires soonest so the
caller can decide to wait or fail.

NOTE: This module is intended for development and benchmarking only.
Multi-account usage may violate the provider's Terms of Service.
Remove this module before publishing or sharing the project publicly.
"""

from __future__ import annotations

import logging
import os
import time
from itertools import cycle
from threading import Lock
from typing import Optional

logger = logging.getLogger(__name__)

MAX_KEY_SLOTS = 10


def _mask(key: str) -> str:
    """Return a log-safe representation of a key (first 6 + last 4 chars)."""
    if not key or len(key) < 12:
        return "***"
    return f"{key[:6]}...{key[-4:]}"


class GroqKeyPool:
    """Thread-safe round-robin key pool with per-key cooldown."""

    def __init__(self, keys: Optional[list[str]] = None):
        if keys is None:
            keys = self._discover_keys_from_env()
        # Deduplicate while preserving order
        seen = set()
        self.keys = []
        for k in keys:
            if k and k not in seen:
                self.keys.append(k)
                seen.add(k)
        if not self.keys:
            raise RuntimeError(
                "GroqKeyPool: no API keys found. Set GROQ_API_KEY "
                "(and optionally GROQ_API_KEY_2, GROQ_API_KEY_3, ...) "
                "in your environment or .env file."
            )
        self._cycle = cycle(self.keys)
        self._cooldown: dict[str, float] = {}
        self._lock = Lock()
        logger.info(
            "GroqKeyPool initialized with %d key(s): %s",
            len(self.keys),
            ", ".join(_mask(k) for k in self.keys),
        )

    @staticmethod
    def _discover_keys_from_env() -> list[str]:
        """Look for GROQ_API_KEY, GROQ_API_KEY_2, ..., GROQ_API_KEY_N."""
        keys = []
        primary = os.getenv("GROQ_API_KEY")
        if primary:
            keys.append(primary.strip())
        for i in range(2, MAX_KEY_SLOTS + 1):
            k = os.getenv(f"GROQ_API_KEY_{i}")
            if k:
                keys.append(k.strip())
        return keys

    def size(self) -> int:
        return len(self.keys)

    def get(self) -> Optional[str]:
        """Return the next available key. If all in cooldown, return the one
        closest to expiry (caller may still try it or wait)."""
        now = time.time()
        with self._lock:
            # Try up to 2*N times to find an available key
            for _ in range(len(self.keys) * 2):
                k = next(self._cycle)
                if self._cooldown.get(k, 0) <= now:
                    return k
            # All keys cooling down — return the soonest-available one
            if not self.keys:
                return None
            k = min(self.keys, key=lambda x: self._cooldown.get(x, 0))
            wait = max(0, self._cooldown.get(k, 0) - now)
            logger.warning(
                "GroqKeyPool: all keys in cooldown. Returning %s "
                "(available in ~%ds).",
                _mask(k),
                int(wait),
            )
            return k

    def penalize(self, key: str, seconds: float = 60.0) -> None:
        """Mark `key` as unavailable for `seconds` seconds."""
        with self._lock:
            self._cooldown[key] = time.time() + max(1.0, seconds)
        logger.info(
            "GroqKeyPool: penalizing %s for %ds", _mask(key), int(seconds)
        )

    def status(self) -> list[dict]:
        """Return pool state for debugging."""
        now = time.time()
        with self._lock:
            return [
                {
                    "key": _mask(k),
                    "available": self._cooldown.get(k, 0) <= now,
                    "cooldown_remaining_s": max(
                        0, int(self._cooldown.get(k, 0) - now)
                    ),
                }
                for k in self.keys
            ]


def classify_error(err: Exception) -> str:
    """Classify an API error so the caller knows how to react.

    Returns one of: "rate_limit", "auth", "server", "other".
    Works without importing any specific SDK — uses string matching on
    the exception / message / status code, which is robust across
    httpx, requests, the groq SDK, and openai-compatible clients.
    """
    status = getattr(err, "status_code", None)
    if status is None:
        resp = getattr(err, "response", None)
        if resp is not None:
            status = getattr(resp, "status_code", None)

    msg = (str(err) or "").lower()

    if status == 429 or "rate limit" in msg or "too many requests" in msg \
            or "quota" in msg:
        return "rate_limit"
    if status in (401, 403) or "invalid api key" in msg \
            or "unauthorized" in msg or "forbidden" in msg:
        return "auth"
    if status is not None and 500 <= status < 600:
        return "server"
    if "timeout" in msg or "connection" in msg:
        return "server"
    return "other"


def retry_after_from_error(err: Exception, default: float = 60.0) -> float:
    """Extract Retry-After header value in seconds if present."""
    resp = getattr(err, "response", None)
    if resp is None:
        return default
    headers = getattr(resp, "headers", None) or {}
    ra = headers.get("Retry-After") or headers.get("retry-after")
    if ra:
        try:
            return float(ra)
        except (TypeError, ValueError):
            pass
    return default
