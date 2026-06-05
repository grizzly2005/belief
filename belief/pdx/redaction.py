"""Redaction helpers for BELIEF's JSON-only PDX adapter."""

from __future__ import annotations

import re
from typing import Any

from belief.tool_results.io import sanitize_for_json


_PROMPT_INJECTION_RE = re.compile(
    r"(?i)\b(ignore previous|system:|assistant:|new instructions|forget everything|override)\b"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_LONG_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def redact_pdx_value(value: Any) -> Any:
    """Return a JSON-safe, deterministic, redacted copy of PDX-derived data."""
    sanitized = sanitize_for_json(value)
    return _redact_extra(sanitized)


def _redact_extra(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _redact_extra(raw) for key, raw in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, list):
        return [_redact_extra(item) for item in value]
    if isinstance(value, str):
        redacted = _JWT_RE.sub("[REDACTED_JWT]", value)
        redacted = _LONG_HEX_RE.sub("[REDACTED_HEX]", redacted)
        redacted = _EMAIL_RE.sub("[REDACTED_EMAIL]", redacted)
        redacted = _PROMPT_INJECTION_RE.sub("[REDACTED_PROMPT_TEXT]", redacted)
        return redacted
    return value


__all__ = ["redact_pdx_value"]
