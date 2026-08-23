"""Canonical JSON, digest, URL, and timestamp helpers for intelligence inputs."""

from __future__ import annotations

import hashlib
from datetime import date, datetime, time, timezone
from typing import Any
from urllib.parse import urlsplit

from belief.json_contracts import StrictJSONError, strict_json_dumps

from .errors import QueryNormalizationError


def canonical_json(value: Any) -> str:
    """Return deterministic UTF-8 JSON without permissive numeric values."""

    try:
        return strict_json_dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
    except (StrictJSONError, TypeError, ValueError) as exc:
        raise QueryNormalizationError(f"value is not canonical JSON: {exc}") from exc


def canonical_json_sha256(value: Any) -> str:
    """Hash a JSON value after semantic key-order normalization."""

    return sha256_bytes(canonical_json(value).encode("utf-8"))


def sha256_bytes(value: bytes | bytearray) -> str:
    """Hash exact bytes, preserving byte-level response provenance."""

    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("sha256_bytes expects bytes")
    return hashlib.sha256(bytes(value)).hexdigest()


def normalize_retrieval_timestamp(value: str | datetime) -> str:
    """Require a timezone-aware retrieval time and render it in canonical UTC."""

    parsed = _parse_datetime(value, allow_date_only=False)
    return _format_utc(parsed)


def parse_source_timestamp(value: str) -> datetime:
    """Parse provider timestamps used only for explicit freshness metadata."""

    return _parse_datetime(value, allow_date_only=True)


def require_https_url(value: str, *, field: str = "source_url") -> str:
    """Validate a credential-free absolute HTTPS provider URL."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty HTTPS URL")
    normalized = value.strip()
    parts = urlsplit(normalized)
    if parts.scheme.lower() != "https" or not parts.hostname:
        raise ValueError(f"{field} must be an absolute HTTPS URL")
    if parts.username is not None or parts.password is not None:
        raise ValueError(f"{field} must not contain credentials")
    if parts.fragment:
        raise ValueError(f"{field} must not contain a fragment")
    return normalized


def _parse_datetime(value: str | datetime, *, allow_date_only: bool) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if allow_date_only:
            for separator in ("-", "."):
                try:
                    parsed_date = date.fromisoformat(text.replace(separator, "-"))
                except ValueError:
                    continue
                if len(text) == 10:
                    parsed = datetime.combine(parsed_date, time.min, tzinfo=timezone.utc)
                    break
            else:
                parsed = _parse_iso_datetime(text)
        else:
            parsed = _parse_iso_datetime(text)
    else:
        raise ValueError("timestamp must be a non-empty string or datetime")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _parse_iso_datetime(value: str) -> datetime:
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc


def _format_utc(value: datetime) -> str:
    utc = value.astimezone(timezone.utc)
    rendered = utc.isoformat(timespec="microseconds" if utc.microsecond else "seconds")
    return rendered.replace("+00:00", "Z")


__all__ = [
    "canonical_json",
    "canonical_json_sha256",
    "normalize_retrieval_timestamp",
    "parse_source_timestamp",
    "require_https_url",
    "sha256_bytes",
]
