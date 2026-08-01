"""Strict, bounded JSON contracts for first-party BELIEF inputs.

Python's ``json`` module accepts NaN/Infinity by default and silently keeps the
last value for duplicate object keys.  Both behaviours are dangerous at trust
boundaries because the parsed object is not the document a reviewer may think
was signed, hashed, or validated.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any, Iterable

DEFAULT_JSON_MAX_BYTES = 64 * 1024 * 1024


class StrictJSONError(ValueError):
    """Raised when a JSON input violates BELIEF's interchange contract."""


def _reject_constant(token: str) -> None:
    raise StrictJSONError(f"non-finite JSON number is forbidden: {token}")


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def strict_json_loads(text: str | bytes | bytearray) -> Any:
    """Decode one JSON document, rejecting duplicates and non-finite numbers."""

    if isinstance(text, (bytes, bytearray)):
        try:
            decoded = bytes(text).decode("utf-8-sig", errors="strict")
        except UnicodeDecodeError as exc:
            raise StrictJSONError(f"JSON input is not strict UTF-8: {exc}") from exc
    elif isinstance(text, str):
        decoded = text.lstrip("\ufeff")
    else:
        raise TypeError("strict_json_loads expects str or bytes")

    try:
        return json.loads(
            decoded,
            parse_constant=_reject_constant,
            object_pairs_hook=_unique_object,
        )
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise StrictJSONError(f"invalid JSON document: {exc}") from exc


def load_json_file(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_JSON_MAX_BYTES,
) -> Any:
    """Read and strictly decode a bounded UTF-8 JSON file."""

    source = Path(path)
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    try:
        size = source.stat().st_size
    except OSError as exc:
        raise StrictJSONError(f"cannot stat JSON input {source}: {exc}") from exc
    if size > max_bytes:
        raise StrictJSONError(
            f"JSON input exceeds {max_bytes} byte limit: {source} ({size} bytes)"
        )
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise StrictJSONError(f"cannot read JSON input {source}: {exc}") from exc
    if len(raw) > max_bytes:
        raise StrictJSONError(
            f"JSON input exceeds {max_bytes} byte limit after read: {source}"
        )
    return strict_json_loads(raw)


def read_bounded_utf8(
    path: str | Path,
    *,
    max_bytes: int = DEFAULT_JSON_MAX_BYTES,
) -> str:
    """Read a bounded text interchange file using strict UTF-8."""

    source = Path(path)
    if max_bytes <= 0:
        raise ValueError("max_bytes must be positive")
    try:
        size = source.stat().st_size
        if size > max_bytes:
            raise StrictJSONError(
                f"input exceeds {max_bytes} byte limit: {source} ({size} bytes)"
            )
        raw = source.read_bytes()
    except StrictJSONError:
        raise
    except OSError as exc:
        raise StrictJSONError(f"cannot read input {source}: {exc}") from exc
    if len(raw) > max_bytes:
        raise StrictJSONError(
            f"input exceeds {max_bytes} byte limit after read: {source}"
        )
    try:
        return raw.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as exc:
        raise StrictJSONError(f"input is not strict UTF-8: {exc}") from exc


def require_finite_float(value: object, *, field: str) -> float:
    """Coerce a numeric field while rejecting NaN and infinities."""

    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise StrictJSONError(f"{field} must be numeric") from exc
    if not math.isfinite(parsed):
        raise StrictJSONError(f"{field} must be finite")
    return parsed


def assert_finite_json(value: Any, *, path: str = "$") -> None:
    """Recursively reject non-finite floats before serialization or hashing."""

    if isinstance(value, float):
        if not math.isfinite(value):
            raise StrictJSONError(f"{path} contains a non-finite number")
        return
    if value is None or isinstance(value, (str, int, bool)):
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise StrictJSONError(f"{path} contains a non-string object key")
            assert_finite_json(child, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            assert_finite_json(child, path=f"{path}[{index}]")
        return
    raise StrictJSONError(
        f"{path} contains unsupported JSON value type {type(value).__name__}"
    )


def strict_json_dumps(value: Any, **kwargs: Any) -> str:
    """Serialize only finite, structurally valid JSON values."""

    assert_finite_json(value)
    kwargs["allow_nan"] = False
    return json.dumps(value, **kwargs)


def strict_json_clone(value: Any) -> Any:
    """Return a detached JSON value without permissive coercions."""

    return strict_json_loads(
        strict_json_dumps(value, sort_keys=True, separators=(",", ":"))
    )


__all__ = [
    "DEFAULT_JSON_MAX_BYTES",
    "StrictJSONError",
    "assert_finite_json",
    "load_json_file",
    "read_bounded_utf8",
    "require_finite_float",
    "strict_json_clone",
    "strict_json_dumps",
    "strict_json_loads",
]
