"""Small path/URL matchers for scope policies."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def is_url(value: str) -> bool:
    return value.lower().startswith(("http://", "https://"))


def match_scope_pattern(pattern: str, target: str) -> bool:
    pattern = str(pattern).strip()
    target = str(target).strip()
    if not pattern:
        return False
    if is_url(pattern) or is_url(target):
        return _match_url(pattern, target)
    return _match_path(pattern, target)


def _match_url(pattern: str, target: str) -> bool:
    pattern_url = urlparse(pattern)
    target_url = urlparse(target)
    if not pattern_url.scheme or not target_url.scheme:
        return False
    if pattern_url.scheme != target_url.scheme:
        return False
    if pattern_url.netloc.lower() != target_url.netloc.lower():
        return False
    pattern_path = pattern_url.path.rstrip("/")
    target_path = target_url.path.rstrip("/")
    return target_path == pattern_path or target_path.startswith(pattern_path + "/")


def _match_path(pattern: str, target: str) -> bool:
    pattern_path = _norm_path(pattern)
    target_path = _norm_path(target)
    return (
        target_path == pattern_path
        or target_path.startswith(pattern_path + "/")
        or target_path.endswith("/" + pattern_path)
        or pattern_path.endswith("/" + target_path)
    )


def _norm_path(value: str) -> str:
    return Path(value).as_posix().rstrip("/") or "."


__all__ = ["is_url", "match_scope_pattern"]
