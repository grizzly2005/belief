"""Small path/URL matchers for scope policies."""

from __future__ import annotations

import os
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
    """Match only the configured path or a child path.

    Relative entries are resolved from the current workspace.  The former
    suffix-based matching accepted unrelated sibling paths ending with the
    same directory name, which is unsafe for scope enforcement.
    """
    pattern_path = _resolved_path(pattern)
    target_path = _resolved_path(target)
    try:
        target_path.relative_to(pattern_path)
        return True
    except ValueError:
        return False


def _resolved_path(value: str) -> Path:
    return Path(os.path.normcase(str(Path(value).resolve(strict=False))))


__all__ = ["is_url", "match_scope_pattern"]
