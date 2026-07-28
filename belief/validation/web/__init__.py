"""Miniature Flask and FastAPI fixtures for isolated local validation."""

from __future__ import annotations

import re
from importlib.metadata import PackageNotFoundError, version


_SUPPORTED_FRAMEWORK_VERSIONS = {
    "flask": ((3, 0), (4, 0)),
    "fastapi": ((0, 115), (1, 0)),
}


def optional_framework_available(framework: str) -> bool:
    """Return whether a fixed optional framework meets BELIEF's range."""

    bounds = _SUPPORTED_FRAMEWORK_VERSIONS.get(framework)
    if bounds is None:
        return False
    try:
        installed = version(framework)
    except PackageNotFoundError:
        return False
    match = re.match(r"^(\d+)\.(\d+)", installed)
    if match is None:
        return False
    parsed = (int(match.group(1)), int(match.group(2)))
    minimum, maximum = bounds
    return minimum <= parsed < maximum


__all__ = ["optional_framework_available"]
