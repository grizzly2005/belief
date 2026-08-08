"""Observation-only interfaces exposed by fixture applications to evaluators."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ClientResponse:
    status_code: int
    body: dict[str, Any]


@dataclass(frozen=True)
class PathApplication:
    request: Callable[[str], ClientResponse]
    state: Callable[[], dict[str, Any]]
    absolute_outside_stimulus: str
    symlink_supported: bool


@dataclass(frozen=True)
class ResourceApplication:
    request: Callable[[str, str, str, str, str], ClientResponse]
    state: Callable[[], dict[str, dict[str, str]]]


__all__ = [
    "ClientResponse",
    "PathApplication",
    "ResourceApplication",
]
