"""Application-only state and decisions for registered fixtures.

No oracle, expected verdict, or ground-truth label is imported here.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PUBLIC_MARKER = "BELIEF_WEB_PUBLIC"
SENTINEL_MARKER = "BELIEF_WEB_OUTSIDE_SENTINEL"


@dataclass(frozen=True)
class PathFixtureLayout:
    root: Path
    allowed: Path
    outside: Path
    public: Path
    sentinel: Path
    symlink: Path
    symlink_supported: bool


def prepare_path_layout(
    root: Path,
    *,
    include_symlink: bool,
) -> PathFixtureLayout:
    root.mkdir(parents=True, exist_ok=False)
    allowed = root / "allowed"
    outside = root / "outside"
    nested = allowed / "nested"
    allowed.mkdir()
    outside.mkdir()
    nested.mkdir()
    public = allowed / "public.txt"
    sentinel = outside / "sentinel.txt"
    public.write_text(PUBLIC_MARKER, encoding="utf-8")
    sentinel.write_text(SENTINEL_MARKER, encoding="utf-8")
    link = allowed / "linked-sentinel.txt"
    symlink_supported = False
    if include_symlink:
        try:
            link.symlink_to(sentinel)
        except (NotImplementedError, OSError):
            pass
        else:
            symlink_supported = True
    return PathFixtureLayout(
        root=root.resolve(),
        allowed=allowed.resolve(),
        outside=outside.resolve(),
        public=public.resolve(),
        sentinel=sentinel.resolve(),
        symlink=link,
        symlink_supported=symlink_supported,
    )


def path_policy_alpha(
    layout: PathFixtureLayout,
    value: str,
) -> tuple[int, dict[str, Any]]:
    candidate = (layout.allowed / value).resolve()
    if not candidate.is_relative_to(layout.root):
        return 403, {
            "decision": "fixture_boundary_blocked",
            "marker": "none",
            "resolved_path": "outside_fixture_root",
        }
    return _read_path_candidate(candidate, _logical_path(candidate, layout))


def path_policy_beta(
    layout: PathFixtureLayout,
    value: str,
) -> tuple[int, dict[str, Any]]:
    candidate = (layout.allowed / value).resolve()
    if not candidate.is_relative_to(layout.root):
        return 403, {
            "decision": "fixture_boundary_blocked",
            "marker": "none",
            "resolved_path": "outside_fixture_root",
        }
    logical = _logical_path(candidate, layout)
    if not candidate.is_relative_to(layout.allowed):
        return 403, {
            "decision": "authorization_blocked",
            "marker": "none",
            "resolved_path": logical,
        }
    return _read_path_candidate(candidate, logical)


def path_state(layout: PathFixtureLayout) -> dict[str, Any]:
    return {
        "public_marker": layout.public.read_text(encoding="utf-8"),
        "sentinel_marker": layout.sentinel.read_text(encoding="utf-8"),
        "symlink_supported": layout.symlink_supported,
    }


def initial_resources() -> dict[str, dict[str, str]]:
    return {
        "resource_a": {
            "owner_id": "user_a",
            "tenant_id": "tenant_a",
            "value": "resource_a_initial",
        },
        "resource_b": {
            "owner_id": "user_b",
            "tenant_id": "tenant_a",
            "value": "resource_b_initial",
        },
        "resource_c": {
            "owner_id": "user_a",
            "tenant_id": "tenant_b",
            "value": "resource_c_initial",
        },
    }


def resource_state(
    resources: dict[str, dict[str, str]],
) -> dict[str, dict[str, str]]:
    return copy.deepcopy(resources)


def resource_policy_alpha(
    resources: dict[str, dict[str, str]],
    *,
    method: str,
    resource_id: str,
    user_id: str,
    tenant_id: str,
    value: str,
) -> tuple[int, dict[str, Any]]:
    del tenant_id
    if not user_id:
        return 401, {
            "allowed": False,
            "resource_exposed": False,
            "detail": "unauthenticated",
        }
    resource = resources.get(resource_id)
    if resource is None:
        return 404, {
            "allowed": False,
            "resource_exposed": False,
            "detail": "not_found",
        }
    return _apply_resource_operation(resource, method=method, value=value)


def resource_policy_beta(
    resources: dict[str, dict[str, str]],
    *,
    method: str,
    resource_id: str,
    user_id: str,
    tenant_id: str,
    value: str,
) -> tuple[int, dict[str, Any]]:
    if not user_id:
        return 401, {
            "allowed": False,
            "resource_exposed": False,
            "detail": "unauthenticated",
        }
    resource = resources.get(resource_id)
    if resource is None:
        return 404, {
            "allowed": False,
            "resource_exposed": False,
            "detail": "not_found",
        }
    if (
        resource["owner_id"] != user_id
        or resource["tenant_id"] != tenant_id
    ):
        return 403, {
            "allowed": False,
            "resource_exposed": False,
            "detail": "authorization_denied",
        }
    return _apply_resource_operation(resource, method=method, value=value)


def _read_path_candidate(
    candidate: Path,
    logical: str,
) -> tuple[int, dict[str, Any]]:
    try:
        content = candidate.read_text(encoding="utf-8")
    except (FileNotFoundError, IsADirectoryError):
        return 404, {
            "decision": "not_found",
            "marker": "none",
            "resolved_path": logical,
        }
    marker = (
        "public"
        if content == PUBLIC_MARKER
        else "sentinel"
        if content == SENTINEL_MARKER
        else "other"
    )
    return 200, {
        "decision": "read",
        "marker": marker,
        "resolved_path": logical,
    }


def _apply_resource_operation(
    resource: dict[str, str],
    *,
    method: str,
    value: str,
) -> tuple[int, dict[str, Any]]:
    if method == "GET":
        return 200, {
            "allowed": True,
            "resource_exposed": True,
            "owner_id": resource["owner_id"],
            "tenant_id": resource["tenant_id"],
            "value": resource["value"],
        }
    if method == "PATCH":
        resource["value"] = value
        return 200, {
            "allowed": True,
            "resource_exposed": False,
            "owner_id": resource["owner_id"],
            "tenant_id": resource["tenant_id"],
            "value": resource["value"],
        }
    return 405, {
        "allowed": False,
        "resource_exposed": False,
        "detail": "method_not_allowed",
    }


def _logical_path(
    candidate: Path,
    layout: PathFixtureLayout,
) -> str:
    if candidate.is_relative_to(layout.allowed):
        return "allowed/" + candidate.relative_to(layout.allowed).as_posix()
    if candidate.is_relative_to(layout.root):
        return candidate.relative_to(layout.root).as_posix()
    return "outside_fixture_root"


__all__ = [
    "PUBLIC_MARKER",
    "SENTINEL_MARKER",
    "PathFixtureLayout",
    "initial_resources",
    "path_policy_alpha",
    "path_policy_beta",
    "path_state",
    "prepare_path_layout",
    "resource_policy_alpha",
    "resource_policy_beta",
    "resource_state",
]
