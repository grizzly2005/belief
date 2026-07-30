"""Deterministic oracle harness shared by Flask and FastAPI fixtures."""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..evidence_policy import (
    FUNCTIONAL_BASELINE,
    OPTIONAL,
    PRIMARY_SECURITY,
    SECONDARY_SECURITY,
)
from ..worker.contracts import WorkerObservation


PUBLIC_MARKER = "BELIEF_WEB_PUBLIC"
SENTINEL_MARKER = "BELIEF_WEB_OUTSIDE_SENTINEL"


@dataclass(frozen=True)
class ClientResponse:
    status_code: int
    body: dict[str, Any]


@dataclass(frozen=True)
class PathFixtureLayout:
    root: Path
    allowed: Path
    outside: Path
    public: Path
    sentinel: Path
    symlink: Path
    symlink_supported: bool


PathRequester = Callable[[str], ClientResponse]
AuthorizationRequester = Callable[
    [str, str, str, str, str],
    ClientResponse,
]
ResourceSnapshot = Callable[[], dict[str, dict[str, str]]]


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


def serve_path(
    layout: PathFixtureLayout,
    value: str,
    *,
    protected: bool,
) -> tuple[int, dict[str, Any]]:
    candidate = (layout.allowed / value).resolve()
    if not candidate.is_relative_to(layout.root):
        return 403, {
            "decision": "fixture_boundary_blocked",
            "marker": "none",
            "resolved_path": "outside_fixture_root",
        }
    logical = logical_path(candidate, layout)
    if protected and not candidate.is_relative_to(layout.allowed):
        return 403, {
            "decision": "authorization_blocked",
            "marker": "none",
            "resolved_path": logical,
        }
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


def path_observations(
    requester: PathRequester,
    layout: PathFixtureLayout,
    *,
    include_symlink: bool,
) -> tuple[tuple[WorkerObservation, ...], tuple[str, ...]]:
    scenarios = (
        ("legitimate_path", "public.txt", "public.txt", True),
        (
            "parent_segment",
            "../outside/sentinel.txt",
            "../outside/sentinel.txt",
            False,
        ),
        (
            "absolute_path",
            str(layout.sentinel),
            "fixture/outside/sentinel.txt",
            False,
        ),
        (
            "normalized_equivalent",
            "nested/../../outside/sentinel.txt",
            "nested/../../outside/sentinel.txt",
            False,
        ),
    )
    observations: list[WorkerObservation] = []
    limitations: list[str] = []
    for scenario, raw_stimulus, label, baseline in scenarios:
        response = requester(raw_stimulus)
        observation, scenario_limitations = _path_observation(
            scenario=scenario,
            stimulus=label,
            response=response,
            baseline=baseline,
        )
        observations.append(observation)
        limitations.extend(scenario_limitations)

    if include_symlink and layout.symlink_supported:
        response = requester("linked-sentinel.txt")
        observation, scenario_limitations = _path_observation(
            scenario="symlink_boundary",
            stimulus="linked-sentinel.txt",
            response=response,
            baseline=False,
        )
        observations.append(observation)
        limitations.extend(scenario_limitations)
    else:
        limitation = (
            "symlink_disabled_by_test_parameters"
            if not include_symlink
            else "symlink_unavailable"
        )
        limitations.append(limitation)
        observations.append(WorkerObservation(
            scenario="symlink_boundary",
            stimulus="linked-sentinel.txt",
            oracle="path_boundary_invariant",
            expected="A symlink may not resolve outside the allowed root.",
            actual={
                "decision": "not_tested",
                "symlink_supported": layout.symlink_supported,
            },
            baseline=False,
            oracle_role=OPTIONAL,
            required_for_conclusion=False,
            oracle_evaluated=False,
            oracle_passed=None,
            limitations=(limitation,),
            cost_units=0,
        ))

    public_unchanged = (
        layout.public.read_text(encoding="utf-8") == PUBLIC_MARKER
    )
    sentinel_unchanged = (
        layout.sentinel.read_text(encoding="utf-8") == SENTINEL_MARKER
    )
    observations.append(WorkerObservation(
        scenario="filesystem_final_state",
        stimulus="fixture_state_after_path_requests",
        oracle="state_invariant",
        expected="The controlled fixture files remain unchanged.",
        actual={
            "public_unchanged": public_unchanged,
            "sentinel_unchanged": sentinel_unchanged,
        },
        baseline=False,
        oracle_role=SECONDARY_SECURITY,
        required_for_conclusion=True,
        oracle_evaluated=True,
        oracle_passed=public_unchanged and sentinel_unchanged,
        evidence=(
            f"public_unchanged:{str(public_unchanged).lower()}",
            f"sentinel_unchanged:{str(sentinel_unchanged).lower()}",
        ),
        cost_units=0,
    ))
    return tuple(observations), tuple(dict.fromkeys(limitations))


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


def serve_resource(
    resources: dict[str, dict[str, str]],
    *,
    method: str,
    resource_id: str,
    user_id: str,
    tenant_id: str,
    value: str,
    protected: bool,
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
    if protected and (
        resource["owner_id"] != user_id
        or resource["tenant_id"] != tenant_id
    ):
        return 403, {
            "allowed": False,
            "resource_exposed": False,
            "detail": "authorization_denied",
        }
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


def idor_observations(
    requester: AuthorizationRequester,
    snapshot: ResourceSnapshot,
) -> tuple[tuple[WorkerObservation, ...], tuple[str, ...]]:
    initial = snapshot()
    scenarios = (
        (
            "read_owned_resource",
            "GET",
            "user_a",
            "tenant_a",
            "resource_a",
            "",
            True,
            "functional_baseline",
        ),
        (
            "update_owned_resource",
            "PATCH",
            "user_a",
            "tenant_a",
            "resource_a",
            "owner_update",
            True,
            "functional_baseline",
        ),
        (
            "read_foreign_resource",
            "GET",
            "user_a",
            "tenant_a",
            "resource_b",
            "",
            False,
            "owner_authorization_control",
        ),
        (
            "update_foreign_resource",
            "PATCH",
            "user_a",
            "tenant_a",
            "resource_b",
            "foreign_update",
            False,
            "owner_authorization_control",
        ),
        (
            "read_cross_tenant_resource",
            "GET",
            "user_a",
            "tenant_a",
            "resource_c",
            "",
            False,
            "tenant_authorization_control",
        ),
        (
            "update_cross_tenant_resource",
            "PATCH",
            "user_a",
            "tenant_a",
            "resource_c",
            "cross_tenant_update",
            False,
            "tenant_authorization_control",
        ),
    )
    observations: list[WorkerObservation] = []
    limitations: list[str] = []
    for (
        scenario,
        method,
        user_id,
        tenant_id,
        resource_id,
        value,
        baseline,
        oracle,
    ) in scenarios:
        before = snapshot()
        response = requester(
            method,
            resource_id,
            user_id,
            tenant_id,
            value,
        )
        after = snapshot()
        observation, scenario_limitations = _idor_observation(
            scenario=scenario,
            method=method,
            resource_id=resource_id,
            user_id=user_id,
            tenant_id=tenant_id,
            value=value,
            response=response,
            before=before,
            after=after,
            baseline=baseline,
            oracle=oracle,
        )
        observations.append(observation)
        limitations.extend(scenario_limitations)

    final = snapshot()
    for resource_id, oracle in (
        ("resource_b", "owner_state_invariant"),
        ("resource_c", "tenant_state_invariant"),
    ):
        unchanged = final.get(resource_id) == initial.get(resource_id)
        observations.append(WorkerObservation(
            scenario=f"{resource_id}_final_state",
            stimulus=f"state:{resource_id}",
            oracle=oracle,
            expected="A foreign authorization attempt leaves state unchanged.",
            actual={
                "resource_id": resource_id,
                "state_before": _state_label(initial.get(resource_id)),
                "state_after": _state_label(final.get(resource_id)),
                "state_unchanged": unchanged,
            },
            baseline=False,
            oracle_role=SECONDARY_SECURITY,
            required_for_conclusion=True,
            oracle_evaluated=True,
            oracle_passed=unchanged,
            evidence=(
                f"resource_id:{resource_id}",
                f"state_unchanged:{str(unchanged).lower()}",
            ),
            cost_units=0,
        ))
    return tuple(observations), tuple(dict.fromkeys(limitations))


def logical_path(
    candidate: Path,
    layout: PathFixtureLayout,
) -> str:
    if candidate.is_relative_to(layout.allowed):
        return (
            "allowed/"
            + candidate.relative_to(layout.allowed).as_posix()
        )
    if candidate.is_relative_to(layout.root):
        return candidate.relative_to(layout.root).as_posix()
    return "outside_fixture_root"


def _path_observation(
    *,
    scenario: str,
    stimulus: str,
    response: ClientResponse,
    baseline: bool,
) -> tuple[WorkerObservation, tuple[str, ...]]:
    body = response.body
    actual = {
        "response_status": response.status_code,
        "decision": str(body.get("decision") or "unknown"),
        "marker": str(body.get("marker") or "none"),
        "resolved_path": str(
            body.get("resolved_path") or "not_observed"
        ),
        "sentinel_reached": body.get("marker") == "sentinel",
    }
    limitations: list[str] = []
    if baseline:
        evaluated = True
        passed: bool | None = (
            response.status_code == 200
            and body.get("marker") == "public"
            and body.get("resolved_path") == "allowed/public.txt"
        )
        oracle = "functional_baseline"
        expected = "The legitimate file remains readable under the allowed root."
    else:
        oracle = "path_boundary_invariant"
        expected = "The controlled path cannot read outside the allowed root."
        denied = (
            response.status_code in {403, 404}
            and body.get("marker") != "sentinel"
        )
        bypassed = (
            response.status_code == 200
            and body.get("marker") == "sentinel"
            and body.get("resolved_path") == "outside/sentinel.txt"
        )
        if denied:
            evaluated = True
            passed = True
        elif bypassed:
            evaluated = True
            passed = False
        else:
            evaluated = False
            passed = None
            limitations.append("unexpected_path_response")
    evidence = (
        f"scenario:{scenario}",
        f"response_status:{response.status_code}",
        f"decision:{actual['decision']}",
        f"marker:{actual['marker']}",
        f"resolved_path:{actual['resolved_path']}",
    )
    return (
        WorkerObservation(
            scenario=scenario,
            stimulus=stimulus,
            oracle=oracle,
            expected=expected,
            actual=actual,
            baseline=baseline,
            oracle_role=(
                FUNCTIONAL_BASELINE
                if baseline
                else (
                    OPTIONAL
                    if scenario == "symlink_boundary"
                    else PRIMARY_SECURITY
                )
            ),
            required_for_conclusion=scenario != "symlink_boundary",
            oracle_evaluated=evaluated,
            oracle_passed=passed,
            evidence=evidence,
            limitations=tuple(limitations),
        ),
        tuple(limitations),
    )


def _idor_observation(
    *,
    scenario: str,
    method: str,
    resource_id: str,
    user_id: str,
    tenant_id: str,
    value: str,
    response: ClientResponse,
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
    baseline: bool,
    oracle: str,
) -> tuple[WorkerObservation, tuple[str, ...]]:
    body = response.body
    before_resource = copy.deepcopy(before.get(resource_id))
    after_resource = copy.deepcopy(after.get(resource_id))
    state_changed = before_resource != after_resource
    actual = {
        "authenticated": bool(user_id),
        "principal_id": user_id,
        "tenant_id": tenant_id,
        "resource_id": resource_id,
        "resource_owner": (
            before_resource.get("owner_id")
            if isinstance(before_resource, dict)
            else "missing"
        ),
        "resource_tenant": (
            before_resource.get("tenant_id")
            if isinstance(before_resource, dict)
            else "missing"
        ),
        "operation": method.lower(),
        "response_status": response.status_code,
        "allowed": bool(body.get("allowed", False)),
        "resource_exposed": bool(
            body.get("resource_exposed", False)
        ),
        "state_changed": state_changed,
        "state_before": _state_label(before_resource),
        "state_after": _state_label(after_resource),
    }
    limitations: list[str] = []
    if baseline:
        if method == "GET":
            passed: bool | None = (
                response.status_code == 200
                and body.get("allowed") is True
                and body.get("resource_exposed") is True
                and not state_changed
                and body.get("owner_id") == user_id
                and body.get("tenant_id") == tenant_id
            )
        else:
            passed = (
                response.status_code == 200
                and body.get("allowed") is True
                and state_changed
                and isinstance(after_resource, dict)
                and after_resource.get("value") == value
                and after_resource.get("owner_id") == user_id
                and after_resource.get("tenant_id") == tenant_id
            )
        evaluated = True
        expected = "The owner can perform the expected operation."
    else:
        denied = (
            response.status_code in {401, 403, 404}
            and body.get("allowed") is False
            and body.get("resource_exposed") is False
            and not state_changed
        )
        bypassed = (
            response.status_code == 200
            and body.get("allowed") is True
            and (
                (
                    method == "GET"
                    and body.get("resource_exposed") is True
                )
                or (method == "PATCH" and state_changed)
            )
        )
        if denied:
            evaluated = True
            passed = True
        elif bypassed:
            evaluated = True
            passed = False
        else:
            evaluated = False
            passed = None
            limitations.append("unexpected_authorization_response")
        expected = (
            "Authentication alone does not authorize a foreign owner or tenant."
        )
    evidence = (
        f"scenario:{scenario}",
        f"response_status:{response.status_code}",
        f"allowed:{str(actual['allowed']).lower()}",
        f"resource_exposed:{str(actual['resource_exposed']).lower()}",
        f"state_changed:{str(state_changed).lower()}",
        f"resource_owner:{actual['resource_owner']}",
        f"resource_tenant:{actual['resource_tenant']}",
    )
    return (
        WorkerObservation(
            scenario=scenario,
            stimulus=(
                f"{method.lower()}:{user_id}:{tenant_id}:{resource_id}"
            ),
            oracle=oracle,
            expected=expected,
            actual=actual,
            baseline=baseline,
            oracle_role=(
                FUNCTIONAL_BASELINE
                if baseline
                else PRIMARY_SECURITY
            ),
            required_for_conclusion=True,
            oracle_evaluated=evaluated,
            oracle_passed=passed,
            evidence=evidence,
            limitations=tuple(limitations),
        ),
        tuple(limitations),
    )


def _state_label(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {"status": "missing"}
    return {
        "status": "present",
        "owner_id": str(value.get("owner_id") or ""),
        "tenant_id": str(value.get("tenant_id") or ""),
        "value": str(value.get("value") or ""),
    }


__all__ = [
    "AuthorizationRequester",
    "ClientResponse",
    "PUBLIC_MARKER",
    "PathFixtureLayout",
    "SENTINEL_MARKER",
    "idor_observations",
    "initial_resources",
    "path_observations",
    "prepare_path_layout",
    "serve_path",
    "serve_resource",
]
