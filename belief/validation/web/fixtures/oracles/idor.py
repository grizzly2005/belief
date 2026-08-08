"""Authorization evaluator that never calls application decision helpers."""

from __future__ import annotations

import copy
from typing import Any, Iterable, Mapping

from ....evidence_policy import (
    FUNCTIONAL_BASELINE,
    PRIMARY_SECURITY,
    SECONDARY_SECURITY,
)
from ....worker.contracts import WorkerObservation
from ..apps.contracts import ResourceApplication


def evaluate_resource_application(
    application: ResourceApplication,
    scenarios: Iterable[Mapping[str, Any]],
) -> tuple[tuple[WorkerObservation, ...], tuple[str, ...]]:
    initial = application.state()
    observations: list[WorkerObservation] = []
    limitations: list[str] = []
    for raw in scenarios:
        before = application.state()
        response = application.request(
            str(raw["method"]),
            str(raw["resource_id"]),
            str(raw["user_id"]),
            str(raw["tenant_id"]),
            str(raw["value"]),
        )
        after = application.state()
        observation, item_limitations = _evaluate_response(
            scenario=str(raw["scenario"]),
            method=str(raw["method"]),
            resource_id=str(raw["resource_id"]),
            user_id=str(raw["user_id"]),
            tenant_id=str(raw["tenant_id"]),
            value=str(raw["value"]),
            response_status=response.status_code,
            body=response.body,
            before=before,
            after=after,
            baseline=raw["baseline"] is True,
            oracle=str(raw["oracle"]),
        )
        observations.append(observation)
        limitations.extend(item_limitations)

    final = application.state()
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


def _evaluate_response(
    *,
    scenario: str,
    method: str,
    resource_id: str,
    user_id: str,
    tenant_id: str,
    value: str,
    response_status: int,
    body: Mapping[str, Any],
    before: dict[str, dict[str, str]],
    after: dict[str, dict[str, str]],
    baseline: bool,
    oracle: str,
) -> tuple[WorkerObservation, tuple[str, ...]]:
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
        "response_status": response_status,
        "allowed": bool(body.get("allowed", False)),
        "resource_exposed": bool(body.get("resource_exposed", False)),
        "state_changed": state_changed,
        "state_before": _state_label(before_resource),
        "state_after": _state_label(after_resource),
    }
    limitations: list[str] = []
    if baseline:
        if method == "GET":
            passed: bool | None = (
                response_status == 200
                and body.get("allowed") is True
                and body.get("resource_exposed") is True
                and not state_changed
                and body.get("owner_id") == user_id
                and body.get("tenant_id") == tenant_id
            )
        else:
            passed = (
                response_status == 200
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
            response_status in {401, 403, 404}
            and body.get("allowed") is False
            and body.get("resource_exposed") is False
            and not state_changed
        )
        bypassed = (
            response_status == 200
            and body.get("allowed") is True
            and (
                method == "GET"
                and body.get("resource_exposed") is True
                or method == "PATCH"
                and state_changed
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
    return (
        WorkerObservation(
            scenario=scenario,
            stimulus=f"{method.lower()}:{user_id}:{tenant_id}:{resource_id}",
            oracle=oracle,
            expected=expected,
            actual=actual,
            baseline=baseline,
            oracle_role=(
                FUNCTIONAL_BASELINE if baseline else PRIMARY_SECURITY
            ),
            required_for_conclusion=True,
            oracle_evaluated=evaluated,
            oracle_passed=passed,
            evidence=(
                f"scenario:{scenario}",
                f"response_status:{response_status}",
                f"allowed:{str(actual['allowed']).lower()}",
                f"resource_exposed:{str(actual['resource_exposed']).lower()}",
                f"state_changed:{str(state_changed).lower()}",
                f"resource_owner:{actual['resource_owner']}",
                f"resource_tenant:{actual['resource_tenant']}",
            ),
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


__all__ = ["evaluate_resource_application"]
