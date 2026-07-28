"""In-memory IDOR/BOLA validation with fixed identities and state oracles."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass
from typing import Any

from ..execution_models import (
    ValidationExecutionContext,
    ValidationExecutionSummary,
    ValidationObservation,
)
from ..plan_models import ValidationPlan, clean_text
from .base import (
    LocalValidationExecutor,
    ValidationEntrypointUnavailable,
    baseline_verdict,
    conclusive_safe_outcome,
    resolved_runtime_gaps,
    stable_limitations,
    validation_plan_digest,
)


@dataclass(frozen=True)
class AuthorizationRequest:
    principal_id: str
    tenant_id: str
    operation: str
    resource_id: str
    value: str = ""


@dataclass(frozen=True)
class AuthorizationResponse:
    status: int
    allowed: bool
    resource_exposed: bool = False
    detail: str = ""

    def __post_init__(self) -> None:
        if (
            not isinstance(self.status, int)
            or isinstance(self.status, bool)
            or not 100 <= self.status <= 599
        ):
            raise ValueError("authorization response status is invalid")
        object.__setattr__(self, "detail", clean_text(self.detail))


ResourceStore = MutableMapping[str, dict[str, str]]
AuthorizationTarget = Callable[
    [AuthorizationRequest, ResourceStore],
    AuthorizationResponse,
]


def _perform(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    resource = resources.get(request.resource_id)
    if resource is None:
        return AuthorizationResponse(404, False, False, "not_found")
    if request.operation == "read":
        return AuthorizationResponse(200, True, True, "returned")
    if request.operation == "update":
        resource["value"] = request.value
        return AuthorizationResponse(200, True, False, "updated")
    if request.operation == "delete":
        del resources[request.resource_id]
        return AuthorizationResponse(204, True, False, "deleted")
    raise ValueError("unsupported fixture operation")


def _deny() -> AuthorizationResponse:
    return AuthorizationResponse(403, False, False, "denied")


def _authentication_only(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    if not request.principal_id:
        return AuthorizationResponse(401, False, False, "unauthenticated")
    return _perform(request, resources)


def _owner_tenant_enforced(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    resource = resources.get(request.resource_id)
    if resource is None:
        return AuthorizationResponse(404, False, False, "not_found")
    if (
        resource["owner_id"] != request.principal_id
        or resource["tenant_id"] != request.tenant_id
    ):
        return _deny()
    return _perform(request, resources)


def _tenant_only(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    resource = resources.get(request.resource_id)
    if resource is None:
        return AuthorizationResponse(404, False, False, "not_found")
    if resource["tenant_id"] != request.tenant_id:
        return _deny()
    return _perform(request, resources)


def _owner_without_tenant(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    resource = resources.get(request.resource_id)
    if resource is None:
        return AuthorizationResponse(404, False, False, "not_found")
    if resource["owner_id"] != request.principal_id:
        return _deny()
    return _perform(request, resources)


def _wrong_resource_guard(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    guard_resource = resources.get("resource_a")
    if (
        guard_resource is None
        or guard_resource["owner_id"] != request.principal_id
    ):
        return _deny()
    return _perform(request, resources)


def _guard_after_operation(
    request: AuthorizationRequest,
    resources: ResourceStore,
) -> AuthorizationResponse:
    resource_before = copy.deepcopy(resources.get(request.resource_id))
    response = _perform(request, resources)
    if resource_before is None:
        return response
    authorized = (
        resource_before["owner_id"] == request.principal_id
        and resource_before["tenant_id"] == request.tenant_id
    )
    if authorized:
        return response
    return AuthorizationResponse(
        403,
        False,
        resource_exposed=(
            response.resource_exposed or request.operation == "read"
        ),
        detail="denied_after_operation",
    )


def _entrypoint_unavailable(
    _request: AuthorizationRequest,
    _resources: ResourceStore,
) -> AuthorizationResponse:
    raise ValidationEntrypointUnavailable(
        "fixture entrypoint is not reproducible"
    )


BUILTIN_IDOR_ADAPTERS: Mapping[str, AuthorizationTarget] = {
    "idor_authentication_only": _authentication_only,
    "idor_lookup_unscoped": _authentication_only,
    "idor_owner_tenant_enforced": _owner_tenant_enforced,
    "idor_tenant_only": _tenant_only,
    "idor_owner_without_tenant": _owner_without_tenant,
    "idor_wrong_resource_guard": _wrong_resource_guard,
    "idor_guard_after_operation": _guard_after_operation,
    "idor_entrypoint_unavailable": _entrypoint_unavailable,
}


class IDORValidationExecutor(LocalValidationExecutor):
    """Evaluate authorization and state invariants in a fixed memory store."""

    validation_type = "idor_bola"
    case_types = frozenset({"idor_bola_possible"})

    def execute(
        self,
        plan: ValidationPlan,
        context: ValidationExecutionContext,
    ) -> ValidationExecutionSummary:
        adapter = _idor_adapter(context)
        plan_digest = validation_plan_digest(plan)
        if adapter is None:
            return ValidationExecutionSummary(
                validation_plan_id=plan.plan_id,
                validation_plan_digest=plan_digest,
                subject_id=plan.subject_id,
                validation_type=self.validation_type,
                source_revision=context.source_revision,
                fixture_id=context.fixture_id,
                fixture_digest=context.fixture_digest,
                adapter=context.adapter,
                supported=True,
                executed=False,
                outcome="inconclusive",
                baseline_passed=None,
                limitations=(
                    f"unregistered_fixture_adapter:{context.adapter}",
                ),
            )

        scenarios = (
            (
                "read_owned_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "read",
                    "resource_a",
                ),
                True,
            ),
            (
                "update_owned_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "update",
                    "resource_a",
                    "owner_update",
                ),
                True,
            ),
            (
                "read_foreign_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "read",
                    "resource_b",
                ),
                False,
            ),
            (
                "update_foreign_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "update",
                    "resource_b",
                    "foreign_update",
                ),
                False,
            ),
            (
                "delete_foreign_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "delete",
                    "resource_b",
                ),
                False,
            ),
            (
                "read_wrong_tenant_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "read",
                    "resource_c",
                ),
                False,
            ),
            (
                "update_wrong_tenant_resource",
                AuthorizationRequest(
                    "user_a",
                    "tenant_a",
                    "update",
                    "resource_c",
                    "cross_tenant_update",
                ),
                False,
            ),
        )

        observations: list[ValidationObservation] = []
        limitations: list[str] = []
        for scenario, request, baseline in scenarios:
            scenario_observations, scenario_limitations = _observe_idor(
                plan,
                adapter,
                scenario=scenario,
                request=request,
                baseline=baseline,
            )
            observations.extend(scenario_observations)
            limitations.extend(scenario_limitations)

        baseline_passed = baseline_verdict(observations)
        security = [
            item for item in observations if not item.baseline
        ]
        failed_security = [
            item
            for item in security
            if item.oracle_evaluated and item.oracle_passed is False
        ]
        unevaluated_security = [
            item for item in security if not item.oracle_evaluated
        ]
        if baseline_passed and failed_security:
            outcome = "bypassed"
        elif baseline_passed and not unevaluated_security:
            outcome = conclusive_safe_outcome(plan)
        else:
            outcome = "inconclusive"
        conclusive = outcome != "inconclusive"
        return ValidationExecutionSummary(
            validation_plan_id=plan.plan_id,
            validation_plan_digest=plan_digest,
            subject_id=plan.subject_id,
            validation_type=self.validation_type,
            source_revision=context.source_revision,
            fixture_id=context.fixture_id,
            fixture_digest=context.fixture_digest,
            adapter=context.adapter,
            supported=True,
            executed=True,
            outcome=outcome,
            baseline_passed=baseline_passed,
            observations=tuple(observations),
            resolved_evidence_gaps=resolved_runtime_gaps(
                plan,
                conclusive=conclusive,
            ),
            limitations=stable_limitations(limitations),
            protected_regression=(
                outcome == "bypassed"
                and plan.case_status
                in {"protected", "false_positive_likely"}
            ),
        )


def _idor_adapter(
    context: ValidationExecutionContext,
) -> AuthorizationTarget | None:
    builtin = BUILTIN_IDOR_ADAPTERS.get(context.adapter)
    if builtin is not None:
        return builtin
    return context.adapter_registry.get(context.adapter)


def _observe_idor(
    plan: ValidationPlan,
    adapter: AuthorizationTarget,
    *,
    scenario: str,
    request: AuthorizationRequest,
    baseline: bool,
) -> tuple[tuple[ValidationObservation, ...], tuple[str, ...]]:
    resources = _resource_fixture()
    before = copy.deepcopy(resources.get(request.resource_id))
    limitations: list[str] = []
    try:
        response = adapter(request, resources)
        if not isinstance(response, AuthorizationResponse):
            raise TypeError(
                "IDOR adapter must return AuthorizationResponse"
            )
    except ValidationEntrypointUnavailable:
        limitations.append("entrypoint_unavailable")
        return (
            (
                _unavailable_observation(
                    plan,
                    scenario=scenario,
                    request=request,
                    baseline=baseline,
                    limitation="entrypoint_unavailable",
                ),
            ),
            tuple(limitations),
        )
    except Exception as exc:
        limitation = f"entrypoint_error:{type(exc).__name__}"
        limitations.append(limitation)
        return (
            (
                _unavailable_observation(
                    plan,
                    scenario=scenario,
                    request=request,
                    baseline=baseline,
                    limitation=limitation,
                ),
            ),
            tuple(limitations),
        )

    after = copy.deepcopy(resources.get(request.resource_id))
    state_changed = before != after
    actual = {
        "principal_id": request.principal_id,
        "tenant_id": request.tenant_id,
        "resource_id": request.resource_id,
        "operation": request.operation,
        "response_status": response.status,
        "allowed": response.allowed,
        "resource_exposed": response.resource_exposed,
        "state_changed": state_changed,
        "resource_owner": (
            before.get("owner_id") if isinstance(before, dict) else "missing"
        ),
        "resource_tenant": (
            before.get("tenant_id") if isinstance(before, dict) else "missing"
        ),
    }
    evidence = (
        f"scenario:{scenario}",
        f"response_status:{response.status}",
        f"allowed:{str(response.allowed).lower()}",
        f"state_changed:{str(state_changed).lower()}",
    )
    if baseline:
        if request.operation == "read":
            passed = (
                response.allowed
                and response.resource_exposed
                and response.status == 200
                and not state_changed
            )
        else:
            passed = (
                response.allowed
                and response.status == 200
                and state_changed
                and isinstance(after, dict)
                and after.get("value") == request.value
            )
        return (
            (
                ValidationObservation(
                    validation_plan_id=plan.plan_id,
                    subject_id=plan.subject_id,
                    validation_type="idor_bola",
                    scenario=scenario,
                    stimulus=_stimulus_label(request),
                    oracle="functional_baseline",
                    expected=(
                        "The owner can perform the expected operation."
                    ),
                    actual=actual,
                    baseline=True,
                    oracle_evaluated=True,
                    oracle_passed=passed,
                    evidence=evidence,
                ),
            ),
            (),
        )

    authorization_passed = (
        not response.allowed
        and not response.resource_exposed
        and response.status in {401, 403, 404}
    )
    authorization = ValidationObservation(
        validation_plan_id=plan.plan_id,
        subject_id=plan.subject_id,
        validation_type="idor_bola",
        scenario=scenario,
        stimulus=_stimulus_label(request),
        oracle="authorization_differential",
        expected=(
            "The fixed principal cannot access a foreign resource or tenant."
        ),
        actual=actual,
        baseline=False,
        oracle_evaluated=True,
        oracle_passed=authorization_passed,
        evidence=evidence,
    )
    if request.operation == "read":
        return (authorization,), ()

    state = ValidationObservation(
        validation_plan_id=plan.plan_id,
        subject_id=plan.subject_id,
        validation_type="idor_bola",
        scenario=f"{scenario}_state",
        stimulus=_stimulus_label(request),
        oracle="state_invariant",
        expected=(
            "A denied foreign operation leaves the resource unchanged."
        ),
        actual={
            **actual,
            "state_before": _state_label(before),
            "state_after": _state_label(after),
        },
        baseline=False,
        oracle_evaluated=True,
        oracle_passed=not state_changed,
        evidence=(*evidence, "state_oracle_evaluated"),
        cost_units=0,
    )
    return (authorization, state), ()


def _unavailable_observation(
    plan: ValidationPlan,
    *,
    scenario: str,
    request: AuthorizationRequest,
    baseline: bool,
    limitation: str,
) -> ValidationObservation:
    return ValidationObservation(
        validation_plan_id=plan.plan_id,
        subject_id=plan.subject_id,
        validation_type="idor_bola",
        scenario=scenario,
        stimulus=_stimulus_label(request),
        oracle=(
            "functional_baseline"
            if baseline
            else "authorization_differential"
        ),
        expected=(
            "The local fixture entrypoint returns reproducible evidence."
        ),
        actual={
            "operation": request.operation,
            "decision": "not_observed",
        },
        baseline=baseline,
        oracle_evaluated=False,
        oracle_passed=None,
        limitations=(limitation,),
    )


def _resource_fixture() -> dict[str, dict[str, str]]:
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


def _stimulus_label(request: AuthorizationRequest) -> str:
    return (
        f"{request.operation}:{request.principal_id}:"
        f"{request.tenant_id}:{request.resource_id}"
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
    "AuthorizationRequest",
    "AuthorizationResponse",
    "AuthorizationTarget",
    "BUILTIN_IDOR_ADAPTERS",
    "IDORValidationExecutor",
]
