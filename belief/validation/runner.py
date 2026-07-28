"""High-level, local-only execution of canonical validation plans."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .execution_models import (
    ValidationContractError,
    ValidationExecutionContext,
    ValidationExecutionSummary,
)
from .executors import (
    IDORValidationExecutor,
    LocalValidationExecutor,
    PathTraversalValidationExecutor,
)
from .executors.idor import BUILTIN_IDOR_ADAPTERS
from .executors.path_traversal import BUILTIN_PATH_ADAPTERS
from .metrics import summarize_validation_results
from .models import ValidationResult
from .plan_models import (
    ValidationPlan,
    canonical_digest,
    clean_text,
    stable_plan_id,
)
from .plans import validation_result_from_plan


VALIDATION_RESULT_BUNDLE_SCHEMA_VERSION = (
    "belief.validation_result_bundle.v2"
)

_BUILTIN_ADAPTERS_BY_CASE_TYPE = {
    "idor_bola_possible": frozenset(BUILTIN_IDOR_ADAPTERS),
    "path_traversal_possible": frozenset(BUILTIN_PATH_ADAPTERS),
}


def default_executor_registry() -> dict[str, LocalValidationExecutor]:
    """Return a fresh closed registry for the two supported verticals."""

    path = PathTraversalValidationExecutor()
    idor = IDORValidationExecutor()
    return {
        "path_traversal_possible": path,
        "idor_bola_possible": idor,
    }


def run_validation_plan(
    plan: ValidationPlan | Mapping[str, Any],
    *,
    context: ValidationExecutionContext,
    executor_registry: Mapping[
        str,
        LocalValidationExecutor,
    ]
    | None = None,
) -> ValidationResult:
    """Execute one canonical plan against one explicitly bound fixture."""

    canonical_plan = _canonical_plan(plan)
    plan_digest = canonical_digest(canonical_plan.to_dict())
    _validate_context_binding(
        canonical_plan,
        context,
        plan_digest=plan_digest,
    )
    registry = _executor_registry(executor_registry)
    executor = registry.get(canonical_plan.case_type)
    if executor is None:
        summary = ValidationExecutionSummary(
            validation_plan_id=canonical_plan.plan_id,
            validation_plan_digest=plan_digest,
            subject_id=canonical_plan.subject_id,
            validation_type=canonical_plan.case_type,
            source_revision=context.source_revision,
            fixture_id=context.fixture_id,
            fixture_digest=context.fixture_digest,
            adapter=context.adapter,
            supported=False,
            executed=False,
            outcome="inconclusive",
            baseline_passed=None,
            limitations=(
                f"unsupported_validation_type:{canonical_plan.case_type}",
            ),
        )
    else:
        _validate_safety_contract(canonical_plan)
        if not executor.supports(canonical_plan):
            raise ValidationContractError(
                "registered executor does not support its case type"
            )
        summary = executor.execute(canonical_plan, context)
        _validate_summary_binding(
            canonical_plan,
            context,
            summary,
            plan_digest=plan_digest,
        )
    return _result_from_summary(canonical_plan, summary)


def run_validation_plan_bundle(
    plans: Sequence[ValidationPlan | Mapping[str, Any]],
    *,
    contexts: Mapping[str, ValidationExecutionContext],
    executor_registry: Mapping[
        str,
        LocalValidationExecutor,
    ]
    | None = None,
    source_bundle_digest: str = "",
) -> dict[str, Any]:
    """Execute a complete plan bundle with exact fixture coverage."""

    canonical_plans = tuple(_canonical_plan(plan) for plan in plans)
    plan_ids = [plan.plan_id for plan in canonical_plans]
    if len(plan_ids) != len(set(plan_ids)):
        raise ValidationContractError(
            "validation plan bundle has duplicate plan ids"
        )
    context_ids = set(contexts)
    if context_ids != set(plan_ids):
        missing = sorted(set(plan_ids) - context_ids)
        extra = sorted(context_ids - set(plan_ids))
        detail = []
        if missing:
            detail.append("missing=" + ",".join(missing))
        if extra:
            detail.append("extra=" + ",".join(extra))
        raise ValidationContractError(
            "fixture bindings do not match validation plans: "
            + "; ".join(detail)
        )
    process_local_extension_used = (
        executor_registry is not None
        or any(
            _uses_process_local_adapter(
                plan,
                contexts[plan.plan_id],
            )
            for plan in canonical_plans
        )
    )
    results = tuple(
        run_validation_plan(
            plan,
            context=contexts[plan.plan_id],
            executor_registry=executor_registry,
        )
        for plan in canonical_plans
    )
    normalized_source_digest = clean_text(source_bundle_digest).lower()
    if normalized_source_digest and (
        len(normalized_source_digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in normalized_source_digest
        )
    ):
        raise ValidationContractError(
            "source validation-plan bundle digest is invalid"
        )
    payload: dict[str, Any] = {
        "schema_version": VALIDATION_RESULT_BUNDLE_SCHEMA_VERSION,
        "source_plan_bundle_digest": (
            normalized_source_digest
            or canonical_digest(
                [plan.to_dict() for plan in canonical_plans]
            )
        ),
        "boundaries": _execution_boundaries(
            process_local_extension_used=process_local_extension_used,
        ),
        "result_count": len(results),
        "metrics": summarize_validation_results(results),
        "results": [result.to_dict() for result in results],
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_validation_result_bundle(
    output: str | Path,
    payload: Mapping[str, Any],
) -> None:
    """Write a result bundle create-only."""

    canonical_payload = _validated_result_bundle(payload)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(
        canonical_payload,
        indent=2,
        sort_keys=True,
    ) + "\n"
    try:
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(rendered)
    except FileExistsError as exc:
        raise ValidationContractError(
            f"refusing to overwrite validation result bundle: {destination}"
        ) from exc


def _validated_result_bundle(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise ValidationContractError(
            "validation result bundle must be a JSON object"
        )
    canonical = dict(payload)
    if canonical.get("schema_version") != (
        VALIDATION_RESULT_BUNDLE_SCHEMA_VERSION
    ):
        raise ValidationContractError(
            "unsupported validation result bundle schema"
        )
    unsigned = dict(canonical)
    supplied_digest = clean_text(
        unsigned.pop("deterministic_digest", "")
    ).lower()
    if supplied_digest != canonical_digest(unsigned):
        raise ValidationContractError(
            "validation result bundle deterministic digest mismatch"
        )
    results = canonical.get("results")
    metrics = canonical.get("metrics")
    if (
        not isinstance(results, list)
        or not isinstance(metrics, Mapping)
        or not isinstance(canonical.get("result_count"), int)
        or isinstance(canonical.get("result_count"), bool)
        or canonical["result_count"] != len(results)
        or metrics.get("plan_count") != len(results)
    ):
        raise ValidationContractError(
            "validation result bundle counts are invalid"
        )
    boundaries = canonical.get("boundaries")
    extension_used = (
        boundaries.get("process_local_extension_used")
        if isinstance(boundaries, Mapping)
        else None
    )
    if (
        not isinstance(extension_used, bool)
        or boundaries
        != _execution_boundaries(
            process_local_extension_used=extension_used,
        )
    ):
        raise ValidationContractError(
            "validation result bundle boundaries are invalid"
        )
    return canonical


def _uses_process_local_adapter(
    plan: ValidationPlan,
    context: ValidationExecutionContext,
) -> bool:
    builtins = _BUILTIN_ADAPTERS_BY_CASE_TYPE.get(plan.case_type)
    return (
        builtins is not None
        and context.adapter not in builtins
        and context.adapter in context.adapter_registry
    )


def _execution_boundaries(
    *,
    process_local_extension_used: bool,
) -> dict[str, Any]:
    io_attested = not process_local_extension_used
    observed_usage: bool | None = False if io_attested else None
    return {
        "execution_mode": (
            "trusted_process_local_extension"
            if process_local_extension_used
            else "built_in_only"
        ),
        "process_local_extension_used": process_local_extension_used,
        "io_usage_attested": io_attested,
        "local_only": True if io_attested else None,
        "network_used": observed_usage,
        "subprocess_used": observed_usage,
        "shell_used": observed_usage,
        "docker_used": observed_usage,
        "dynamic_import_used": observed_usage,
        "production_data_used": observed_usage,
        "human_confirmation_claimed": False,
        "secpass_claimed": False,
    }


def _canonical_plan(
    plan: ValidationPlan | Mapping[str, Any],
) -> ValidationPlan:
    if isinstance(plan, ValidationPlan):
        if plan.plan_id != stable_plan_id(plan):
            raise ValidationContractError(
                "validation plan identity mismatch"
            )
        return plan
    if not isinstance(plan, Mapping):
        raise ValidationContractError(
            "validation plan must be a ValidationPlan or JSON object"
        )
    try:
        canonical = ValidationPlan.from_dict(plan)
    except ValueError as exc:
        raise ValidationContractError(str(exc)) from exc
    if canonical.to_dict() != dict(plan):
        raise ValidationContractError(
            "validation plan is not canonical"
        )
    return canonical


def _validate_context_binding(
    plan: ValidationPlan,
    context: ValidationExecutionContext,
    *,
    plan_digest: str,
) -> None:
    mismatches = []
    if context.validation_plan_id != plan.plan_id:
        mismatches.append("validation_plan_id")
    if context.case_type != plan.case_type:
        mismatches.append("case_type")
    if context.expected_plan_digest != plan_digest:
        mismatches.append("expected_plan_digest")
    if mismatches:
        raise ValidationContractError(
            "validation fixture does not match plan: "
            + ", ".join(mismatches)
        )


def _validate_safety_contract(plan: ValidationPlan) -> None:
    required = {
        "authorized_scope_required": True,
        "network_mode": "forbidden",
        "destructive_actions_allowed": False,
        "production_data_allowed": False,
        "real_secrets_allowed": False,
        "payload_policy": "benign_markers_only",
        "automatic_scope_expansion": False,
    }
    mismatches = [
        key
        for key, expected in required.items()
        if plan.safety.get(key) != expected
    ]
    if mismatches:
        raise ValidationContractError(
            "validation plan safety contract is incompatible: "
            + ", ".join(mismatches)
        )


def _executor_registry(
    supplied: Mapping[str, LocalValidationExecutor] | None,
) -> dict[str, LocalValidationExecutor]:
    registry = (
        default_executor_registry()
        if supplied is None
        else dict(supplied)
    )
    for case_type, executor in registry.items():
        if (
            not clean_text(case_type)
            or not isinstance(executor, LocalValidationExecutor)
            or case_type not in executor.case_types
        ):
            raise ValidationContractError(
                "validation executor registry is invalid"
            )
    return registry


def _validate_summary_binding(
    plan: ValidationPlan,
    context: ValidationExecutionContext,
    summary: ValidationExecutionSummary,
    *,
    plan_digest: str,
) -> None:
    expected = {
        "validation_plan_id": plan.plan_id,
        "validation_plan_digest": plan_digest,
        "subject_id": plan.subject_id,
        "source_revision": context.source_revision,
        "fixture_id": context.fixture_id,
        "fixture_digest": context.fixture_digest,
        "adapter": context.adapter,
    }
    mismatches = [
        key
        for key, value in expected.items()
        if getattr(summary, key) != value
    ]
    if mismatches:
        raise ValidationContractError(
            "validation executor returned mismatched evidence: "
            + ", ".join(mismatches)
        )


def _result_from_summary(
    plan: ValidationPlan,
    summary: ValidationExecutionSummary,
) -> ValidationResult:
    reasons = {
        "bypassed": (
            "A local security oracle failed while the functional baseline "
            "remained valid; human confirmation is still required."
        ),
        "enforced": (
            "The functional baseline passed and every evaluated local "
            "security oracle remained enforced."
        ),
        "false_positive": (
            "The explicitly likely-false-positive case retained a working "
            "baseline and all local security oracles were enforced."
        ),
        "inconclusive": (
            "The local fixture could not produce sufficient reproducible "
            "oracle evidence."
        ),
    }
    confidence = {
        "bypassed": 0.95,
        "enforced": 0.9,
        "false_positive": 0.9,
        "inconclusive": 0.2,
    }[summary.outcome]
    evidence = [
        f"execution_summary:{summary.summary_id}",
        f"fixture:{summary.fixture_id}",
        f"adapter:{summary.adapter}",
        f"oracle_evaluated_count:{summary.oracle_evaluated_count}",
    ]
    if summary.baseline_passed is not None:
        evidence.append(
            "baseline_passed:"
            + str(summary.baseline_passed).lower()
        )
    for observation in summary.observations:
        if observation.oracle_passed is False:
            evidence.append(
                f"oracle_failed:{observation.oracle}:"
                f"{observation.scenario}"
            )
    return validation_result_from_plan(
        plan,
        source="belief.local_validation_executor.v1",
        outcome=summary.outcome,
        confidence=confidence,
        tested=(
            summary.executed
            and summary.oracle_evaluated_count > 0
        ),
        human_validated=False,
        method=(
            f"local_fixture/{summary.validation_type}/{summary.adapter}"
        ),
        reason=reasons[summary.outcome],
        evidence=tuple(evidence),
        metadata={
            "validation_plan_digest": summary.validation_plan_digest,
            "source_revision": summary.source_revision,
            "fixture_id": summary.fixture_id,
            "fixture_digest": summary.fixture_digest,
            "baseline_functional": summary.baseline_passed,
            "counterexamples_attempted": sum(
                not observation.baseline
                for observation in summary.observations
            ),
            "counterexamples_tested": sum(
                not observation.baseline
                and observation.oracle_evaluated
                for observation in summary.observations
            ),
            "oracle_evaluated_count": (
                summary.oracle_evaluated_count
            ),
            "proof_collected": [
                observation.observation_id
                for observation in summary.observations
                if observation.oracle_evaluated
            ],
            "limitations": list(summary.limitations),
            "deterministic_cost": {
                "unit": "local_operation",
                "value": summary.deterministic_cost_units,
            },
            "execution": summary.to_dict(),
            "human_confirmation_required": (
                summary.outcome == "bypassed"
            ),
        },
    )


__all__ = [
    "VALIDATION_RESULT_BUNDLE_SCHEMA_VERSION",
    "default_executor_registry",
    "run_validation_plan",
    "run_validation_plan_bundle",
    "write_validation_result_bundle",
]
