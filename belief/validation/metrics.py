"""Deterministic metrics for local validation-result bundles."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .evidence_policy import evaluate_evidence, infer_legacy_oracle_role
from .models import ValidationResult


VALIDATION_METRICS_SCHEMA_VERSION = "belief.validation_metrics.v2"


def summarize_validation_results(
    results: Sequence[ValidationResult],
) -> dict[str, Any]:
    """Summarize executions without conflating them with SecPass."""

    summaries = []
    for result in results:
        execution = result.metadata.get("execution")
        if not isinstance(execution, dict):
            raise ValueError(
                "validation result is missing execution metadata"
            )
        summaries.append(execution)

    decisions = []
    for result, summary in zip(results, summaries, strict=True):
        observations = _policy_observations(summary.get("observations"))
        decision = evaluate_evidence(
            observations,
            completed=summary.get("executed") is True,
            safe_outcome=(
                "false_positive"
                if result.outcome == "false_positive"
                else "enforced"
            ),
        )
        if decision.outcome != result.outcome:
            raise ValueError(
                "validation result contradicts the evidence policy"
            )
        if decision.baseline_passed != summary.get("baseline_passed"):
            raise ValueError(
                "validation result baseline contradicts its observations"
            )
        decisions.append(decision)

    executed = [
        item for item in summaries if item.get("executed") is True
    ]
    resolved = [
        item
        for item in executed
        if item.get("resolved_evidence_gaps")
    ]
    executed_decisions = [
        decision
        for summary, decision in zip(summaries, decisions, strict=True)
        if summary.get("executed") is True
    ]
    baseline_passes = sum(
        item.baseline_passed is True for item in executed_decisions
    )
    baseline_failures = sum(
        item.baseline_passed is False for item in executed_decisions
    )
    baseline_not_evaluated = sum(
        item.baseline_passed is None for item in executed_decisions
    )
    oracle_counts = []
    for item in summaries:
        count = item.get("oracle_evaluated_count", 0)
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
        ):
            raise ValueError(
                "validation result has an invalid evaluated-oracle count"
            )
        oracle_counts.append(count)
        observations = item.get("observations")
        evaluated = sum(
            observation.get("oracle_evaluated") is True
            for observation in observations
        )
        if count != evaluated:
            raise ValueError(
                "validation result evaluated-oracle count is inconsistent"
            )
    return {
        "schema_version": VALIDATION_METRICS_SCHEMA_VERSION,
        "plan_count": len(results),
        "supported_plan_count": sum(
            item.get("supported") is True for item in summaries
        ),
        "executed_plan_count": len(executed),
        "enforced_count": sum(
            result.outcome == "enforced" for result in results
        ),
        "bypassed_count": sum(
            result.outcome == "bypassed" for result in results
        ),
        "inconclusive_count": sum(
            result.outcome == "inconclusive" for result in results
        ),
        "false_positive_count": sum(
            result.outcome == "false_positive" for result in results
        ),
        "baseline_pass_count": baseline_passes,
        "baseline_failure_count": baseline_failures,
        "baseline_not_evaluated_count": baseline_not_evaluated,
        "oracle_evaluated_count": sum(oracle_counts),
        "plans_with_evaluated_oracle_count": sum(
            count > 0 for count in oracle_counts
        ),
        "primary_oracle_evaluated_count": sum(
            decision.evaluated_primary_count
            for decision in decisions
        ),
        "conclusive_plan_count": sum(
            decision.conclusive for decision in decisions
        ),
        "evidence_gap_resolution_rate": round(
            len(resolved) / len(executed),
            6,
        )
        if executed
        else 0.0,
        "protected_regression_count": sum(
            item.get("protected_regression") is True
            for item in summaries
        ),
        "deterministic_cost_units": sum(
            int(
                item.get("deterministic_cost", {}).get("value", 0)
            )
            for item in summaries
            if isinstance(item.get("deterministic_cost"), dict)
        ),
        "secpass_equivalent": False,
    }


def _policy_observations(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValueError("validation result observations are invalid")
    normalized: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("validation result observation is invalid")
        observation = dict(item)
        if (
            "oracle_role" not in observation
            or "required_for_conclusion" not in observation
        ):
            try:
                role, required = infer_legacy_oracle_role(
                    baseline=observation["baseline"],
                    oracle=observation["oracle"],
                    scenario=observation["scenario"],
                )
            except (KeyError, TypeError) as exc:
                raise ValueError(
                    "validation result observation is incomplete"
                ) from exc
            observation["oracle_role"] = role
            observation["required_for_conclusion"] = required
        normalized.append(observation)
    return normalized


__all__ = [
    "VALIDATION_METRICS_SCHEMA_VERSION",
    "summarize_validation_results",
]
