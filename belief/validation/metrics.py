"""Deterministic metrics for local validation-result bundles."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from .models import ValidationResult


VALIDATION_METRICS_SCHEMA_VERSION = "belief.validation_metrics.v1"


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

    executed = [
        item for item in summaries if item.get("executed") is True
    ]
    resolved = [
        item
        for item in executed
        if item.get("resolved_evidence_gaps")
    ]
    baseline_passes = sum(
        item.get("baseline_passed") is True
        for item in executed
    )
    baseline_failures = sum(
        item.get("baseline_passed") is False
        for item in executed
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
        "oracle_evaluated_count": sum(
            int(item.get("oracle_evaluated_count", 0) > 0)
            for item in summaries
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


__all__ = [
    "VALIDATION_METRICS_SCHEMA_VERSION",
    "summarize_validation_results",
]
