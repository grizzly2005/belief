"""Base contracts shared by explicitly registered local validators."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from ..execution_models import (
    ValidationExecutionContext,
    ValidationExecutionSummary,
    ValidationObservation,
)
from ..plan_models import ValidationPlan, canonical_digest


class ValidationEntrypointUnavailable(RuntimeError):
    """The trusted fixture could not call its bounded entrypoint reliably."""


class ValidationAccessDenied(PermissionError):
    """A fixture deliberately denied the tested operation."""


class LocalValidationExecutor(ABC):
    """Executor selected explicitly by audit-case type."""

    validation_type: str
    case_types: frozenset[str]

    def supports(self, plan: ValidationPlan) -> bool:
        return plan.case_type in self.case_types

    @abstractmethod
    def execute(
        self,
        plan: ValidationPlan,
        context: ValidationExecutionContext,
    ) -> ValidationExecutionSummary:
        """Execute one trusted local fixture and return oracle evidence."""


def validation_plan_digest(plan: ValidationPlan) -> str:
    return canonical_digest(plan.to_dict())


def resolved_runtime_gaps(
    plan: ValidationPlan,
    *,
    conclusive: bool,
) -> tuple[str, ...]:
    """Return only gaps directly resolved by a completed local oracle."""

    if not conclusive:
        return ()
    resolvable = {
        "dynamic_exploitability_not_observed",
        "runtime_guard_enforcement_not_observed",
        "runtime_entrypoint_not_mapped",
    }
    return tuple(
        gap
        for gap in plan.evidence_gaps
        if gap in resolvable
    )


def conclusive_safe_outcome(plan: ValidationPlan) -> str:
    """Use false_positive only for an explicit likely-false-positive case."""

    return (
        "false_positive"
        if plan.case_status == "false_positive_likely"
        else "enforced"
    )


def baseline_verdict(
    observations: Iterable[ValidationObservation],
) -> bool | None:
    """Return a tri-state verdict for the complete functional baseline.

    A demonstrated failure remains ``False``. A baseline is ``True`` only
    when every baseline oracle was evaluated and passed. Missing or partially
    unavailable baseline evidence remains ``None`` instead of being
    misclassified as a functional regression.
    """

    baseline = tuple(
        observation
        for observation in observations
        if observation.baseline
    )
    if any(
        observation.oracle_evaluated
        and observation.oracle_passed is False
        for observation in baseline
    ):
        return False
    if baseline and all(
        observation.oracle_evaluated
        and observation.oracle_passed is True
        for observation in baseline
    ):
        return True
    return None


def stable_limitations(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value) for value in values if str(value)))


__all__ = [
    "LocalValidationExecutor",
    "ValidationAccessDenied",
    "ValidationEntrypointUnavailable",
    "baseline_verdict",
    "conclusive_safe_outcome",
    "resolved_runtime_gaps",
    "stable_limitations",
    "validation_plan_digest",
]
