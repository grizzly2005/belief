"""Fail-closed projection from ValidationPlan to ExplorationObjective."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from belief.validation.plan_models import (
    VALIDATION_REACHABILITY_SCHEMA_VERSION,
    ValidationPlan,
)

from .models import (
    ExplorationConstraint,
    ExplorationObjective,
    ExplorationTarget,
)


class ExplorationCompileError(ValueError):
    """Raised when a validation plan lacks an explicit C objective contract."""


def compile_validation_plan(
    plan: ValidationPlan | Mapping[str, Any],
) -> ExplorationObjective:
    """Compile only explicit, structured C reachability hints.

    The compiler never derives a constraint from prose and never calls an LLM,
    parser subprocess, compiler, shell, or external analysis tool.
    """

    try:
        canonical = plan if isinstance(plan, ValidationPlan) else ValidationPlan.from_dict(plan)
    except (TypeError, ValueError) as exc:
        raise ExplorationCompileError(f"invalid ValidationPlan: {exc}") from exc

    hints = canonical.reachability_hints
    if hints.get("schema_version") != VALIDATION_REACHABILITY_SCHEMA_VERSION:
        raise ExplorationCompileError("unsupported reachability hint schema")
    if hints.get("language") != "c":
        raise ExplorationCompileError("exploration pilot accepts only explicit C hints")

    function_context = _required_mapping(hints.get("function_context"), "function_context")
    sink = _required_mapping(hints.get("sink"), "sink")
    candidate = _required_mapping(
        hints.get("candidate_constraint"),
        "candidate_constraint",
    )
    if set(function_context) != {"name"}:
        raise ExplorationCompileError("function_context must contain only name")
    if set(sink) != {"file", "line", "symbol"}:
        raise ExplorationCompileError("sink must contain file, line, and symbol")
    if set(candidate) != {"expression", "logic", "origin"}:
        raise ExplorationCompileError(
            "candidate_constraint must contain expression, logic, and origin"
        )

    try:
        return ExplorationObjective(
            subject_id=canonical.subject_id,
            source_plan_id=canonical.plan_id,
            language="c",
            function=function_context["name"],
            entry_boundary="function_entry",
            target=ExplorationTarget.from_dict(sink),
            constraint=ExplorationConstraint.from_dict(candidate),
        )
    except (TypeError, ValueError) as exc:
        raise ExplorationCompileError(f"cannot compile exploration objective: {exc}") from exc


def _required_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExplorationCompileError(f"{field} must be an explicit JSON object")
    return value


__all__ = ["ExplorationCompileError", "compile_validation_plan"]
