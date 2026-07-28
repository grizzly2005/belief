"""Isolated path-traversal validation using temporary sentinel files only."""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ..execution_models import (
    ValidationExecutionContext,
    ValidationExecutionSummary,
    ValidationObservation,
)
from ..plan_models import ValidationPlan
from .base import (
    LocalValidationExecutor,
    ValidationAccessDenied,
    ValidationEntrypointUnavailable,
    conclusive_safe_outcome,
    resolved_runtime_gaps,
    stable_limitations,
    validation_plan_digest,
)


PathTarget = Callable[[Path, str], str | Path]

_PUBLIC_MARKER = "BELIEF_LOCAL_PUBLIC"
_SENTINEL_MARKER = "BELIEF_LOCAL_SENTINEL"


def _unchecked_path(allowed_root: Path, value: str) -> Path:
    return (allowed_root / value).resolve()


def _enforced_path(allowed_root: Path, value: str) -> Path:
    candidate = (allowed_root / value).resolve()
    if not candidate.is_relative_to(allowed_root.resolve()):
        raise ValidationAccessDenied("candidate left the allowed root")
    return candidate


def _guard_after_sink(allowed_root: Path, value: str) -> Path:
    candidate = (allowed_root / value).resolve()
    # This intentionally models a guard evaluated after the sink decision.
    candidate.is_relative_to(allowed_root.resolve())
    return candidate


def _sanitizer_result_unused(allowed_root: Path, value: str) -> Path:
    Path(value).name
    return (allowed_root / value).resolve()


def _entrypoint_unavailable(_allowed_root: Path, _value: str) -> Path:
    raise ValidationEntrypointUnavailable(
        "fixture entrypoint is not reproducible"
    )


BUILTIN_PATH_ADAPTERS: Mapping[str, PathTarget] = {
    "path_join_unchecked": _unchecked_path,
    "path_resolve_enforced": _enforced_path,
    "path_guard_after_sink": _guard_after_sink,
    "path_sanitizer_result_unused": _sanitizer_result_unused,
    "path_entrypoint_unavailable": _entrypoint_unavailable,
}


class PathTraversalValidationExecutor(LocalValidationExecutor):
    """Evaluate path-boundary oracles inside one temporary sandbox."""

    validation_type = "path_traversal"
    case_types = frozenset({"path_traversal_possible"})

    def execute(
        self,
        plan: ValidationPlan,
        context: ValidationExecutionContext,
    ) -> ValidationExecutionSummary:
        adapter = _path_adapter(context)
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

        observations: list[ValidationObservation] = []
        limitations: list[str] = []
        with tempfile.TemporaryDirectory(
            prefix="belief-local-path-validation-"
        ) as temporary:
            sandbox = Path(temporary).resolve()
            allowed = sandbox / "allowed"
            outside = sandbox / "outside"
            nested = allowed / "nested"
            allowed.mkdir()
            outside.mkdir()
            nested.mkdir()
            public = allowed / "public.txt"
            sentinel = outside / "sentinel.txt"
            public.write_text(_PUBLIC_MARKER, encoding="utf-8")
            sentinel.write_text(_SENTINEL_MARKER, encoding="utf-8")

            scenarios = [
                (
                    "legitimate_path",
                    "public.txt",
                    True,
                ),
                (
                    "parent_segment",
                    "../outside/sentinel.txt",
                    False,
                ),
                (
                    "normalized_equivalent",
                    "nested/../../outside/sentinel.txt",
                    False,
                ),
                (
                    "absolute_path",
                    str(sentinel),
                    False,
                ),
            ]
            for scenario, stimulus, baseline in scenarios:
                observation, scenario_limitations = _observe_path(
                    plan,
                    adapter,
                    sandbox=sandbox,
                    allowed=allowed,
                    scenario=scenario,
                    stimulus=stimulus,
                    baseline=baseline,
                )
                observations.append(observation)
                limitations.extend(scenario_limitations)

            link = allowed / "linked-sentinel.txt"
            try:
                link.symlink_to(sentinel)
            except (NotImplementedError, OSError):
                limitations.append("symlink_unavailable")
                observations.append(
                    ValidationObservation(
                        validation_plan_id=plan.plan_id,
                        subject_id=plan.subject_id,
                        validation_type=self.validation_type,
                        scenario="symlink_boundary",
                        stimulus="allowed/linked-sentinel.txt",
                        oracle="path_boundary_invariant",
                        expected=(
                            "A symlink may not resolve outside the allowed root."
                        ),
                        actual={
                            "decision": "not_tested",
                            "symlink_supported": False,
                        },
                        baseline=False,
                        oracle_evaluated=False,
                        oracle_passed=None,
                        limitations=("symlink_unavailable",),
                        cost_units=0,
                    )
                )
            else:
                observation, scenario_limitations = _observe_path(
                    plan,
                    adapter,
                    sandbox=sandbox,
                    allowed=allowed,
                    scenario="symlink_boundary",
                    stimulus="linked-sentinel.txt",
                    baseline=False,
                )
                observations.append(observation)
                limitations.extend(scenario_limitations)

        baseline_observation = observations[0]
        baseline_passed = baseline_observation.oracle_passed is True
        security = [
            item
            for item in observations
            if not item.baseline
        ]
        failed_security = [
            item
            for item in security
            if item.oracle_evaluated and item.oracle_passed is False
        ]
        mandatory_unevaluated = [
            item
            for item in security
            if item.scenario != "symlink_boundary"
            and not item.oracle_evaluated
        ]

        if baseline_passed and failed_security:
            outcome = "bypassed"
        elif baseline_passed and not mandatory_unevaluated:
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


def _path_adapter(
    context: ValidationExecutionContext,
) -> PathTarget | None:
    builtin = BUILTIN_PATH_ADAPTERS.get(context.adapter)
    if builtin is not None:
        return builtin
    return context.adapter_registry.get(context.adapter)


def _observe_path(
    plan: ValidationPlan,
    adapter: PathTarget,
    *,
    sandbox: Path,
    allowed: Path,
    scenario: str,
    stimulus: str,
    baseline: bool,
) -> tuple[ValidationObservation, tuple[str, ...]]:
    expected = (
        "The legitimate file remains readable under the allowed root."
        if baseline
        else "The controlled path cannot resolve or read outside allowed."
    )
    limitations: list[str] = []
    actual: dict[str, Any] = {
        "decision": "error",
        "resolved_path": "not_observed",
        "content_marker": "none",
        "sentinel_reached": False,
    }
    evaluated = False
    passed: bool | None = None
    evidence: list[str] = []
    try:
        raw_candidate = adapter(allowed, stimulus)
        if not isinstance(raw_candidate, (str, Path)):
            raise TypeError("path adapter must return str or Path")
        candidate = Path(raw_candidate).resolve()
        label = _logical_path(candidate, sandbox, allowed)
        actual["resolved_path"] = label
        if not candidate.is_relative_to(sandbox):
            limitations.append("adapter_resolved_outside_fixture_root")
            actual["decision"] = "engine_blocked_out_of_fixture_access"
        else:
            content = candidate.read_text(encoding="utf-8")
            actual["decision"] = "read"
            if content == _PUBLIC_MARKER:
                actual["content_marker"] = "public"
            elif content == _SENTINEL_MARKER:
                actual["content_marker"] = "sentinel"
            else:
                actual["content_marker"] = "other"
            outside_allowed = not candidate.is_relative_to(allowed)
            sentinel_reached = (
                outside_allowed and content == _SENTINEL_MARKER
            )
            actual["sentinel_reached"] = sentinel_reached
            evaluated = True
            passed = (
                candidate == (allowed / "public.txt").resolve()
                and content == _PUBLIC_MARKER
                if baseline
                else not outside_allowed
            )
            evidence.extend(
                (
                    f"scenario:{scenario}",
                    f"resolved_path:{label}",
                    f"decision:{actual['decision']}",
                )
            )
            if sentinel_reached:
                evidence.append("outside_sentinel_reached")
    except ValidationAccessDenied:
        actual["decision"] = "blocked"
        evaluated = True
        passed = not baseline
        evidence.extend((f"scenario:{scenario}", "decision:blocked"))
    except (FileNotFoundError, IsADirectoryError):
        actual["decision"] = "not_found"
        evaluated = True
        passed = not baseline
        evidence.extend((f"scenario:{scenario}", "decision:not_found"))
    except ValidationEntrypointUnavailable:
        actual["decision"] = "entrypoint_unavailable"
        limitations.append("entrypoint_unavailable")
    except Exception as exc:
        actual["decision"] = "entrypoint_error"
        limitations.append(f"entrypoint_error:{type(exc).__name__}")

    return (
        ValidationObservation(
            validation_plan_id=plan.plan_id,
            subject_id=plan.subject_id,
            validation_type="path_traversal",
            scenario=scenario,
            stimulus=(
                "sandbox/outside/sentinel.txt"
                if scenario == "absolute_path"
                else stimulus
            ),
            oracle=(
                "functional_baseline"
                if baseline
                else "path_boundary_invariant"
            ),
            expected=expected,
            actual=actual,
            baseline=baseline,
            oracle_evaluated=evaluated,
            oracle_passed=passed,
            evidence=tuple(evidence),
            limitations=tuple(limitations),
        ),
        tuple(limitations),
    )


def _logical_path(
    candidate: Path,
    sandbox: Path,
    allowed: Path,
) -> str:
    if candidate.is_relative_to(allowed):
        relative = candidate.relative_to(allowed).as_posix()
        return f"allowed/{relative}"
    if candidate.is_relative_to(sandbox):
        return candidate.relative_to(sandbox).as_posix()
    return "outside_fixture_root"


__all__ = [
    "BUILTIN_PATH_ADAPTERS",
    "PathTarget",
    "PathTraversalValidationExecutor",
]
