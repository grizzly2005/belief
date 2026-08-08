"""One conservative decision policy for local validation evidence.

The policy is deliberately independent from the concrete worker and executor
models.  Both layers expose the same small observation surface and therefore
must reach the same conclusion for the same evidence.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any


FUNCTIONAL_BASELINE = "functional_baseline"
PRIMARY_SECURITY = "primary_security"
SECONDARY_SECURITY = "secondary_security"
OPTIONAL = "optional"

ORACLE_ROLES = frozenset(
    {
        FUNCTIONAL_BASELINE,
        PRIMARY_SECURITY,
        SECONDARY_SECURITY,
        OPTIONAL,
    }
)
SECURITY_ORACLE_ROLES = frozenset(
    {
        PRIMARY_SECURITY,
        SECONDARY_SECURITY,
        OPTIONAL,
    }
)
SAFE_OUTCOMES = frozenset({"enforced", "false_positive"})


class EvidencePolicyError(ValueError):
    """Raised when evidence cannot be interpreted without guessing."""


@dataclass(frozen=True)
class EvidenceDecision:
    """Normalized conclusion and the evidence counts supporting it."""

    outcome: str
    baseline_passed: bool | None
    conclusive: bool
    evaluated_primary_count: int
    evaluated_security_count: int
    required_security_count: int
    failed_security_oracles: tuple[str, ...] = ()
    required_unevaluated_oracles: tuple[str, ...] = ()
    optional_unevaluated_oracles: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()


def evaluate_evidence(
    observations: Iterable[Any],
    *,
    completed: bool,
    safe_outcome: str = "enforced",
) -> EvidenceDecision:
    """Apply the shared fail-closed conclusion policy.

    A conclusion requires a completed execution, a complete functional
    baseline, and at least one evaluated primary security oracle.  A proved
    security-oracle failure is a bypass once those gates are met.  Missing
    optional evidence is retained as a limitation but does not turn passing
    required evidence into an abstention.
    """

    if not isinstance(completed, bool):
        raise EvidencePolicyError("completed must be boolean")
    if safe_outcome not in SAFE_OUTCOMES:
        raise EvidencePolicyError("safe_outcome is invalid")

    normalized = tuple(_normalize_observation(item) for item in observations)
    baseline = tuple(
        item for item in normalized if item["role"] == FUNCTIONAL_BASELINE
    )
    security = tuple(
        item for item in normalized if item["role"] in SECURITY_ORACLE_ROLES
    )
    primary = tuple(
        item for item in security if item["role"] == PRIMARY_SECURITY
    )

    baseline_passed = _baseline_verdict(baseline)
    evaluated_primary = tuple(item for item in primary if item["evaluated"])
    evaluated_security = tuple(item for item in security if item["evaluated"])
    failed_security = tuple(
        item for item in evaluated_security if item["passed"] is False
    )
    required_security = tuple(
        item for item in security if item["required"]
    )
    required_unevaluated = tuple(
        item for item in required_security if not item["evaluated"]
    )
    optional_unevaluated = tuple(
        item
        for item in security
        if not item["required"] and not item["evaluated"]
    )

    failed_ids = _identifiers(failed_security)
    required_unevaluated_ids = _identifiers(required_unevaluated)
    optional_unevaluated_ids = _identifiers(optional_unevaluated)
    limitations: list[str] = [
        f"optional_oracle_unevaluated:{identifier}"
        for identifier in optional_unevaluated_ids
    ]

    outcome = "inconclusive"
    if not completed:
        limitations.append("execution_not_completed")
    elif not baseline:
        limitations.append("required_functional_baseline_missing")
    elif baseline_passed is False:
        limitations.append("functional_baseline_failed")
    elif baseline_passed is None:
        limitations.extend(
            f"required_functional_baseline_unevaluated:{identifier}"
            for identifier in _identifiers(
                item for item in baseline if not item["evaluated"]
            )
        )
    elif not evaluated_primary:
        limitations.append("primary_security_oracle_not_evaluated")
    elif failed_security:
        outcome = "bypassed"
    elif required_unevaluated:
        limitations.extend(
            f"required_security_oracle_unevaluated:{identifier}"
            for identifier in required_unevaluated_ids
        )
    else:
        outcome = safe_outcome

    return EvidenceDecision(
        outcome=outcome,
        baseline_passed=baseline_passed,
        conclusive=outcome != "inconclusive",
        evaluated_primary_count=len(evaluated_primary),
        evaluated_security_count=len(evaluated_security),
        required_security_count=len(required_security),
        failed_security_oracles=failed_ids,
        required_unevaluated_oracles=required_unevaluated_ids,
        optional_unevaluated_oracles=optional_unevaluated_ids,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def baseline_verdict(observations: Iterable[Any]) -> bool | None:
    """Return the tri-state verdict for required functional baselines."""

    normalized = tuple(_normalize_observation(item) for item in observations)
    return _baseline_verdict(
        tuple(
            item
            for item in normalized
            if item["role"] == FUNCTIONAL_BASELINE
        )
    )


def infer_legacy_oracle_role(
    *,
    baseline: bool,
    oracle: str,
    scenario: str,
) -> tuple[str, bool]:
    """Migrate a v1/v2 observation without changing its old meaning.

    This inference is only for backward readers.  New writers must supply the
    role and conclusion requirement explicitly.
    """

    if baseline:
        return FUNCTIONAL_BASELINE, True
    if scenario == "symlink_boundary":
        return OPTIONAL, False
    if oracle in {
        "state_invariant",
        "owner_state_invariant",
        "tenant_state_invariant",
    }:
        return SECONDARY_SECURITY, True
    return PRIMARY_SECURITY, True


def _normalize_observation(item: Any) -> dict[str, Any]:
    role = _value(item, "oracle_role")
    required = _value(item, "required_for_conclusion")
    evaluated = _value(item, "oracle_evaluated")
    passed = _value(item, "oracle_passed")
    baseline = _value(item, "baseline")
    oracle = _value(item, "oracle")
    scenario = _value(item, "scenario")

    if role not in ORACLE_ROLES:
        raise EvidencePolicyError("observation oracle_role is invalid")
    if not isinstance(required, bool):
        raise EvidencePolicyError(
            "observation required_for_conclusion must be boolean"
        )
    if not isinstance(evaluated, bool):
        raise EvidencePolicyError(
            "observation oracle_evaluated must be boolean"
        )
    if passed not in {True, False, None}:
        raise EvidencePolicyError("observation oracle_passed is invalid")
    if passed is not None and not evaluated:
        raise EvidencePolicyError(
            "unevaluated observation cannot have a verdict"
        )
    if not isinstance(baseline, bool):
        raise EvidencePolicyError("observation baseline must be boolean")
    if (role == FUNCTIONAL_BASELINE) != baseline:
        raise EvidencePolicyError(
            "observation baseline flag contradicts its oracle role"
        )
    if role == FUNCTIONAL_BASELINE and not required:
        raise EvidencePolicyError(
            "functional baseline must be required for conclusion"
        )
    if not isinstance(oracle, str) or not oracle:
        raise EvidencePolicyError("observation oracle is invalid")
    if not isinstance(scenario, str) or not scenario:
        raise EvidencePolicyError("observation scenario is invalid")
    return {
        "role": role,
        "required": required,
        "evaluated": evaluated,
        "passed": passed,
        "oracle": oracle,
        "scenario": scenario,
    }


def _baseline_verdict(
    baseline: tuple[dict[str, Any], ...],
) -> bool | None:
    if any(
        item["evaluated"] and item["passed"] is False
        for item in baseline
    ):
        return False
    if baseline and all(
        item["evaluated"] and item["passed"] is True
        for item in baseline
    ):
        return True
    return None


def _identifiers(items: Iterable[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(
        dict.fromkeys(
            f"{item['oracle']}:{item['scenario']}"
            for item in items
        )
    )


def _value(item: Any, field_name: str) -> Any:
    if isinstance(item, Mapping):
        if field_name not in item:
            raise EvidencePolicyError(
                f"observation is missing {field_name}"
            )
        return item[field_name]
    if not hasattr(item, field_name):
        raise EvidencePolicyError(
            f"observation is missing {field_name}"
        )
    return getattr(item, field_name)


__all__ = [
    "EvidenceDecision",
    "EvidencePolicyError",
    "FUNCTIONAL_BASELINE",
    "OPTIONAL",
    "ORACLE_ROLES",
    "PRIMARY_SECURITY",
    "SAFE_OUTCOMES",
    "SECONDARY_SECURITY",
    "SECURITY_ORACLE_ROLES",
    "baseline_verdict",
    "evaluate_evidence",
    "infer_legacy_oracle_role",
]
