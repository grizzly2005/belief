"""Versioned contracts for deterministic, local validation execution."""

from __future__ import annotations

import copy
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any

from .evidence_policy import (
    FUNCTIONAL_BASELINE,
    ORACLE_ROLES,
    evaluate_evidence,
)
from .plan_models import canonical_digest, clean_text, json_object, unique_strings


VALIDATION_EXECUTION_CONTEXT_SCHEMA_VERSION = (
    "belief.validation_execution_context.v1"
)
VALIDATION_OBSERVATION_SCHEMA_VERSION = "belief.validation_observation.v2"
VALIDATION_EXECUTION_SUMMARY_SCHEMA_VERSION = (
    "belief.validation_execution_summary.v2"
)
VALIDATION_FIXTURE_BUNDLE_SCHEMA_VERSION = (
    "belief.validation_fixture_bundle.v1"
)

LOCAL_EXECUTION_OUTCOMES = {
    "bypassed",
    "enforced",
    "false_positive",
    "inconclusive",
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

LocalAdapter = Callable[..., Any]


class ValidationContractError(ValueError):
    """Raised when a plan, fixture, registry, or artifact breaks its contract."""


@dataclass(frozen=True)
class ValidationExecutionContext:
    """Explicit binding between one validation plan and one trusted fixture.

    ``adapter_registry`` is intentionally process-local and is never loaded
    from JSON. This permits directly callable Python fixtures while preventing
    import strings or dynamic discovery from crossing the artifact boundary.
    """

    validation_plan_id: str
    case_type: str
    fixture_id: str
    adapter: str
    source_revision: str
    config: dict[str, Any] = field(default_factory=dict)
    expected_plan_digest: str = ""
    adapter_registry: Mapping[str, LocalAdapter] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    schema_version: str = VALIDATION_EXECUTION_CONTEXT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_EXECUTION_CONTEXT_SCHEMA_VERSION:
            raise ValidationContractError(
                "unsupported validation execution context schema"
            )
        normalized = {
            "validation_plan_id": clean_text(self.validation_plan_id),
            "case_type": clean_text(self.case_type),
            "fixture_id": clean_text(self.fixture_id),
            "adapter": clean_text(self.adapter),
            "source_revision": clean_text(self.source_revision),
        }
        missing = [key for key, value in normalized.items() if not value]
        if missing:
            raise ValidationContractError(
                "validation execution context is missing: "
                + ", ".join(missing)
            )
        for key, value in normalized.items():
            object.__setattr__(self, key, value)

        plan_digest = clean_text(self.expected_plan_digest).lower()
        if not _SHA256_RE.fullmatch(plan_digest):
            raise ValidationContractError(
                "expected validation plan digest must be a SHA-256"
            )
        object.__setattr__(self, "expected_plan_digest", plan_digest)
        object.__setattr__(self, "config", json_object(self.config))

        registry = dict(self.adapter_registry)
        if any(
            not isinstance(name, str)
            or name != clean_text(name)
            or not name
            or not callable(adapter)
            for name, adapter in registry.items()
        ):
            raise ValidationContractError(
                "validation adapter registry contains an invalid entry"
            )
        object.__setattr__(
            self,
            "adapter_registry",
            MappingProxyType(registry),
        )

    @property
    def fixture_digest(self) -> str:
        return canonical_digest(self._binding_payload())

    def _binding_payload(self) -> dict[str, Any]:
        payload = {
            "schema_version": self.schema_version,
            "validation_plan_id": self.validation_plan_id,
            "case_type": self.case_type,
            "fixture_id": self.fixture_id,
            "adapter": self.adapter,
            "source_revision": self.source_revision,
            "config": copy.deepcopy(self.config),
        }
        payload["expected_plan_digest"] = self.expected_plan_digest
        return payload

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._binding_payload(),
            "fixture_digest": self.fixture_digest,
        }

    @classmethod
    def for_plan(
        cls,
        plan: Any,
        *,
        fixture_id: str,
        adapter: str,
        source_revision: str,
        config: Mapping[str, Any] | None = None,
        adapter_registry: Mapping[str, LocalAdapter] | None = None,
    ) -> "ValidationExecutionContext":
        """Create an exact context binding for a canonical ValidationPlan."""

        serializer = getattr(plan, "to_dict", None)
        if not callable(serializer):
            raise ValidationContractError(
                "validation context requires a serializable plan"
            )
        plan_payload = serializer()
        if not isinstance(plan_payload, Mapping):
            raise ValidationContractError(
                "validation plan serializer returned an invalid payload"
            )
        return cls(
            validation_plan_id=str(plan_payload.get("plan_id") or ""),
            case_type=str(plan_payload.get("case_type") or ""),
            fixture_id=fixture_id,
            adapter=adapter,
            source_revision=source_revision,
            config=json_object(config),
            expected_plan_digest=canonical_digest(plan_payload),
            adapter_registry=adapter_registry or {},
        )

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
        *,
        adapter_registry: Mapping[str, LocalAdapter] | None = None,
    ) -> "ValidationExecutionContext":
        if not isinstance(payload, Mapping):
            raise ValidationContractError(
                "validation fixture must be a JSON object"
            )
        allowed = {
            "schema_version",
            "validation_plan_id",
            "case_type",
            "fixture_id",
            "adapter",
            "source_revision",
            "config",
            "expected_plan_digest",
            "fixture_digest",
        }
        if set(payload) - allowed:
            raise ValidationContractError(
                "validation fixture contains unsupported fields"
            )
        context = cls(
            validation_plan_id=str(
                payload.get("validation_plan_id") or ""
            ),
            case_type=str(payload.get("case_type") or ""),
            fixture_id=str(payload.get("fixture_id") or ""),
            adapter=str(payload.get("adapter") or ""),
            source_revision=str(payload.get("source_revision") or ""),
            config=json_object(payload.get("config")),
            expected_plan_digest=str(
                payload.get("expected_plan_digest") or ""
            ),
            adapter_registry=adapter_registry or {},
            schema_version=str(
                payload.get("schema_version")
                or VALIDATION_EXECUTION_CONTEXT_SCHEMA_VERSION
            ),
        )
        supplied_digest = clean_text(payload.get("fixture_digest")).lower()
        if supplied_digest != context.fixture_digest:
            raise ValidationContractError(
                "validation fixture digest mismatch"
            )
        if context.to_dict() != dict(payload):
            raise ValidationContractError(
                "validation fixture is not canonical"
            )
        return context


@dataclass(frozen=True)
class ValidationObservation:
    """One reproducible baseline or security-oracle observation."""

    validation_plan_id: str
    subject_id: str
    validation_type: str
    scenario: str
    stimulus: str
    oracle: str
    expected: str
    actual: dict[str, Any]
    baseline: bool
    oracle_role: str
    required_for_conclusion: bool
    oracle_evaluated: bool
    oracle_passed: bool | None
    evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    cost_units: int = 1
    observation_id: str = ""
    schema_version: str = VALIDATION_OBSERVATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_OBSERVATION_SCHEMA_VERSION:
            raise ValidationContractError(
                "unsupported validation observation schema"
            )
        for field_name in (
            "validation_plan_id",
            "subject_id",
            "validation_type",
            "scenario",
            "stimulus",
            "oracle",
            "expected",
        ):
            value = clean_text(getattr(self, field_name))
            if not value:
                raise ValidationContractError(
                    f"validation observation {field_name} is required"
                )
            object.__setattr__(self, field_name, value)
        if (
            self.oracle_passed is not True
            and self.oracle_passed is not False
            and self.oracle_passed is not None
        ):
            raise ValidationContractError(
                "validation observation oracle_passed is invalid"
            )
        if self.oracle_passed is not None and not self.oracle_evaluated:
            raise ValidationContractError(
                "unevaluated validation oracle cannot have a verdict"
            )
        oracle_role = clean_text(self.oracle_role)
        if oracle_role not in ORACLE_ROLES:
            raise ValidationContractError(
                "validation observation oracle_role is invalid"
            )
        object.__setattr__(self, "oracle_role", oracle_role)
        if not isinstance(self.required_for_conclusion, bool):
            raise ValidationContractError(
                "validation observation required_for_conclusion "
                "must be boolean"
            )
        if (oracle_role == FUNCTIONAL_BASELINE) != self.baseline:
            raise ValidationContractError(
                "validation observation baseline contradicts oracle_role"
            )
        if (
            oracle_role == FUNCTIONAL_BASELINE
            and not self.required_for_conclusion
        ):
            raise ValidationContractError(
                "functional baseline must be required for conclusion"
            )
        if (
            not isinstance(self.cost_units, int)
            or isinstance(self.cost_units, bool)
            or self.cost_units < 0
        ):
            raise ValidationContractError(
                "validation observation cost_units is invalid"
            )
        object.__setattr__(self, "actual", json_object(self.actual))
        object.__setattr__(self, "evidence", unique_strings(self.evidence))
        object.__setattr__(
            self,
            "limitations",
            unique_strings(self.limitations),
        )
        expected_id = "vo_" + canonical_digest(
            self._semantic_payload()
        )[:16]
        supplied = clean_text(self.observation_id)
        if supplied and supplied != expected_id:
            raise ValidationContractError(
                "validation observation id does not match its content"
            )
        object.__setattr__(self, "observation_id", expected_id)

    def _semantic_payload(self) -> dict[str, Any]:
        return {
            "validation_plan_id": self.validation_plan_id,
            "subject_id": self.subject_id,
            "validation_type": self.validation_type,
            "scenario": self.scenario,
            "stimulus": self.stimulus,
            "oracle": self.oracle,
            "expected": self.expected,
            "actual": copy.deepcopy(self.actual),
            "baseline": self.baseline,
            "oracle_role": self.oracle_role,
            "required_for_conclusion": self.required_for_conclusion,
            "oracle_evaluated": self.oracle_evaluated,
            "oracle_passed": self.oracle_passed,
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
            "cost_units": self.cost_units,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            **self._semantic_payload(),
        }


@dataclass(frozen=True)
class ValidationExecutionSummary:
    """Deterministic execution evidence for one plan and fixture."""

    validation_plan_id: str
    validation_plan_digest: str
    subject_id: str
    validation_type: str
    source_revision: str
    fixture_id: str
    fixture_digest: str
    adapter: str
    supported: bool
    executed: bool
    outcome: str
    baseline_passed: bool | None
    observations: tuple[ValidationObservation, ...] = ()
    resolved_evidence_gaps: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    protected_regression: bool = False
    summary_id: str = ""
    schema_version: str = VALIDATION_EXECUTION_SUMMARY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_EXECUTION_SUMMARY_SCHEMA_VERSION:
            raise ValidationContractError(
                "unsupported validation execution summary schema"
            )
        for field_name in (
            "validation_plan_id",
            "subject_id",
            "validation_type",
            "source_revision",
            "fixture_id",
            "adapter",
        ):
            value = clean_text(getattr(self, field_name))
            if not value:
                raise ValidationContractError(
                    f"validation summary {field_name} is required"
                )
            object.__setattr__(self, field_name, value)
        for field_name in ("validation_plan_digest", "fixture_digest"):
            value = clean_text(getattr(self, field_name)).lower()
            if not _SHA256_RE.fullmatch(value):
                raise ValidationContractError(
                    f"validation summary {field_name} is invalid"
                )
            object.__setattr__(self, field_name, value)

        outcome = clean_text(self.outcome).lower()
        if outcome not in LOCAL_EXECUTION_OUTCOMES:
            raise ValidationContractError(
                f"unsupported local validation outcome: {outcome!r}"
            )
        object.__setattr__(self, "outcome", outcome)
        if self.baseline_passed not in {True, False, None}:
            raise ValidationContractError(
                "validation summary baseline_passed is invalid"
            )
        observations = tuple(self.observations)
        if any(
            not isinstance(item, ValidationObservation)
            for item in observations
        ):
            raise ValidationContractError(
                "validation summary contains an invalid observation"
            )
        if any(
            item.validation_plan_id != self.validation_plan_id
            or item.subject_id != self.subject_id
            or item.validation_type != self.validation_type
            for item in observations
        ):
            raise ValidationContractError(
                "validation observations do not match their summary"
            )
        object.__setattr__(self, "observations", observations)
        object.__setattr__(
            self,
            "resolved_evidence_gaps",
            unique_strings(self.resolved_evidence_gaps),
        )
        object.__setattr__(
            self,
            "limitations",
            unique_strings(self.limitations),
        )

        safe_outcome = (
            "false_positive"
            if outcome == "false_positive"
            else "enforced"
        )
        decision = evaluate_evidence(
            observations,
            completed=self.executed,
            safe_outcome=safe_outcome,
        )
        if self.baseline_passed != decision.baseline_passed:
            raise ValidationContractError(
                "validation summary baseline does not match observations"
            )
        if outcome == "bypassed" and decision.outcome != "bypassed":
            raise ValidationContractError(
                "a bypass requires a working baseline and failed oracle"
            )
        if (
            outcome in {"enforced", "false_positive"}
            and decision.outcome != outcome
        ):
            raise ValidationContractError(
                "an enforced result requires passing required oracles"
            )
        if outcome == "inconclusive" and decision.outcome != "inconclusive":
            raise ValidationContractError(
                "an inconclusive result contradicts conclusive evidence"
            )
        if not self.executed and outcome != "inconclusive":
            raise ValidationContractError(
                "an unexecuted validation must remain inconclusive"
            )
        if self.protected_regression and outcome != "bypassed":
            raise ValidationContractError(
                "protected regression requires a demonstrated bypass"
            )

        expected_id = "ves_" + canonical_digest(
            self._semantic_payload()
        )[:16]
        supplied = clean_text(self.summary_id)
        if supplied and supplied != expected_id:
            raise ValidationContractError(
                "validation summary id does not match its content"
            )
        object.__setattr__(self, "summary_id", expected_id)

    @property
    def oracle_evaluated_count(self) -> int:
        return sum(item.oracle_evaluated for item in self.observations)

    @property
    def primary_oracle_evaluated_count(self) -> int:
        decision = evaluate_evidence(
            self.observations,
            completed=self.executed,
            safe_outcome=(
                "false_positive"
                if self.outcome == "false_positive"
                else "enforced"
            ),
        )
        return decision.evaluated_primary_count

    @property
    def deterministic_cost_units(self) -> int:
        return sum(item.cost_units for item in self.observations)

    def _semantic_payload(self) -> dict[str, Any]:
        return {
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "subject_id": self.subject_id,
            "validation_type": self.validation_type,
            "source_revision": self.source_revision,
            "fixture_id": self.fixture_id,
            "fixture_digest": self.fixture_digest,
            "adapter": self.adapter,
            "supported": self.supported,
            "executed": self.executed,
            "outcome": self.outcome,
            "baseline_passed": self.baseline_passed,
            "observations": [
                item.to_dict() for item in self.observations
            ],
            "resolved_evidence_gaps": list(
                self.resolved_evidence_gaps
            ),
            "limitations": list(self.limitations),
            "protected_regression": self.protected_regression,
            "oracle_evaluated_count": self.oracle_evaluated_count,
            "primary_oracle_evaluated_count": (
                self.primary_oracle_evaluated_count
            ),
            "deterministic_cost": {
                "unit": "local_operation",
                "value": self.deterministic_cost_units,
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "summary_id": self.summary_id,
            **self._semantic_payload(),
        }


def build_validation_fixture_bundle(
    contexts: Sequence[ValidationExecutionContext],
) -> dict[str, Any]:
    """Build a canonical, offline fixture bundle."""

    ordered = sorted(
        tuple(contexts),
        key=lambda item: (
            item.validation_plan_id,
            item.fixture_id,
        ),
    )
    plan_ids = [item.validation_plan_id for item in ordered]
    if len(plan_ids) != len(set(plan_ids)):
        raise ValidationContractError(
            "validation fixture bundle has duplicate plan bindings"
        )
    payload: dict[str, Any] = {
        "schema_version": VALIDATION_FIXTURE_BUNDLE_SCHEMA_VERSION,
        "fixture_count": len(ordered),
        "boundaries": {
            "local_only": True,
            "network_allowed": False,
            "subprocess_allowed": False,
            "shell_allowed": False,
            "dynamic_import_allowed": False,
            "production_data_allowed": False,
        },
        "fixtures": [item.to_dict() for item in ordered],
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def load_validation_fixture_bundle(
    path: str | Path,
) -> tuple[dict[str, Any], dict[str, ValidationExecutionContext]]:
    """Load and verify a canonical local-fixture bundle."""

    from belief.json_contracts import StrictJSONError, load_json_file

    try:
        payload = load_json_file(path)
    except StrictJSONError as exc:
        raise ValidationContractError(
            f"invalid validation fixture bundle: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise ValidationContractError(
            "validation fixture bundle must be a JSON object"
        )
    if payload.get("schema_version") != (
        VALIDATION_FIXTURE_BUNDLE_SCHEMA_VERSION
    ):
        raise ValidationContractError(
            "unsupported validation fixture bundle schema"
        )
    unsigned = dict(payload)
    expected = clean_text(unsigned.pop("deterministic_digest", "")).lower()
    if expected != canonical_digest(unsigned):
        raise ValidationContractError(
            "validation fixture bundle deterministic digest mismatch"
        )
    expected_boundaries = {
        "local_only": True,
        "network_allowed": False,
        "subprocess_allowed": False,
        "shell_allowed": False,
        "dynamic_import_allowed": False,
        "production_data_allowed": False,
    }
    if payload.get("boundaries") != expected_boundaries:
        raise ValidationContractError(
            "validation fixture bundle boundaries are invalid"
        )
    rows = payload.get("fixtures")
    if not isinstance(rows, list):
        raise ValidationContractError(
            "validation fixture bundle fixtures must be a list"
        )
    contexts = tuple(
        ValidationExecutionContext.from_dict(row)
        for row in rows
    )
    if int(payload.get("fixture_count", -1)) != len(contexts):
        raise ValidationContractError(
            "validation fixture bundle count mismatch"
        )
    by_plan = {
        context.validation_plan_id: context
        for context in contexts
    }
    if len(by_plan) != len(contexts):
        raise ValidationContractError(
            "validation fixture bundle has duplicate plan bindings"
        )
    if build_validation_fixture_bundle(contexts) != payload:
        raise ValidationContractError(
            "validation fixture bundle is not canonical"
        )
    return payload, by_plan


def write_validation_fixture_bundle(
    output: str | Path,
    contexts: Sequence[ValidationExecutionContext],
) -> dict[str, Any]:
    """Create a canonical fixture bundle without replacing an artifact."""

    from belief.json_contracts import strict_json_dumps

    payload = build_validation_fixture_bundle(contexts)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(
                strict_json_dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValidationContractError(
            f"refusing to overwrite validation fixture bundle: {destination}"
        ) from exc
    return payload


__all__ = [
    "LOCAL_EXECUTION_OUTCOMES",
    "VALIDATION_EXECUTION_CONTEXT_SCHEMA_VERSION",
    "VALIDATION_EXECUTION_SUMMARY_SCHEMA_VERSION",
    "VALIDATION_FIXTURE_BUNDLE_SCHEMA_VERSION",
    "VALIDATION_OBSERVATION_SCHEMA_VERSION",
    "LocalAdapter",
    "ValidationContractError",
    "ValidationExecutionContext",
    "ValidationExecutionSummary",
    "ValidationObservation",
    "build_validation_fixture_bundle",
    "load_validation_fixture_bundle",
    "write_validation_fixture_bundle",
]
