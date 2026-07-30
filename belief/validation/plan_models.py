"""Versioned data models used by evidence-guided validation planning."""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .models import VALIDATION_OUTCOMES, VALIDATION_RESULT_SCHEMA_VERSION

VALIDATION_PLAN_V1_SCHEMA_VERSION = "belief.validation_plan.v1"
VALIDATION_PLAN_SCHEMA_VERSION = "belief.validation_plan.v2"
VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION = "belief.validation_plan_bundle.v1"
VALIDATION_REACHABILITY_SCHEMA_VERSION = "belief.validation_reachability.v1"

VALIDATION_STRATEGIES = {
    "argument_boundary_differential",
    "contextual_output_encoding",
    "defensive_regression",
    "manual_evidence_collection",
    "mocked_network_policy_differential",
    "property_guided_path_boundary",
    "query_parameterization_differential",
    "safe_deserialization_policy",
    "secret_provenance_verification",
    "stateful_authorization_differential",
}
VALIDATION_SUBJECT_KINDS = {
    "audit_case",
    "validation_contract_seed",
}


@dataclass(frozen=True)
class ValidationStimulus:
    """A benign baseline or counterfactual input family."""

    kind: str
    description: str
    value_hint: str = ""
    transformations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", clean_text(self.kind) or "manual")
        object.__setattr__(self, "description", clean_text(self.description))
        object.__setattr__(self, "value_hint", clean_text(self.value_hint))
        object.__setattr__(
            self,
            "transformations",
            unique_strings(self.transformations),
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "description": self.description,
        }
        if self.value_hint:
            payload["value_hint"] = self.value_hint
        if self.transformations:
            payload["transformations"] = list(self.transformations)
        return payload

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationStimulus":
        if not isinstance(payload, Mapping):
            raise ValueError("validation stimulus must be a JSON object")
        return cls(
            kind=str(payload.get("kind") or "manual"),
            description=str(payload.get("description") or ""),
            value_hint=str(payload.get("value_hint") or ""),
            transformations=unique_strings(payload.get("transformations")),
        )


@dataclass(frozen=True)
class ValidationOracle:
    """A checkable invariant separating safe behavior from a bypass."""

    kind: str
    expected: str
    failure_signal: str
    evidence_to_capture: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", clean_text(self.kind) or "manual")
        object.__setattr__(self, "expected", clean_text(self.expected))
        object.__setattr__(
            self,
            "failure_signal",
            clean_text(self.failure_signal),
        )
        object.__setattr__(
            self,
            "evidence_to_capture",
            unique_strings(self.evidence_to_capture),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "expected": self.expected,
            "failure_signal": self.failure_signal,
            "evidence_to_capture": list(self.evidence_to_capture),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationOracle":
        if not isinstance(payload, Mapping):
            raise ValueError("validation oracle must be a JSON object")
        return cls(
            kind=str(payload.get("kind") or "manual"),
            expected=str(payload.get("expected") or ""),
            failure_signal=str(payload.get("failure_signal") or ""),
            evidence_to_capture=unique_strings(
                payload.get("evidence_to_capture")
            ),
        )


@dataclass(frozen=True)
class ValidationPlan:
    """A safe, deterministic plan for resolving one BELIEF audit case."""

    subject_id: str
    case_type: str
    case_status: str
    strategy: str
    objective: str
    subject_kind: str = "audit_case"
    priority: str = "medium"
    target: dict[str, Any] = field(default_factory=dict)
    evidence_gaps: tuple[str, ...] = ()
    prerequisites: tuple[str, ...] = ()
    stimuli: tuple[ValidationStimulus, ...] = ()
    oracles: tuple[ValidationOracle, ...] = ()
    reachability_hints: dict[str, Any] = field(default_factory=dict)
    stop_conditions: tuple[str, ...] = ()
    safety: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    plan_id: str = ""
    schema_version: str = VALIDATION_PLAN_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_PLAN_SCHEMA_VERSION:
            raise ValueError(
                f"unsupported ValidationPlan schema: {self.schema_version!r}"
            )
        subject_id = clean_text(self.subject_id)
        strategy = clean_text(self.strategy)
        if not subject_id:
            raise ValueError("ValidationPlan subject_id is required")
        if strategy not in VALIDATION_STRATEGIES:
            raise ValueError(f"unsupported validation strategy: {strategy!r}")

        object.__setattr__(self, "subject_id", subject_id)
        subject_kind = clean_text(self.subject_kind)
        if subject_kind not in VALIDATION_SUBJECT_KINDS:
            raise ValueError(
                f"unsupported ValidationPlan subject kind: {subject_kind!r}"
            )
        object.__setattr__(self, "subject_kind", subject_kind)
        object.__setattr__(
            self,
            "case_type",
            clean_text(self.case_type) or "unknown",
        )
        object.__setattr__(
            self,
            "case_status",
            clean_text(self.case_status) or "unknown",
        )
        object.__setattr__(self, "strategy", strategy)
        object.__setattr__(self, "objective", clean_text(self.objective))
        object.__setattr__(self, "priority", normalize_priority(self.priority))
        object.__setattr__(self, "target", json_object(self.target))
        object.__setattr__(
            self,
            "evidence_gaps",
            unique_strings(self.evidence_gaps),
        )
        object.__setattr__(
            self,
            "prerequisites",
            unique_strings(self.prerequisites),
        )
        object.__setattr__(self, "stimuli", tuple(self.stimuli))
        object.__setattr__(self, "oracles", tuple(self.oracles))
        object.__setattr__(
            self,
            "reachability_hints",
            json_object(self.reachability_hints),
        )
        object.__setattr__(
            self,
            "stop_conditions",
            unique_strings(self.stop_conditions),
        )
        object.__setattr__(self, "safety", json_object(self.safety))
        object.__setattr__(self, "metadata", json_object(self.metadata))
        expected = stable_plan_id(self)
        supplied = clean_text(self.plan_id)
        if supplied and supplied != expected:
            raise ValueError("ValidationPlan plan_id does not match its content")
        object.__setattr__(self, "plan_id", expected)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "case_type": self.case_type,
            "case_status": self.case_status,
            "strategy": self.strategy,
            "objective": self.objective,
            "priority": self.priority,
            "target": copy.deepcopy(self.target),
            "evidence_gaps": list(self.evidence_gaps),
            "prerequisites": list(self.prerequisites),
            "stimuli": [item.to_dict() for item in self.stimuli],
            "oracles": [item.to_dict() for item in self.oracles],
            "reachability_hints": copy.deepcopy(self.reachability_hints),
            "stop_conditions": list(self.stop_conditions),
            "safety": copy.deepcopy(self.safety),
            "result_contract": {
                "schema_version": VALIDATION_RESULT_SCHEMA_VERSION,
                "subject_id": self.subject_id,
                "subject_kind": self.subject_kind,
                "required_metadata": {"validation_plan_id": self.plan_id},
                "allowed_outcomes": sorted(VALIDATION_OUTCOMES),
            },
            "metadata": copy.deepcopy(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationPlan":
        if not isinstance(payload, Mapping):
            raise ValueError("ValidationPlan payload must be a JSON object")
        source_schema = str(
            payload.get("schema_version")
            or VALIDATION_PLAN_V1_SCHEMA_VERSION
        )
        if source_schema not in {
            VALIDATION_PLAN_V1_SCHEMA_VERSION,
            VALIDATION_PLAN_SCHEMA_VERSION,
        }:
            raise ValueError(
                f"unsupported ValidationPlan schema: {source_schema!r}"
            )
        subject_kind = str(
            payload.get("subject_kind") or "audit_case"
        )
        if (
            source_schema == VALIDATION_PLAN_V1_SCHEMA_VERSION
            and subject_kind != "audit_case"
        ):
            raise ValueError(
                "v1 ValidationPlan subject kind must be audit_case"
            )
        return cls(
            plan_id=str(payload.get("plan_id") or ""),
            subject_id=str(payload.get("subject_id") or ""),
            case_type=str(payload.get("case_type") or "unknown"),
            case_status=str(payload.get("case_status") or "unknown"),
            strategy=str(
                payload.get("strategy") or "manual_evidence_collection"
            ),
            objective=str(payload.get("objective") or ""),
            subject_kind=subject_kind,
            priority=str(payload.get("priority") or "medium"),
            target=json_object(payload.get("target")),
            evidence_gaps=unique_strings(payload.get("evidence_gaps")),
            prerequisites=unique_strings(payload.get("prerequisites")),
            stimuli=tuple(
                ValidationStimulus.from_dict(item)
                for item in object_list(payload.get("stimuli"))
            ),
            oracles=tuple(
                ValidationOracle.from_dict(item)
                for item in object_list(payload.get("oracles"))
            ),
            reachability_hints=json_object(
                payload.get("reachability_hints")
            ),
            stop_conditions=unique_strings(payload.get("stop_conditions")),
            safety=json_object(payload.get("safety")),
            metadata=json_object(payload.get("metadata")),
            schema_version=VALIDATION_PLAN_SCHEMA_VERSION,
        )


def stable_plan_id(plan: ValidationPlan) -> str:
    payload = {
        "subject_id": plan.subject_id,
        "case_type": plan.case_type,
        "case_status": plan.case_status,
        "strategy": plan.strategy,
        "objective": plan.objective,
        "priority": plan.priority,
        "target": plan.target,
        "evidence_gaps": list(plan.evidence_gaps),
        "prerequisites": list(plan.prerequisites),
        "stimuli": [item.to_dict() for item in plan.stimuli],
        "oracles": [item.to_dict() for item in plan.oracles],
        "reachability_hints": plan.reachability_hints,
        "stop_conditions": list(plan.stop_conditions),
        "safety": plan.safety,
    }
    return "vp_" + canonical_digest(payload)[:16]


def canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def clean_text(value: Any) -> str:
    return " ".join(str(value or "").strip().split())


def normalize_priority(value: Any) -> str:
    normalized = clean_text(value).lower()
    return normalized if normalized in {
        "critical",
        "high",
        "medium",
        "low",
        "info",
    } else "medium"


def unique_strings(value: Any) -> tuple[str, ...]:
    if value in (None, ""):
        values: Sequence[Any] = ()
    elif isinstance(value, (str, bytes)):
        values = (value,)
    elif isinstance(value, Sequence):
        values = value
    elif isinstance(value, set):
        values = sorted(value, key=str)
    else:
        values = (value,)
    result: list[str] = []
    for item in values:
        text = clean_text(item)
        if text and text not in result:
            result.append(text)
    return tuple(result)


def json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    return json.loads(json.dumps(dict(value), sort_keys=True, default=str))


def object_list(value: Any) -> list[Mapping[str, Any]]:
    if value in (None, ""):
        return []
    if not isinstance(value, list) or not all(
        isinstance(item, Mapping) for item in value
    ):
        raise ValueError("expected a list of JSON objects")
    return value


__all__ = [
    "VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION",
    "VALIDATION_PLAN_SCHEMA_VERSION",
    "VALIDATION_PLAN_V1_SCHEMA_VERSION",
    "VALIDATION_REACHABILITY_SCHEMA_VERSION",
    "VALIDATION_STRATEGIES",
    "VALIDATION_SUBJECT_KINDS",
    "ValidationOracle",
    "ValidationPlan",
    "ValidationStimulus",
]
