"""Stable offline reasoning models for BELIEF audit cases."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Literal


REASONING_SCHEMA_VERSION = "belief.reasoning.v1"

ReasoningRecommendation = Literal[
    "keep",
    "lower_confidence",
    "needs_manual_validation",
    "likely_false_positive",
    "protected_by_guard",
    "request_more_evidence",
]

REASONING_RECOMMENDATIONS = {
    "keep",
    "lower_confidence",
    "needs_manual_validation",
    "likely_false_positive",
    "protected_by_guard",
    "request_more_evidence",
}


@dataclass(frozen=True)
class ReasoningRequest:
    case_id: str
    title: str = ""
    case_type: str = ""
    severity: str = ""
    confidence: float = 0.0
    evidence: tuple[str, ...] = ()
    positive_factors: tuple[str, ...] = ()
    negative_factors: tuple[str, ...] = ()
    missing_evidence: tuple[str, ...] = ()
    validation_steps: tuple[str, ...] = ()
    validation_results: tuple[dict[str, Any], ...] = ()
    feedback_events: tuple[dict[str, Any], ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = REASONING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _clamp_float(self.confidence, default=0.0))
        for name in (
            "evidence",
            "positive_factors",
            "negative_factors",
            "missing_evidence",
            "validation_steps",
        ):
            object.__setattr__(self, name, tuple(str(item) for item in getattr(self, name) if str(item)))
        object.__setattr__(self, "validation_results", tuple(_dicts(self.validation_results)))
        object.__setattr__(self, "feedback_events", tuple(_dicts(self.feedback_events)))
        object.__setattr__(self, "metadata", _json_safe_dict(self.metadata))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "title": self.title,
            "case_type": self.case_type,
            "severity": self.severity,
            "confidence": round(float(self.confidence), 3),
            "evidence": list(self.evidence),
            "positive_factors": list(self.positive_factors),
            "negative_factors": list(self.negative_factors),
            "missing_evidence": list(self.missing_evidence),
            "validation_steps": list(self.validation_steps),
            "validation_results": [_json_safe_dict(item) for item in self.validation_results],
            "feedback_events": [_json_safe_dict(item) for item in self.feedback_events],
            "metadata": _json_safe_dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReasoningRequest":
        if not isinstance(payload, dict):
            raise ValueError("ReasoningRequest payload must be a JSON object")
        schema = str(payload.get("schema_version") or REASONING_SCHEMA_VERSION)
        if schema != REASONING_SCHEMA_VERSION:
            raise ValueError(f"unsupported ReasoningRequest schema: {schema!r}")
        return cls(
            schema_version=schema,
            case_id=str(payload.get("case_id") or ""),
            title=str(payload.get("title") or ""),
            case_type=str(payload.get("case_type") or ""),
            severity=str(payload.get("severity") or ""),
            confidence=_clamp_float(payload.get("confidence"), default=0.0),
            evidence=tuple(_strings(payload.get("evidence"))),
            positive_factors=tuple(_strings(payload.get("positive_factors"))),
            negative_factors=tuple(_strings(payload.get("negative_factors"))),
            missing_evidence=tuple(_strings(payload.get("missing_evidence"))),
            validation_steps=tuple(_strings(payload.get("validation_steps"))),
            validation_results=tuple(_dicts(payload.get("validation_results"))),
            feedback_events=tuple(_dicts(payload.get("feedback_events"))),
            metadata=_as_dict(payload.get("metadata")),
        )


@dataclass(frozen=True)
class ReasoningResponse:
    case_id: str
    recommendation: ReasoningRecommendation
    rationale_summary: str
    suggested_missing_evidence: tuple[str, ...] = ()
    suggested_validation_steps: tuple[str, ...] = ()
    confidence: float = 0.0
    source_engine: str = "offline"
    safety_notes: tuple[str, ...] = ()
    schema_version: str = REASONING_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.recommendation not in REASONING_RECOMMENDATIONS:
            raise ValueError(f"unsupported reasoning recommendation: {self.recommendation!r}")
        object.__setattr__(self, "confidence", _clamp_float(self.confidence, default=0.0))
        object.__setattr__(
            self,
            "suggested_missing_evidence",
            tuple(str(item) for item in self.suggested_missing_evidence if str(item)),
        )
        object.__setattr__(
            self,
            "suggested_validation_steps",
            tuple(str(item) for item in self.suggested_validation_steps if str(item)),
        )
        object.__setattr__(self, "safety_notes", tuple(str(item) for item in self.safety_notes if str(item)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "recommendation": self.recommendation,
            "rationale_summary": self.rationale_summary,
            "suggested_missing_evidence": list(self.suggested_missing_evidence),
            "suggested_validation_steps": list(self.suggested_validation_steps),
            "confidence": round(float(self.confidence), 3),
            "source_engine": self.source_engine,
            "safety_notes": list(self.safety_notes),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ReasoningResponse":
        if not isinstance(payload, dict):
            raise ValueError("ReasoningResponse payload must be a JSON object")
        schema = str(payload.get("schema_version") or REASONING_SCHEMA_VERSION)
        if schema != REASONING_SCHEMA_VERSION:
            raise ValueError(f"unsupported ReasoningResponse schema: {schema!r}")
        return cls(
            schema_version=schema,
            case_id=str(payload.get("case_id") or ""),
            recommendation=str(payload.get("recommendation") or "request_more_evidence"),  # type: ignore[arg-type]
            rationale_summary=str(payload.get("rationale_summary") or ""),
            suggested_missing_evidence=tuple(_strings(payload.get("suggested_missing_evidence"))),
            suggested_validation_steps=tuple(_strings(payload.get("suggested_validation_steps"))),
            confidence=_clamp_float(payload.get("confidence"), default=0.0),
            source_engine=str(payload.get("source_engine") or "offline"),
            safety_notes=tuple(_strings(payload.get("safety_notes"))),
        )


def _strings(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if str(item)]
    if value in (None, ""):
        return []
    return [str(value)]


def _dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)):
        return []
    return [_json_safe_dict(item) for item in value if isinstance(item, dict)]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _json_safe_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return {"value": str(value)}


def _clamp_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 0.0), 1.0)


__all__ = [
    "REASONING_RECOMMENDATIONS",
    "REASONING_SCHEMA_VERSION",
    "ReasoningRecommendation",
    "ReasoningRequest",
    "ReasoningResponse",
]
