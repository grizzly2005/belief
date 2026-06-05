"""Generic validation-result models for BELIEF audit evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any


VALIDATION_RESULT_SCHEMA_VERSION = "belief.validation_result.v1"
VALIDATION_OUTCOMES = {
    "bypassed",
    "validated_candidate",
    "inconclusive",
    "enforced",
    "false_positive",
    "informational",
    "unknown",
}


@dataclass(frozen=True)
class ValidationResult:
    """A generic validation signal attached to a finding or audit case.

    The model is deliberately source-agnostic. PDX, humans, or future local
    validators can adapt into this shape without changing BELIEF's core
    Finding or AuditCase models.
    """

    subject_id: str
    subject_kind: str
    source: str
    outcome: str
    confidence: float = 0.5
    tested: bool = False
    human_validated: bool = False
    method: str = ""
    reason: str = ""
    evidence: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    result_id: str = ""
    schema_version: str = VALIDATION_RESULT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "outcome", _normalize_outcome(self.outcome))
        object.__setattr__(self, "confidence", _clamp_float(self.confidence))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence if str(item)))
        if not self.result_id:
            object.__setattr__(self, "result_id", _stable_result_id(self))

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "result_id": self.result_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "source": self.source,
            "outcome": self.outcome,
            "confidence": round(float(self.confidence), 3),
            "tested": bool(self.tested),
            "human_validated": bool(self.human_validated),
            "method": self.method,
            "reason": self.reason,
            "evidence": list(self.evidence),
        }
        if self.metadata:
            data["metadata"] = _json_safe(self.metadata)
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ValidationResult":
        if not isinstance(payload, dict):
            raise ValueError("ValidationResult payload must be a JSON object")
        schema = str(payload.get("schema_version") or VALIDATION_RESULT_SCHEMA_VERSION)
        if schema != VALIDATION_RESULT_SCHEMA_VERSION:
            raise ValueError(f"unsupported ValidationResult schema: {schema!r}")
        return cls(
            result_id=str(payload.get("result_id") or ""),
            subject_id=str(payload.get("subject_id") or ""),
            subject_kind=str(payload.get("subject_kind") or ""),
            source=str(payload.get("source") or ""),
            outcome=str(payload.get("outcome") or "unknown"),
            confidence=_clamp_float(payload.get("confidence"), default=0.5),
            tested=bool(payload.get("tested", False)),
            human_validated=bool(payload.get("human_validated", False)),
            method=str(payload.get("method") or ""),
            reason=str(payload.get("reason") or ""),
            evidence=tuple(str(item) for item in _as_list(payload.get("evidence")) if str(item)),
            metadata=_as_dict(payload.get("metadata")),
            schema_version=schema,
        )


def _normalize_outcome(value: object) -> str:
    text = str(value or "").strip().lower()
    return text if text in VALIDATION_OUTCOMES else "unknown"


def _stable_result_id(result: ValidationResult) -> str:
    payload = {
        "subject_id": result.subject_id,
        "subject_kind": result.subject_kind,
        "source": result.source,
        "outcome": result.outcome,
        "tested": result.tested,
        "human_validated": result.human_validated,
        "method": result.method,
        "reason": result.reason,
        "evidence": list(result.evidence),
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return f"vr_{digest}"


def _clamp_float(value: object, default: float = 0.5) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 0.0), 1.0)


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "") else [value])


__all__ = [
    "VALIDATION_OUTCOMES",
    "VALIDATION_RESULT_SCHEMA_VERSION",
    "ValidationResult",
]
