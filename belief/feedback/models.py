"""Minimal human feedback model for BELIEF."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


FEEDBACK_SCHEMA_VERSION = "belief.feedback.v1"


@dataclass(frozen=True)
class FeedbackEvent:
    case_id: str
    verdict: str
    reason: str
    source: str = "human"
    created_at: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    event_id: str = ""
    schema_version: str = FEEDBACK_SCHEMA_VERSION

    def __post_init__(self) -> None:
        created_at = self.created_at or datetime.now(timezone.utc).isoformat(timespec="seconds")
        object.__setattr__(self, "created_at", created_at)
        object.__setattr__(self, "verdict", str(self.verdict or "unknown").strip().lower())
        if not self.event_id:
            object.__setattr__(self, "event_id", _stable_event_id(self))

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "case_id": self.case_id,
            "verdict": self.verdict,
            "reason": self.reason,
            "source": self.source,
            "created_at": self.created_at,
        }
        if self.metadata:
            data["metadata"] = _json_safe(self.metadata)
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "FeedbackEvent":
        if not isinstance(payload, dict):
            raise ValueError("FeedbackEvent payload must be a JSON object")
        schema = str(payload.get("schema_version") or FEEDBACK_SCHEMA_VERSION)
        if schema != FEEDBACK_SCHEMA_VERSION:
            raise ValueError(f"unsupported FeedbackEvent schema: {schema!r}")
        return cls(
            event_id=str(payload.get("event_id") or ""),
            case_id=str(payload.get("case_id") or ""),
            verdict=str(payload.get("verdict") or "unknown"),
            reason=str(payload.get("reason") or ""),
            source=str(payload.get("source") or "human"),
            created_at=str(payload.get("created_at") or ""),
            metadata=payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {},
            schema_version=schema,
        )


def _stable_event_id(event: FeedbackEvent) -> str:
    payload = {
        "case_id": event.case_id,
        "verdict": event.verdict,
        "reason": event.reason,
        "source": event.source,
        "created_at": event.created_at,
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return f"fb_{digest}"


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


__all__ = ["FEEDBACK_SCHEMA_VERSION", "FeedbackEvent"]
