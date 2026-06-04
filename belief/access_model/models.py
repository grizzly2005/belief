from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


@dataclass
class Actor:
    name: str
    role: str | None = None
    source: str | None = None


@dataclass
class ProtectedObject:
    type_name: str
    id_name: str | None = None
    owner_field: str | None = None
    tenant_field: str | None = None


@dataclass
class ObjectAction:
    name: str
    mutates_state: bool
    reads_sensitive_data: bool = False


@dataclass
class AuthorizationEvidence:
    kind: str
    expression: str
    strength: Literal["none", "weak", "medium", "strong"]
    file: str | None = None
    line: int | None = None


@dataclass
class AccessHypothesis:
    title: str
    actor: Actor | None
    object: ProtectedObject | None
    action: ObjectAction | None
    route: str | None
    missing_guards: list[str]
    detected_guards: list[AuthorizationEvidence] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "medium"

    def to_dict(self) -> dict:
        return {
            "title": self.title,
            "actor": self.actor.__dict__ if self.actor else None,
            "object": self.object.__dict__ if self.object else None,
            "action": self.action.__dict__ if self.action else None,
            "route": self.route,
            "missing_guards": list(self.missing_guards),
            "detected_guards": [guard.__dict__ for guard in self.detected_guards],
            "validation_steps": list(self.validation_steps),
            "confidence": self.confidence,
        }


__all__ = [
    "AccessHypothesis",
    "Actor",
    "AuthorizationEvidence",
    "ObjectAction",
    "ProtectedObject",
]
