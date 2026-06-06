"""Data models for BELIEF scope policy v1."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


SCOPE_SCHEMA_VERSION = "belief.scope.v1"


@dataclass(frozen=True)
class ScopeRuleSet:
    allow_network: bool = False
    allow_dynamic: bool = False
    allow_active_scan: bool = False
    allow_fuzzing: bool = False
    allow_auth_tests: bool = False
    max_requests_per_second: int = 0
    timeout_seconds: int = 180

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "ScopeRuleSet":
        raw = raw or {}
        return cls(
            allow_network=bool(raw.get("allow_network", False)),
            allow_dynamic=bool(raw.get("allow_dynamic", False)),
            allow_active_scan=bool(raw.get("allow_active_scan", False)),
            allow_fuzzing=bool(raw.get("allow_fuzzing", False)),
            allow_auth_tests=bool(raw.get("allow_auth_tests", False)),
            max_requests_per_second=int(raw.get("max_requests_per_second", 0) or 0),
            timeout_seconds=int(raw.get("timeout_seconds", 180) or 180),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "allow_network": self.allow_network,
            "allow_dynamic": self.allow_dynamic,
            "allow_active_scan": self.allow_active_scan,
            "allow_fuzzing": self.allow_fuzzing,
            "allow_auth_tests": self.allow_auth_tests,
            "max_requests_per_second": self.max_requests_per_second,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class ScopePolicy:
    schema_version: str = SCOPE_SCHEMA_VERSION
    name: str = "local-safe"
    mode: str = "local-safe"
    include: tuple[str, ...] = field(default_factory=tuple)
    exclude: tuple[str, ...] = field(default_factory=tuple)
    rules: ScopeRuleSet = field(default_factory=ScopeRuleSet)
    redaction: dict[str, bool] = field(default_factory=lambda: {
        "cookies": True,
        "authorization": True,
        "tokens": True,
        "secrets": True,
    })

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ScopePolicy":
        return cls(
            schema_version=str(raw.get("schema_version") or SCOPE_SCHEMA_VERSION),
            name=str(raw.get("name") or "local-safe"),
            mode=str(raw.get("mode") or "local-safe"),
            include=tuple(str(item) for item in _list(raw.get("include"))),
            exclude=tuple(str(item) for item in _list(raw.get("exclude"))),
            rules=ScopeRuleSet.from_dict(raw.get("rules") if isinstance(raw.get("rules"), dict) else {}),
            redaction=_redaction(raw.get("redaction")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "mode": self.mode,
            "include": list(self.include),
            "exclude": list(self.exclude),
            "rules": self.rules.to_dict(),
            "redaction": dict(sorted(self.redaction.items())),
        }


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    target: str
    tool_id: str | None = None
    reason: str = ""
    matched_include: str | None = None
    matched_exclude: str | None = None
    safety_notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "target": self.target,
            "tool_id": self.tool_id,
            "reason": self.reason,
            "matched_include": self.matched_include,
            "matched_exclude": self.matched_exclude,
            "safety_notes": list(self.safety_notes),
        }


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _redaction(value: Any) -> dict[str, bool]:
    defaults = {
        "cookies": True,
        "authorization": True,
        "tokens": True,
        "secrets": True,
    }
    if isinstance(value, dict):
        for key in defaults:
            defaults[key] = bool(value.get(key, defaults[key]))
    return defaults


__all__ = ["SCOPE_SCHEMA_VERSION", "ScopeDecision", "ScopePolicy", "ScopeRuleSet"]
