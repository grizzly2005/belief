"""Validation for BELIEF scope policy v1."""

from __future__ import annotations

from .models import SCOPE_SCHEMA_VERSION, ScopePolicy


def validate_scope(scope: ScopePolicy) -> list[str]:
    issues: list[str] = []
    if scope.schema_version != SCOPE_SCHEMA_VERSION:
        issues.append(f"unsupported schema_version: {scope.schema_version}")
    if not scope.include:
        issues.append("include must contain at least one target")
    if scope.rules.max_requests_per_second < 0:
        issues.append("max_requests_per_second must be non-negative")
    if scope.rules.timeout_seconds <= 0:
        issues.append("timeout_seconds must be positive")
    for key in ("cookies", "authorization", "tokens", "secrets"):
        if scope.redaction.get(key) is not True:
            issues.append(f"redaction.{key} must default to true for safe orchestration")
    if issues:
        raise ValueError("; ".join(issues))
    return issues


__all__ = ["validate_scope"]
