"""Policy loading and decisions for BELIEF scope v1."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .matchers import is_url, match_scope_pattern
from .models import SCOPE_SCHEMA_VERSION, ScopeDecision, ScopePolicy
from .validation import validate_scope


def load_scope(path: str | Path) -> ScopePolicy:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("scope file must contain a JSON object")
    scope = ScopePolicy.from_dict(payload)
    validate_scope(scope)
    return scope


def is_in_scope(scope: ScopePolicy, target: str) -> bool:
    if is_excluded(scope, target):
        return False
    return any(match_scope_pattern(pattern, target) for pattern in scope.include)


def is_excluded(scope: ScopePolicy, target: str) -> bool:
    return any(match_scope_pattern(pattern, target) for pattern in scope.exclude)


def allow_tool(scope: ScopePolicy | None, tool_capability: Any, target: str = "") -> ScopeDecision:
    tool_id = str(_get(tool_capability, "tool_id", "unknown"))
    requires_network = bool(_get(tool_capability, "requires_network", False))
    requires_dynamic = bool(_get(tool_capability, "requires_dynamic", False))
    requires_scope = bool(_get(tool_capability, "requires_scope", False))
    capabilities = set(str(item) for item in (_get(tool_capability, "capabilities", []) or []))

    if scope is None:
        if requires_network or requires_dynamic or requires_scope or (target and is_url(target)):
            return ScopeDecision(False, target, tool_id, "scope file required for network or dynamic target")
        return ScopeDecision(True, target, tool_id, "local static tool allowed without scope")

    matched_exclude = next((pattern for pattern in scope.exclude if match_scope_pattern(pattern, target)), None)
    if target and matched_exclude:
        return ScopeDecision(False, target, tool_id, "target is explicitly excluded", matched_exclude=matched_exclude)

    matched_include = next((pattern for pattern in scope.include if match_scope_pattern(pattern, target)), None)
    if target and not matched_include:
        return ScopeDecision(False, target, tool_id, "target is not included in scope")

    if requires_network and not scope.rules.allow_network:
        return ScopeDecision(False, target, tool_id, "network tools denied by scope", matched_include=matched_include)
    if requires_dynamic and not scope.rules.allow_dynamic:
        return ScopeDecision(False, target, tool_id, "dynamic tools denied by scope", matched_include=matched_include)
    if "active_scan" in capabilities and not scope.rules.allow_active_scan:
        return ScopeDecision(False, target, tool_id, "active scanning denied by scope", matched_include=matched_include)
    if "fuzzing" in capabilities and not scope.rules.allow_fuzzing:
        return ScopeDecision(False, target, tool_id, "fuzzing denied by scope", matched_include=matched_include)

    return ScopeDecision(True, target, tool_id, "allowed by scope", matched_include=matched_include)


def explain_scope_decision(scope: ScopePolicy | None, target: str, tool: Any = None) -> ScopeDecision:
    if tool is not None:
        return allow_tool(scope, tool, target)
    if scope is None:
        return ScopeDecision(not is_url(target), target, None, "scope absent")
    if is_excluded(scope, target):
        matched = next((pattern for pattern in scope.exclude if match_scope_pattern(pattern, target)), None)
        return ScopeDecision(False, target, None, "target is explicitly excluded", matched_exclude=matched)
    matched = next((pattern for pattern in scope.include if match_scope_pattern(pattern, target)), None)
    return ScopeDecision(bool(matched), target, None, "target included" if matched else "target not included", matched_include=matched)


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


__all__ = ["allow_tool", "explain_scope_decision", "is_excluded", "is_in_scope", "load_scope"]
