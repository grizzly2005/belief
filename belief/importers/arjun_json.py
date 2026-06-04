"""Passive Arjun JSON importer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.tools.schemas import AccessObservation, NormalizedToolResult


def import_arjun_json(path: str | Path) -> NormalizedToolResult:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    observations = arjun_payload_to_observations(payload)
    return NormalizedToolResult(tool_id="arjun", access_observations=observations, raw={"payload": payload})


def arjun_payload_to_observations(payload: Any) -> list[AccessObservation]:
    observations: list[AccessObservation] = []
    items = payload.items() if isinstance(payload, dict) else []
    for url, value in items:
        params = _params(value)
        for param in params:
            observations.append(AccessObservation(
                source_tool="arjun",
                actor=None,
                role=None,
                method=None,
                path=str(url),
                object_type=_object_type(param),
                object_id_source=str(param),
                action=None,
                expected_guard=_expected_guard(param),
                missing_guards=[],
                mutation=False,
                confidence="medium",
                evidence=[f"discovered parameter: {param}"],
            ))
    return sorted(observations, key=lambda item: (item.path or "", item.object_id_source or ""))


def _params(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, dict):
        raw = value.get("params") or value.get("parameters") or value.get("result") or []
        if isinstance(raw, dict):
            return [str(k) for k in raw]
        if isinstance(raw, list):
            return [str(item) for item in raw]
    return []


def _object_type(param: str) -> str | None:
    text = param.lower()
    for name in ("user", "account", "tenant", "org", "organization", "invoice", "order", "project"):
        if name in text:
            return name
    return None


def _expected_guard(param: str) -> str | None:
    text = param.lower()
    if text.endswith("_id") or text in {"id", "user", "account"}:
        return "owner_or_tenant_scope"
    if text in {"admin", "is_admin", "role", "permission", "scope"}:
        return "authorization_or_role_check"
    return None


__all__ = ["arjun_payload_to_observations", "import_arjun_json"]
