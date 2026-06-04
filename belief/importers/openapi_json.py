"""Passive OpenAPI JSON importer for route/access observations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.tools.schemas import AccessObservation


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


def import_openapi_json(path: str | Path) -> list[AccessObservation]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return openapi_payload_to_access_observations(payload)


def openapi_payload_to_access_observations(payload: dict[str, Any]) -> list[AccessObservation]:
    observations: list[AccessObservation] = []
    paths = payload.get("paths") if isinstance(payload, dict) else {}
    for route, methods in sorted((paths or {}).items()):
        if not isinstance(methods, dict):
            continue
        for method, operation in sorted(methods.items()):
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            params = [
                str(param.get("name"))
                for param in operation.get("parameters", [])
                if isinstance(param, dict) and param.get("name")
            ]
            object_id = next((param for param in params if param.lower().endswith("_id") or param.lower() == "id"), None)
            observations.append(AccessObservation(
                source_tool="openapi",
                actor=None,
                role=None,
                method=method.upper(),
                path=str(route),
                object_type=_object_type(str(route), object_id),
                object_id_source=object_id,
                action=_action(method, operation),
                expected_guard="owner_or_tenant_scope" if object_id else None,
                mutation=method.lower() in {"post", "put", "patch", "delete"},
                response_exposes_object=method.lower() == "get",
                confidence="medium",
                evidence=_evidence(operation, params),
            ))
    return observations


def _object_type(route: str, object_id: str | None) -> str | None:
    if object_id:
        return object_id.removesuffix("_id")
    parts = [part for part in route.strip("/").split("/") if part and not part.startswith("{")]
    return parts[-1] if parts else None


def _action(method: str, operation: dict[str, Any]) -> str:
    if operation.get("operationId"):
        return str(operation["operationId"])
    return {
        "GET": "read",
        "POST": "create",
        "PUT": "update",
        "PATCH": "update",
        "DELETE": "delete",
    }.get(method.upper(), method.lower())


def _evidence(operation: dict[str, Any], params: list[str]) -> list[str]:
    evidence = []
    if params:
        evidence.append("parameters: " + ", ".join(params))
    responses = operation.get("responses")
    if isinstance(responses, dict):
        evidence.append("responses: " + ", ".join(sorted(str(k) for k in responses)))
    if "requestBody" in operation:
        evidence.append("requestBody present")
    return evidence


__all__ = ["import_openapi_json", "openapi_payload_to_access_observations"]
