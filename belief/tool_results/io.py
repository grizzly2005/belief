"""Read and write stable BELIEF normalized tool-result JSON."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from belief.tools.schemas import (
    AccessObservation,
    AttackPath,
    ExternalFinding,
    NormalizedToolResult,
    RequestStep,
    to_jsonable,
)

from .models import TOOL_RESULT_SCHEMA_VERSION, ToolResultSchemaError


_SENSITIVE_KEY_RE = re.compile(
    r"(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|"
    r"bearer|client[_-]?secret|access[_-]?token|refresh[_-]?token|session)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[^\s,;]+"),
    re.compile(r"(?i)((?:access|refresh|api|session)[_-]?token\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)((?:api[_-]?key|client[_-]?secret|password|passwd)\s*[:=]\s*)[^\s,;]+"),
    re.compile(r"(?i)(cookie\s*[:=]\s*)[^;\n]+"),
]


def normalized_tool_result_to_dict(result: NormalizedToolResult) -> dict[str, Any]:
    """Return deterministic, redacted JSON for one normalized tool result."""
    payload = to_jsonable(result)
    return {
        "schema_version": TOOL_RESULT_SCHEMA_VERSION,
        "tool_id": str(payload.get("tool_id") or result.tool_id),
        "findings": sanitize_for_json(payload.get("findings") or []),
        "access_observations": sanitize_for_json(payload.get("access_observations") or []),
        "attack_paths": sanitize_for_json(payload.get("attack_paths") or []),
        "warnings": sanitize_for_json(payload.get("warnings") or []),
        "artifacts": [
            str(item).replace("\\", "/")
            for item in (payload.get("artifacts") or [])
            if str(item)
        ],
        "raw": sanitize_for_json(payload.get("raw") or {}),
    }


def normalized_tool_result_from_dict(payload: dict[str, Any]) -> NormalizedToolResult:
    """Build a NormalizedToolResult from stable BELIEF JSON.

    Optional lists may be omitted. Unknown keys are ignored deliberately so
    future versions can remain readable by older BELIEF versions.
    """
    if not isinstance(payload, dict):
        raise ToolResultSchemaError("normalized tool result must be a JSON object")
    schema = payload.get("schema_version", TOOL_RESULT_SCHEMA_VERSION)
    if schema != TOOL_RESULT_SCHEMA_VERSION:
        raise ToolResultSchemaError(
            f"unsupported normalized tool result schema: {schema!r}"
        )
    tool_id = str(payload.get("tool_id") or "").strip()
    if not tool_id:
        raise ToolResultSchemaError("normalized tool result is missing tool_id")

    return NormalizedToolResult(
        tool_id=tool_id,
        findings=[_external_finding(item, tool_id) for item in _list(payload.get("findings"))],
        access_observations=[
            _access_observation(item, tool_id)
            for item in _list(payload.get("access_observations"))
        ],
        attack_paths=[
            _attack_path(item, tool_id)
            for item in _list(payload.get("attack_paths"))
        ],
        artifacts=[Path(str(item)) for item in _list(payload.get("artifacts")) if str(item)],
        warnings=[str(item) for item in _list(payload.get("warnings"))],
        raw=_dict(payload.get("raw")),
    )


def write_normalized_tool_result(result: NormalizedToolResult, path: Path | str) -> None:
    """Write one normalized result to disk with deterministic formatting."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(
            normalized_tool_result_to_dict(result),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_normalized_tool_result(path: Path | str) -> NormalizedToolResult:
    """Read one normalized result from disk."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ToolResultSchemaError(f"invalid normalized tool-result JSON: {exc}") from exc
    return normalized_tool_result_from_dict(payload)


def read_many_normalized_tool_results(paths: Iterable[Path | str]) -> list[NormalizedToolResult]:
    """Read many normalized result files in deterministic path order."""
    return [
        read_normalized_tool_result(path)
        for path in sorted((Path(path) for path in paths), key=lambda item: str(item))
    ]


def sanitize_for_json(value: Any) -> Any:
    """Return JSON-safe data with secrets, auth headers, cookies, and tokens redacted."""
    if isinstance(value, Path):
        return str(value).replace("\\", "/")
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, raw in sorted(value.items(), key=lambda item: str(item[0])):
            text_key = str(key)
            if _SENSITIVE_KEY_RE.search(text_key):
                clean[text_key] = "[REDACTED]"
            else:
                clean[text_key] = sanitize_for_json(raw)
        return clean
    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_json(item) for item in value]
    if isinstance(value, str):
        redacted = value
        for pattern in _SENSITIVE_VALUE_PATTERNS:
            redacted = pattern.sub(r"\1[REDACTED]", redacted)
        return redacted
    return to_jsonable(value)


def _external_finding(item: Any, fallback_tool_id: str) -> ExternalFinding:
    data = _dict(item)
    return ExternalFinding(
        tool_id=str(data.get("tool_id") or fallback_tool_id),
        rule_id=_optional_str(data.get("rule_id")),
        title=str(data.get("title") or data.get("rule_id") or "External finding"),
        message=_optional_str(data.get("message")),
        severity=_optional_str(data.get("severity")),
        confidence=_optional_str(data.get("confidence")),
        file=_optional_str(data.get("file")),
        line=_optional_int(data.get("line")),
        column=_optional_int(data.get("column")),
        end_line=_optional_int(data.get("end_line")),
        cwe=[str(item) for item in _list(data.get("cwe")) if str(item)],
        route=_optional_str(data.get("route")),
        evidence=[str(item) for item in _list(data.get("evidence")) if str(item)],
        raw=_dict(sanitize_for_json(data.get("raw") or {})),
    )


def _access_observation(item: Any, fallback_tool_id: str) -> AccessObservation:
    data = _dict(item)
    return AccessObservation(
        source_tool=str(data.get("source_tool") or fallback_tool_id),
        actor=_optional_str(data.get("actor")),
        role=_optional_str(data.get("role")),
        method=_optional_str(data.get("method")),
        path=_optional_str(data.get("path")),
        object_type=_optional_str(data.get("object_type")),
        object_id_source=_optional_str(data.get("object_id_source")),
        action=_optional_str(data.get("action")),
        expected_guard=_optional_str(data.get("expected_guard")),
        detected_guards=[
            str(item) for item in _list(data.get("detected_guards")) if str(item)
        ],
        missing_guards=[
            str(item) for item in _list(data.get("missing_guards")) if str(item)
        ],
        mutation=bool(data.get("mutation", False)),
        response_exposes_object=bool(data.get("response_exposes_object", False)),
        confidence=_optional_str(data.get("confidence")),
        evidence=[str(item) for item in _list(data.get("evidence")) if str(item)],
    )


def _attack_path(item: Any, fallback_tool_id: str) -> AttackPath:
    data = _dict(item)
    return AttackPath(
        source_tool=str(data.get("source_tool") or fallback_tool_id),
        title=str(data.get("title") or "Validation workflow candidate"),
        steps=[_request_step(step) for step in _list(data.get("steps"))],
        hypothesis=str(data.get("hypothesis") or ""),
        evidence_needed=[
            str(item) for item in _list(data.get("evidence_needed")) if str(item)
        ],
        risk=_optional_str(data.get("risk")),
    )


def _request_step(item: Any) -> RequestStep:
    data = _dict(item)
    return RequestStep(
        method=str(data.get("method") or "REQUEST"),
        path=str(data.get("path") or "/"),
        produces=[str(item) for item in _list(data.get("produces")) if str(item)],
        consumes=[str(item) for item in _list(data.get("consumes")) if str(item)],
        actor=_optional_str(data.get("actor")),
        notes=_optional_str(data.get("notes")),
    )


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _optional_str(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


def _optional_int(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "normalized_tool_result_from_dict",
    "normalized_tool_result_to_dict",
    "read_many_normalized_tool_results",
    "read_normalized_tool_result",
    "sanitize_for_json",
    "write_normalized_tool_result",
]
