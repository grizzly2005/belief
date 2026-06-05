"""Conservative correlation for imported BELIEF audit cases."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Iterable

from belief.audit_case import AuditCase, sort_audit_cases


@dataclass(frozen=True)
class AuditCaseKey:
    category: str
    file: str | None
    route: str | None
    object_or_sink: str | None
    line_bucket: int | None


def audit_case_key(case: AuditCase) -> AuditCaseKey:
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    category = _category(case)
    file_path = _norm(case.file) or None
    route = _route(case) or None
    object_or_sink = _object_or_sink(case, metadata)
    line_bucket = (int(case.line) // 10) if case.line else None
    if not any([file_path, route, object_or_sink, line_bucket]):
        object_or_sink = case.case_id
    return AuditCaseKey(category, file_path, route, object_or_sink, line_bucket)


def merge_audit_cases(cases: Iterable[AuditCase]) -> list[AuditCase]:
    """Merge cases that likely describe the same underlying issue."""
    groups: dict[AuditCaseKey, list[AuditCase]] = {}
    for case in cases:
        groups.setdefault(audit_case_key(case), []).append(case)

    merged = [
        _merge_group(group)
        for _, group in sorted(groups.items(), key=lambda item: _key_tuple(item[0]))
    ]
    return sort_audit_cases(merged)


def _merge_group(group: list[AuditCase]) -> AuditCase:
    ordered = sort_audit_cases(group)
    if len(ordered) == 1:
        case = ordered[0]
        metadata = _merged_metadata(case, [case])
        return replace(case, metadata=metadata)
    base = ordered[0]
    metadata = _merged_metadata(base, ordered)
    status = min((case.status for case in ordered), key=_status_rank)
    priority = min((case.review_priority for case in ordered), key=_priority_rank)
    severity = min((case.severity for case in ordered), key=_priority_rank)
    confidence = max(float(case.confidence or 0.0) for case in ordered)
    line = min((case.line for case in ordered if case.line), default=base.line)
    return replace(
        base,
        status=status,
        review_priority=priority,
        severity=severity,
        confidence=confidence,
        line=line,
        dataflow_path=tuple(_unique(
            item for case in ordered for item in case.dataflow_path
        )),
        sanitizers=tuple(_unique(item for case in ordered for item in case.sanitizers)),
        guarantees=tuple(_unique(item for case in ordered for item in case.guarantees)),
        missing_guarantees=tuple(_unique(
            item for case in ordered for item in case.missing_guarantees
        )),
        human_next_steps=tuple(_unique(
            item for case in ordered for item in case.human_next_steps
        )),
        reason=_merge_reason(ordered),
        metadata=metadata,
    )


def _merged_metadata(base: AuditCase, group: list[AuditCase]) -> dict[str, Any]:
    metadata = dict(base.metadata or {})
    provenance = []
    source_tools = set()
    evidence = []
    related_case_ids = []
    for case in group:
        related_case_ids.append(case.case_id)
        item_meta = case.metadata if isinstance(case.metadata, dict) else {}
        for tool in _as_list(item_meta.get("source_tools")):
            source_tools.add(str(tool))
        for prov in _as_list(item_meta.get("provenance")):
            if isinstance(prov, dict):
                provenance.append(prov)
                if prov.get("source_tool"):
                    source_tools.add(str(prov["source_tool"]))
        for value in _as_list(item_meta.get("tool_evidence")):
            evidence.append(value)
        if case.reason:
            evidence.append(case.reason)
    metadata["source_tools"] = sorted(source_tools)
    metadata["provenance"] = _unique_dicts(provenance)
    metadata["tool_evidence"] = list(_unique(str(item) for item in evidence if str(item)))
    metadata["merged_signal_count"] = len(group)
    metadata["related_case_ids"] = sorted(set(related_case_ids))
    if len(group) > 1:
        metadata["merged"] = True
    return metadata


def _merge_reason(cases: list[AuditCase]) -> str:
    tools = []
    for case in cases:
        metadata = case.metadata if isinstance(case.metadata, dict) else {}
        tools.extend(str(tool) for tool in _as_list(metadata.get("source_tools")))
    prefix = "Multiple imported/local signals agree" if len(set(tools)) > 1 else "Correlated signals agree"
    return f"{prefix}; manual validation in authorized scope is still required."


def _category(case: AuditCase) -> str:
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    text = str(metadata.get("category") or case.case_type or "").lower()
    if "idor" in text or "bola" in text or "auth" in text or "access" in text:
        return "access_control"
    if "path" in text:
        return "path_traversal"
    if "deserial" in text:
        return "unsafe_deserialization"
    if "command" in text:
        return "command_injection"
    if "sql" in text:
        return "sql_injection"
    if "xss" in text:
        return "xss"
    if "ssrf" in text:
        return "ssrf"
    if "secret" in text:
        return "secrets"
    return text or "unknown"


def _route(case: AuditCase) -> str:
    route_context = case.route_context if isinstance(case.route_context, dict) else {}
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    return _norm(route_context.get("route") or metadata.get("route") or metadata.get("path"))


def _object_or_sink(case: AuditCase, metadata: dict[str, Any]) -> str | None:
    if metadata.get("tool_signal_type") == "external_finding" and (_route(case) or case.file):
        return _category(case)
    value = (
        metadata.get("object_type")
        or metadata.get("object_id_source")
        or case.sink
        or case.rule_id
        or case.source
    )
    text = _norm(value)
    return text or None


def _norm(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip().lower()


def _key_tuple(key: AuditCaseKey) -> tuple:
    return (
        key.category,
        key.file or "",
        key.route or "",
        key.object_or_sink or "",
        key.line_bucket if key.line_bucket is not None else -1,
    )


def _priority_rank(value: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        str(value or "").lower(),
        5,
    )


def _status_rank(value: str) -> int:
    return {
        "actionable": 0,
        "needs_review": 1,
        "protected": 2,
        "false_positive_likely": 3,
    }.get(str(value or "").lower(), 4)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "") else [value])


def _unique(values: Iterable[Any]) -> list[Any]:
    seen = set()
    result = []
    for value in values:
        key = str(value)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


def _unique_dicts(values: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    result = []
    for value in values:
        key = repr(sorted(value.items()))
        if key in seen:
            continue
        seen.add(key)
        result.append(value)
    return result


__all__ = [
    "AuditCaseKey",
    "audit_case_key",
    "merge_audit_cases",
]
