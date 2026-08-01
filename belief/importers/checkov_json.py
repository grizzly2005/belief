"""Passive Checkov JSON importer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from belief.json_contracts import load_json_file
from belief.tools.schemas import ExternalFinding, NormalizedToolResult


def import_checkov_json(path: str | Path) -> NormalizedToolResult:
    payload = load_json_file(path)
    failed = _failed_checks(payload)
    findings = []
    for item in failed:
        if not isinstance(item, dict):
            continue
        findings.append(ExternalFinding(
            tool_id="checkov",
            rule_id=_str(item.get("check_id")) or None,
            title=_str(item.get("check_name")) or "Checkov finding",
            message=_str(item.get("guideline")) or None,
            severity=_str(item.get("severity")) or None,
            confidence="imported",
            file=_str(item.get("file_path") or item.get("file_abs_path")) or None,
            line=_line(item.get("file_line_range")),
            evidence=[_str(item.get("resource"))] if item.get("resource") else [],
            raw=item,
        ))
    return NormalizedToolResult(tool_id="checkov", findings=sorted(findings, key=lambda f: (f.file or "", f.rule_id or "")))


def _failed_checks(payload: Any) -> list[Any]:
    if not isinstance(payload, dict):
        return []
    results = payload.get("results")
    if isinstance(results, dict):
        return results.get("failed_checks", []) if isinstance(results.get("failed_checks"), list) else []
    if isinstance(results, list):
        failed: list[Any] = []
        for result in results:
            if isinstance(result, dict) and isinstance(result.get("failed_checks"), list):
                failed.extend(result["failed_checks"])
        return failed
    return []


def _line(value: Any) -> int | None:
    if isinstance(value, list) and value:
        try:
            return int(value[0])
        except (TypeError, ValueError):
            return None
    return None


def _str(value: Any) -> str:
    return str(value or "").strip()


__all__ = ["import_checkov_json"]
