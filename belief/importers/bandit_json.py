"""Passive Bandit JSON importer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from belief.json_contracts import load_json_file
from belief.tools.schemas import ExternalFinding, NormalizedToolResult


def import_bandit_json(path: str | Path) -> NormalizedToolResult:
    payload = load_json_file(path)
    findings = []
    for item in payload.get("results", []) if isinstance(payload, dict) else []:
        if not isinstance(item, dict):
            continue
        findings.append(ExternalFinding(
            tool_id="bandit",
            rule_id=_str(item.get("test_id")) or None,
            title=_str(item.get("test_name")) or "Bandit finding",
            message=_str(item.get("issue_text")) or None,
            severity=_str(item.get("issue_severity")) or None,
            confidence=_str(item.get("issue_confidence")) or None,
            file=_str(item.get("filename")) or None,
            line=_int(item.get("line_number")),
            cwe=_cwe(item.get("issue_cwe")),
            evidence=[_str(item.get("code"))] if item.get("code") else [],
            raw=item,
        ))
    return NormalizedToolResult(tool_id="bandit", findings=sorted(findings, key=lambda f: (f.file or "", f.line or 0)))


def _cwe(value: Any) -> list[str]:
    if isinstance(value, dict) and value.get("id"):
        return [f"CWE-{value['id']}"]
    return []


def _str(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["import_bandit_json"]
