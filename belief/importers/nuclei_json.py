"""Passive Nuclei JSON/JSONL importer.

Nuclei execution is intentionally not implemented in this pass.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from belief.json_contracts import read_bounded_utf8, strict_json_loads
from belief.tools.schemas import ExternalFinding, NormalizedToolResult


def import_nuclei_json(path: str | Path) -> NormalizedToolResult:
    text = read_bounded_utf8(path)
    rows = _parse_rows(text)
    findings = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        findings.append(ExternalFinding(
            tool_id="nuclei",
            rule_id=_str(item.get("template-id") or item.get("template_id")) or None,
            title=_str(info.get("name")) or "Nuclei imported finding",
            message=_str(info.get("description")) or None,
            severity=_str(info.get("severity")) or None,
            confidence="imported",
            file=_str(item.get("matched-at") or item.get("host")) or None,
            route=_str(item.get("matched-at") or item.get("host")) or None,
            evidence=[_str(item.get("matcher-name"))] if item.get("matcher-name") else [],
            raw=item,
        ))
    return NormalizedToolResult(
        tool_id="nuclei",
        findings=sorted(findings, key=lambda f: (f.file or "", f.rule_id or "")),
        warnings=["Nuclei is import-only in this pass; no templates were executed."],
    )


def _parse_rows(text: str) -> list[Any]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        payload = strict_json_loads(stripped)
        return payload if isinstance(payload, list) else []
    rows = []
    for line in stripped.splitlines():
        if line.strip():
            rows.append(strict_json_loads(line))
    return rows


def _str(value: Any) -> str:
    return str(value or "").strip()


__all__ = ["import_nuclei_json"]
