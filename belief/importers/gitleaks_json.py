"""Passive Gitleaks JSON importer with redaction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.tool_results.io import sanitize_for_json
from belief.tools.schemas import ExternalFinding, NormalizedToolResult


def import_gitleaks_json(path: str | Path) -> NormalizedToolResult:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = payload if isinstance(payload, list) else payload.get("findings", []) if isinstance(payload, dict) else []
    findings = []
    for item in rows if isinstance(rows, list) else []:
        if not isinstance(item, dict):
            continue
        findings.append(ExternalFinding(
            tool_id="gitleaks",
            rule_id=_str(item.get("RuleID") or item.get("rule_id")) or None,
            title=_str(item.get("Description") or item.get("description")) or "Secret candidate",
            message="Potential secret candidate; raw secret redacted.",
            severity="high",
            confidence="medium",
            file=_str(item.get("File") or item.get("file")) or None,
            line=_int(item.get("StartLine") or item.get("line")),
            evidence=["secret-like value redacted"],
            raw=sanitize_for_json(item),
        ))
    return NormalizedToolResult(tool_id="gitleaks", findings=sorted(findings, key=lambda f: (f.file or "", f.line or 0)))


def _str(value: Any) -> str:
    return str(value or "").strip()


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["import_gitleaks_json"]
