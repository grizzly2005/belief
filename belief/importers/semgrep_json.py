"""Passive Semgrep JSON importer for BELIEF tool bridges."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from belief.json_contracts import load_json_file
from belief.tools.schemas import ExternalFinding


def import_semgrep_json(path: str | Path) -> list[ExternalFinding]:
    payload = load_json_file(path)
    return semgrep_payload_to_findings(payload)


def semgrep_payload_to_findings(payload: dict[str, Any]) -> list[ExternalFinding]:
    findings: list[ExternalFinding] = []
    results = payload.get("results", []) if isinstance(payload, dict) else []
    for result in results if isinstance(results, list) else []:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        end = result.get("end") if isinstance(result.get("end"), dict) else {}
        rule_id = _str(result.get("check_id"))
        message = _str(extra.get("message")) or rule_id
        findings.append(ExternalFinding(
            tool_id="semgrep",
            rule_id=rule_id or None,
            title=rule_id or message or "Semgrep finding",
            message=message,
            severity=_str(extra.get("severity")) or None,
            confidence=_str(metadata.get("confidence")) or None,
            file=_str(result.get("path")) or None,
            line=_int(start.get("line")),
            column=_int(start.get("col")),
            end_line=_int(end.get("line")),
            cwe=_cwes(metadata),
            evidence=[message] if message else [],
            raw=result,
        ))
    return sorted(findings, key=lambda f: (f.file or "", f.line or 0, f.rule_id or ""))


def _cwes(metadata: dict[str, Any]) -> list[str]:
    raw = metadata.get("cwe") or metadata.get("cwe_id") or []
    values = raw if isinstance(raw, list) else [raw]
    cwes = []
    for value in values:
        text = _str(value)
        match = re.search(r"CWE-\d+", text, re.IGNORECASE)
        if match:
            cwes.append(match.group(0).upper())
    return sorted(set(cwes))


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str(value: Any) -> str:
    return str(value or "").strip()


__all__ = ["import_semgrep_json", "semgrep_payload_to_findings"]
