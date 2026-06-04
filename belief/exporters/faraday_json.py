"""Simple Faraday-compatible JSON-like exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from belief.tools.schemas import ExternalFinding, to_jsonable


def export_faraday_json(findings: Iterable[ExternalFinding]) -> dict:
    vulnerabilities = []
    for finding in sorted(findings, key=lambda item: (item.file or "", item.line or 0, item.rule_id or "")):
        vulnerabilities.append({
            "name": finding.title,
            "desc": finding.message or finding.title,
            "severity": finding.severity or "info",
            "type": "Vulnerability",
            "tool": finding.tool_id,
            "refs": finding.cwe,
            "data": {
                "rule_id": finding.rule_id,
                "file": finding.file,
                "line": finding.line,
                "evidence": finding.evidence,
            },
        })
    return {"schema": "belief.faraday_export.v1", "vulnerabilities": vulnerabilities}


def write_faraday_json(findings: Iterable[ExternalFinding], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(to_jsonable(export_faraday_json(findings)), indent=2, sort_keys=True),
        encoding="utf-8",
    )


__all__ = ["export_faraday_json", "write_faraday_json"]
