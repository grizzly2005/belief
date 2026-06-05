"""Minimal SARIF 2.1.0 exporter for BELIEF audit cases.

The structure is hand-built JSON to avoid a mandatory dependency on
sarif-python-om. The shape follows the SARIF 2.1.0 result/rule/location fields
inspected from the public schema and Microsoft SARIF examples.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..audit_case import AuditCase


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def audit_case_to_sarif_result(case: AuditCase) -> dict:
    """Convert one AuditCase into a SARIF result object."""
    result = {
        "ruleId": case.case_type,
        "level": _sarif_level(case.review_priority),
        "message": {"text": _message(case)},
        "locations": [_location(case)],
        "partialFingerprints": {
            "belief.caseId": case.case_id,
            "belief.relatedFinding": case.related_finding_fingerprint or case.case_id,
        },
        "fingerprints": {
            "belief.caseId": case.case_id,
        },
        "properties": {
            "case_id": case.case_id,
            "case_type": case.case_type,
            "status": case.status,
            "review_priority": case.review_priority,
            "confidence": case.confidence,
            "severity": case.severity,
            "cwe": case.cwe,
            "source": case.source,
            "sink": case.sink,
            "dataflow_path": list(case.dataflow_path),
            "sanitizers": list(case.sanitizers),
            "guarantees": list(case.guarantees),
            "missing_guarantees": list(case.missing_guarantees),
            "z3_status": case.z3_status,
            "unsat_core": list(case.unsat_core),
            "human_next_steps": list(case.human_next_steps),
            "related_finding_fingerprint": case.related_finding_fingerprint,
            "reason": case.reason,
            "route_context": dict(case.route_context),
            "metadata": dict(case.metadata),
        },
    }
    return result


def export_audit_cases_to_sarif(
    audit_cases: Iterable[AuditCase],
    target: str,
    tool_version: str | None = None,
) -> dict:
    """Return a minimal deterministic SARIF log."""
    cases = sorted(
        list(audit_cases),
        key=lambda case: (
            case.case_type,
            case.file,
            case.line or 0,
            case.case_id,
        ),
    )
    rules = _rules(cases)
    rule_index = {rule["id"]: i for i, rule in enumerate(rules)}
    results = []
    for case in cases:
        result = audit_case_to_sarif_result(case)
        result["ruleIndex"] = rule_index.get(case.case_type, 0)
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "BELIEF",
                    "version": tool_version or "belief-v4",
                    "informationUri": "https://local/belief",
                    "rules": rules,
                }
            },
            "originalUriBaseIds": {
                "TARGETROOT": {"uri": _uri(target)}
            },
            "results": results,
            "properties": {
                "target": target,
                "audit_case_count": len(cases),
            },
        }],
    }


def write_sarif_report(
    audit_cases: Iterable[AuditCase],
    output_path: str | Path,
    target: str,
    tool_version: str | None = None,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = export_audit_cases_to_sarif(audit_cases, target, tool_version=tool_version)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _rules(cases: list[AuditCase]) -> list[dict]:
    seen = set()
    rules = []
    for case in sorted(cases, key=lambda c: (c.case_type, c.cwe)):
        if case.case_type in seen:
            continue
        seen.add(case.case_type)
        rules.append({
            "id": case.case_type,
            "name": case.case_type,
            "shortDescription": {"text": case.case_type.replace("_", " ")},
            "properties": {
                "cwe": case.cwe,
                "kind": "audit_case",
            },
        })
    return rules


def _sarif_level(priority: str) -> str:
    normalized = str(priority or "").lower()
    if normalized in {"critical", "high"}:
        return "error"
    if normalized == "medium":
        return "warning"
    return "note"


def _location(case: AuditCase) -> dict:
    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": case.file or "unknown"},
        }
    }
    if case.line:
        location["physicalLocation"]["region"] = {"startLine": int(case.line)}
    return location


def _message(case: AuditCase) -> str:
    location = f"{case.file}:{case.line}" if case.line else case.file
    return (
        f"{case.case_type} {case.status} at {location}: "
        f"{case.reason or 'review audit case'}"
    )


def _uri(path: str) -> str:
    value = str(path or ".").replace("\\", "/")
    if not value.endswith("/"):
        value += "/"
    return value


__all__ = [
    "audit_case_to_sarif_result",
    "export_audit_cases_to_sarif",
    "write_sarif_report",
]
