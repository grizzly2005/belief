"""Passive CodeQL SARIF importer with code-flow evidence extraction."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from belief.json_contracts import load_json_file
from belief.tools.schemas import ExternalFinding


def import_codeql_sarif(path: str | Path) -> list[ExternalFinding]:
    payload = load_json_file(path)
    return codeql_sarif_payload_to_findings(payload)


def codeql_sarif_payload_to_findings(payload: dict[str, Any]) -> list[ExternalFinding]:
    findings: list[ExternalFinding] = []
    for run in _list(payload.get("runs")):
        rules = _rules_by_id(run)
        for result in _list(run.get("results")):
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id, {})
            file_path, line, column, end_line = _first_location(result)
            message = _message(result)
            findings.append(ExternalFinding(
                tool_id="codeql",
                rule_id=rule_id or None,
                title=rule_id or message or "CodeQL finding",
                message=message,
                severity=_severity(result, rule),
                file=file_path,
                line=line,
                column=column,
                end_line=end_line,
                cwe=_cwes(result, rule),
                evidence=_code_flow_evidence(result),
                raw=result,
            ))
    return sorted(findings, key=lambda f: (f.file or "", f.line or 0, f.rule_id or ""))


def _rules_by_id(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    driver = ((run.get("tool") or {}).get("driver") or {}) if isinstance(run, dict) else {}
    rules = {}
    for rule in _list(driver.get("rules")):
        if isinstance(rule, dict) and rule.get("id"):
            rules[str(rule["id"])] = rule
    return rules


def _first_location(result: dict[str, Any]) -> tuple[str | None, int | None, int | None, int | None]:
    locations = _list(result.get("locations"))
    if not locations:
        return None, None, None, None
    physical = (locations[0].get("physicalLocation") or {}) if isinstance(locations[0], dict) else {}
    artifact = physical.get("artifactLocation") or {}
    region = physical.get("region") or {}
    return (
        str(artifact.get("uri") or "") or None,
        _int(region.get("startLine")),
        _int(region.get("startColumn")),
        _int(region.get("endLine")),
    )


def _code_flow_evidence(result: dict[str, Any]) -> list[str]:
    evidence: list[str] = []
    for code_flow in _list(result.get("codeFlows")):
        for thread_flow in _list(code_flow.get("threadFlows")) if isinstance(code_flow, dict) else []:
            for location in _list(thread_flow.get("locations")) if isinstance(thread_flow, dict) else []:
                loc = location.get("location") if isinstance(location, dict) else {}
                if not isinstance(loc, dict):
                    continue
                message = _message(loc)
                file_path, line, _, _ = _first_location({"locations": [loc]})
                if file_path or line or message:
                    evidence.append(f"{file_path or '?'}:{line or 0} {message}".strip())
    return evidence


def _severity(result: dict[str, Any], rule: dict[str, Any]) -> str | None:
    props = rule.get("properties") if isinstance(rule.get("properties"), dict) else {}
    return str(result.get("level") or props.get("problem.severity") or "") or None


def _cwes(result: dict[str, Any], rule: dict[str, Any]) -> list[str]:
    props = {}
    props.update(rule.get("properties") if isinstance(rule.get("properties"), dict) else {})
    props.update(result.get("properties") if isinstance(result.get("properties"), dict) else {})
    values = []
    for key in ("tags", "cwe", "security-severity"):
        raw = props.get(key)
        values.extend(raw if isinstance(raw, list) else [raw])
    cwes = set()
    for value in values:
        if not isinstance(value, str):
            continue
        match = re.search(r"cwe[-_/]?(\d+)", value, re.IGNORECASE)
        if match:
            cwes.add(f"CWE-{int(match.group(1)):03d}")
    return sorted(cwes)


def _message(value: dict[str, Any]) -> str:
    msg = value.get("message") if isinstance(value, dict) else {}
    if not isinstance(msg, dict):
        return ""
    return str(msg.get("text") or msg.get("markdown") or "")


def _list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["codeql_sarif_payload_to_findings", "import_codeql_sarif"]
