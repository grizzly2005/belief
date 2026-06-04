"""Minimal SARIF importer for future external analyzer bridges."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from ..models import Finding


def load_sarif(path: str | Path) -> dict[str, Any]:
    """Load a SARIF JSON document without requiring a SARIF package."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("SARIF payload must be a JSON object")
    return payload


def import_sarif_findings(
    path: str | Path,
    source_tool: str | None = None,
) -> list[Finding]:
    """Import all SARIF results from all runs as stable Finding objects."""
    payload = load_sarif(path)
    findings: list[Finding] = []
    for run in payload.get("runs", []) if isinstance(payload.get("runs"), list) else []:
        if not isinstance(run, dict):
            continue
        run_metadata = _run_metadata(run, source_tool)
        for result in run.get("results", []) if isinstance(run.get("results"), list) else []:
            if isinstance(result, dict):
                findings.append(sarif_result_to_finding(result, run_metadata=run_metadata))
    return sorted(
        findings,
        key=lambda finding: (
            finding.file,
            finding.line or 0,
            finding.rule_id,
            finding.fingerprint,
        ),
    )


def sarif_result_to_finding(
    result: dict[str, Any],
    run_metadata: dict[str, Any] | None = None,
) -> Finding:
    """Convert one SARIF result into BELIEF's Finding model."""
    run_metadata = run_metadata or {}
    rule_id = str(result.get("ruleId") or "")
    level = str(result.get("level") or "warning").lower()
    message = _message_text(result)
    file_path, line = _location(result)
    fingerprints = _dict(result.get("fingerprints"))
    partial_fingerprints = _dict(result.get("partialFingerprints"))
    properties = _dict(result.get("properties"))
    rule_properties = _dict((run_metadata.get("rules_by_id") or {}).get(rule_id))
    source_tool = str(run_metadata.get("source_tool") or "unknown")
    fingerprint = _fingerprint(
        source_tool,
        rule_id,
        file_path,
        line,
        message,
        fingerprints,
        partial_fingerprints,
    )

    metadata = {
        "sarif_level": level,
        "sarif_rule_id": rule_id,
        "sarif_file": file_path,
        "sarif_line": line,
        "sarif_fingerprints": fingerprints,
        "sarif_partial_fingerprints": partial_fingerprints,
        "sarif_properties": properties,
        "sarif_tool": source_tool,
    }

    return Finding(
        source=f"sarif:{source_tool}",
        rule_id=rule_id,
        title=rule_id or message or "SARIF finding",
        description=message or rule_id or "SARIF finding",
        file=file_path,
        line=line,
        cwe=str(properties.get("cwe") or rule_properties.get("cwe") or ""),
        severity=_severity_from_level(level),
        confidence=0.7,
        evidence=message,
        fingerprint=fingerprint,
        dedup_key=fingerprint,
        metadata=metadata,
    )


def _run_metadata(run: dict[str, Any], source_tool: str | None) -> dict[str, Any]:
    driver = _dict(_dict(_dict(run.get("tool")).get("driver")))
    tool_name = str(source_tool or driver.get("name") or "unknown")
    rules_by_id = {}
    for rule in driver.get("rules", []) if isinstance(driver.get("rules"), list) else []:
        if not isinstance(rule, dict):
            continue
        rid = str(rule.get("id") or "")
        if rid:
            rules_by_id[rid] = _dict(rule.get("properties"))
    return {
        "source_tool": tool_name,
        "rules_by_id": rules_by_id,
    }


def _message_text(result: dict[str, Any]) -> str:
    message = _dict(result.get("message"))
    return str(message.get("text") or message.get("markdown") or "")


def _location(result: dict[str, Any]) -> tuple[str, int | None]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return "", None
    first = _dict(locations[0])
    physical = _dict(first.get("physicalLocation"))
    artifact = _dict(physical.get("artifactLocation"))
    region = _dict(physical.get("region"))
    return str(artifact.get("uri") or ""), _int_or_none(region.get("startLine"))


def _severity_from_level(level: str) -> str:
    normalized = str(level or "").lower()
    if normalized == "error":
        return "high"
    if normalized == "warning":
        return "medium"
    if normalized in {"note", "none"}:
        return "info"
    return "medium"


def _fingerprint(
    source_tool: str,
    rule_id: str,
    file_path: str,
    line: int | None,
    message: str,
    fingerprints: dict[str, Any],
    partial_fingerprints: dict[str, Any],
) -> str:
    external = fingerprints or partial_fingerprints
    payload = external or {
        "source_tool": source_tool,
        "rule_id": rule_id,
        "file": file_path,
        "line": line,
        "message": message,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = [
    "load_sarif",
    "sarif_result_to_finding",
    "import_sarif_findings",
]
