"""Passive pip-audit JSON importer."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.tools.schemas import ExternalFinding, NormalizedToolResult


def import_pip_audit_json(path: str | Path) -> NormalizedToolResult:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    dependencies = payload.get("dependencies", []) if isinstance(payload, dict) else []
    findings = []
    for dep in dependencies if isinstance(dependencies, list) else []:
        if not isinstance(dep, dict):
            continue
        for vuln in dep.get("vulns", []) if isinstance(dep.get("vulns"), list) else []:
            if not isinstance(vuln, dict):
                continue
            vuln_id = _str(vuln.get("id"))
            findings.append(ExternalFinding(
                tool_id="pip_audit",
                rule_id=vuln_id or None,
                title=f"Vulnerable dependency candidate: {_str(dep.get('name'))}",
                message=_str(vuln.get("description")) or None,
                severity=_str(vuln.get("fix_versions")) or None,
                confidence="imported",
                file=_str(dep.get("name")) or None,
                evidence=[f"package={_str(dep.get('name'))}", f"version={_str(dep.get('version'))}"],
                raw={"dependency": dep.get("name"), "version": dep.get("version"), "vulnerability": vuln},
            ))
    return NormalizedToolResult(tool_id="pip_audit", findings=sorted(findings, key=lambda f: (f.file or "", f.rule_id or "")))


def _str(value: Any) -> str:
    return str(value or "").strip()


__all__ = ["import_pip_audit_json"]
