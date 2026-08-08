"""Passive OWASP ZAP alerts JSON importer."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from belief.json_contracts import load_json_file
from belief.tools.schemas import ExternalFinding


def import_zap_json(path: str | Path) -> list[ExternalFinding]:
    payload = load_json_file(path)
    return zap_payload_to_findings(payload)


def zap_payload_to_findings(payload: dict[str, Any]) -> list[ExternalFinding]:
    sites = payload.get("site", []) if isinstance(payload, dict) else []
    alerts = payload.get("alerts", []) if isinstance(payload, dict) else []
    for site in sites if isinstance(sites, list) else []:
        if isinstance(site, dict):
            alerts.extend(site.get("alerts", []) if isinstance(site.get("alerts"), list) else [])
    findings = []
    for alert in alerts if isinstance(alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        instances = alert.get("instances") if isinstance(alert.get("instances"), list) else []
        instance = instances[0] if instances and isinstance(instances[0], dict) else {}
        findings.append(ExternalFinding(
            tool_id="zap",
            rule_id=str(alert.get("pluginid") or alert.get("alertRef") or "") or None,
            title=str(alert.get("alert") or alert.get("name") or "ZAP alert"),
            message=str(alert.get("desc") or alert.get("description") or ""),
            severity=str(alert.get("riskdesc") or alert.get("risk") or "") or None,
            confidence=str(alert.get("confidence") or "") or None,
            file=str(instance.get("uri") or alert.get("url") or "") or None,
            route=str(instance.get("uri") or "") or None,
            evidence=[
                str(value) for value in (
                    instance.get("param"),
                    instance.get("evidence"),
                    alert.get("solution"),
                ) if value
            ],
            raw=alert,
        ))
    return sorted(findings, key=lambda f: (f.file or "", f.rule_id or "", f.title))


__all__ = ["import_zap_json", "zap_payload_to_findings"]
