"""Minimal JSON PDX exporter for BELIEF reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.pdx.io import write_pdx_bundle
from belief.pdx.models import PDXBundle, PDXDelta, PDXMeta, PDXVerdict


def export_report_to_pdx_bundle(report: dict[str, Any]) -> PDXBundle:
    """Convert a BELIEF report/audit JSON payload into a passive PDX bundle."""
    audit_cases = report.get("audit_cases") if isinstance(report, dict) else None
    findings = report.get("findings") if isinstance(report, dict) else None
    deltas = []
    verdicts = []
    if isinstance(audit_cases, list) and audit_cases:
        for case in sorted(audit_cases, key=lambda item: str((item or {}).get("case_id", ""))):
            if not isinstance(case, dict):
                continue
            delta = _audit_case_to_delta(case)
            deltas.append(delta)
            verdicts.append(_audit_case_to_verdict(case, delta.id))
    elif isinstance(findings, list):
        for finding in sorted(findings, key=lambda item: str((item or {}).get("fingerprint", ""))):
            if not isinstance(finding, dict):
                continue
            deltas.append(_finding_to_delta(finding))
    return PDXBundle(
        meta=PDXMeta(provenance_chain=("belief-report-json",)),
        deltas=tuple(deltas),
        verdicts=tuple(verdicts),
    )


def write_report_as_pdx(report_path: Path | str, output_path: Path | str) -> PDXBundle:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    bundle = export_report_to_pdx_bundle(report)
    write_pdx_bundle(bundle, output_path)
    return bundle


def _audit_case_to_delta(case: dict[str, Any]) -> PDXDelta:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    raw = {"belief_case_id": case.get("case_id")}
    reportability_claim = metadata.get("reportability")
    if isinstance(reportability_claim, dict):
        raw["source_reportability_claim"] = {
            "classification": "unverified_serialized_claim",
            "proof_eligible": False,
            "value": reportability_claim,
        }
    return PDXDelta(
        id=str(case.get("case_id") or ""),
        spec_ref=str(case.get("rule_id") or ""),
        delta_type=_delta_type_from_text(" ".join([
            str(case.get("case_type") or ""),
            str(case.get("rule_id") or ""),
            str(case.get("cwe") or ""),
        ])),
        category=str(case.get("case_type") or ""),
        description=str(case.get("reason") or metadata.get("title") or case.get("case_type") or ""),
        expected="safe or authorized behavior",
        observed=str(case.get("sink") or case.get("source") or ""),
        vector={
            "severity": _score_from_severity(case.get("severity")),
            "confidence": float(case.get("confidence") or 0.5),
        },
        file=str(case.get("file") or ""),
        line=_safe_int(case.get("line")),
        route=str((case.get("route_context") or {}).get("route") or ""),
        evidence=tuple(str(item) for item in case.get("dataflow_path") or [] if str(item)),
        cwe=tuple([str(case.get("cwe"))] if case.get("cwe") else []),
        raw=raw,
    )


def _audit_case_to_verdict(case: dict[str, Any], delta_ref: str) -> PDXVerdict:
    return PDXVerdict(
        delta_ref=delta_ref,
        result="UNCERTAIN",
        tested=False,
        human_validated=False,
        method="belief_report_export_signal_only",
        reason=(
            "Serialized BELIEF reportability is non-authoritative; "
            "no durable validation proof was supplied."
        ),
        weight=0.0,
    )


def _finding_to_delta(finding: dict[str, Any]) -> PDXDelta:
    return PDXDelta(
        id=str(finding.get("fingerprint") or ""),
        spec_ref=str(finding.get("rule_id") or ""),
        delta_type=_delta_type_from_text(" ".join([
            str(finding.get("rule_id") or ""),
            str(finding.get("title") or ""),
            str(finding.get("cwe") or ""),
        ])),
        category=str(finding.get("category") or ""),
        description=str(finding.get("description") or finding.get("title") or ""),
        expected="safe behavior",
        observed=str(finding.get("evidence") or ""),
        vector={
            "severity": _score_from_severity(finding.get("severity")),
            "confidence": float(finding.get("confidence") or 0.5),
        },
        file=str(finding.get("file") or ""),
        line=_safe_int(finding.get("line")),
        cwe=tuple([str(finding.get("cwe"))] if finding.get("cwe") else []),
        raw={"belief_finding_id": finding.get("id")},
    )


def _delta_type_from_text(text: str) -> str:
    lowered = text.lower()
    if "ssrf" in lowered or "cwe-918" in lowered:
        return "SSRF"
    if "deserial" in lowered or "cwe-502" in lowered:
        return "DESERIAL"
    if "auth" in lowered or "access" in lowered or "idor" in lowered or "cwe-862" in lowered or "cwe-863" in lowered:
        return "AUTH_BYPASS"
    if "inject" in lowered:
        return "INJECTION"
    return "UNKNOWN"


def _score_from_severity(value: Any) -> float:
    return {
        "critical": 0.95,
        "high": 0.8,
        "medium": 0.55,
        "low": 0.3,
        "info": 0.1,
    }.get(str(value or "").lower(), 0.2)


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["export_report_to_pdx_bundle", "write_report_as_pdx"]
