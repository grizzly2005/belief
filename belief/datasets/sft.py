"""Minimal deterministic SFT export for BELIEF audit reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.pdx.redaction import redact_pdx_value


SFT_SCHEMA_VERSION = "belief.sft.v1"


def audit_report_to_sft_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    audit_cases = report.get("audit_cases") if isinstance(report, dict) else []
    if not isinstance(audit_cases, list):
        return []
    rows = []
    for case in sorted(
        (item for item in audit_cases if isinstance(item, dict)),
        key=lambda item: str(item.get("case_id") or ""),
    ):
        rows.append(_case_to_sft_row(case))
    return rows


def export_sft_dataset_from_audit_report(
    report_path: Path | str,
    output_path: Path | str,
) -> list[dict[str, Any]]:
    report = json.loads(Path(report_path).read_text(encoding="utf-8"))
    rows = audit_report_to_sft_rows(report)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(redact_pdx_value(row), sort_keys=True) for row in rows]
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return rows


def _case_to_sft_row(case: dict[str, Any]) -> dict[str, Any]:
    metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
    reportability = metadata.get("reportability") if isinstance(metadata.get("reportability"), dict) else {}
    user_content = "\n".join([
        f"case_type: {case.get('case_type') or ''}",
        f"severity: {case.get('severity') or ''}",
        f"confidence: {case.get('confidence') or ''}",
        f"cwe: {case.get('cwe') or ''}",
        f"source: {case.get('source') or ''}",
        f"sink: {case.get('sink') or ''}",
        f"reason: {case.get('reason') or ''}",
        "missing_evidence: " + ", ".join(str(item) for item in reportability.get("missing_evidence") or []),
    ]).strip()
    assistant_content = "\n".join([
        f"verdict: {reportability.get('verdict') or case.get('status') or 'needs_review'}",
        f"score: {reportability.get('score', '')}",
        "positive_factors: " + ", ".join(str(item) for item in reportability.get("positive_factors") or []),
        "negative_factors: " + ", ".join(str(item) for item in reportability.get("negative_factors") or []),
        "next_step: " + _first(case.get("human_next_steps") or reportability.get("validation_steps") or []),
    ]).strip()
    return {
        "messages": [
            {
                "role": "system",
                "content": "Classify BELIEF audit evidence for conservative human review without adding exploit instructions.",
            },
            {"role": "user", "content": user_content},
            {"role": "assistant", "content": assistant_content},
        ],
        "metadata": {
            "schema_version": SFT_SCHEMA_VERSION,
            "source": "belief",
            "case_id": str(case.get("case_id") or ""),
            "case_type": str(case.get("case_type") or ""),
        },
    }


def _first(values: Any) -> str:
    if isinstance(values, list) and values:
        return str(values[0])
    if isinstance(values, tuple) and values:
        return str(values[0])
    return ""


__all__ = [
    "SFT_SCHEMA_VERSION",
    "audit_report_to_sft_rows",
    "export_sft_dataset_from_audit_report",
]
