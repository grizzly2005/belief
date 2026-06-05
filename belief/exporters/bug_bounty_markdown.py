"""Bug-bounty-style candidate Markdown exporter.

This exporter drafts candidate reports from BELIEF audit cases. It never
claims confirmation and never submits anything automatically.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from belief.audit_case import AuditCase, sort_audit_cases
from belief.reportability.scoring import assess_audit_case_reportability
from belief.tool_results.io import sanitize_for_json


def render_bug_bounty_markdown(audit_cases: Iterable[AuditCase], target: str = "") -> str:
    cases = sort_audit_cases(audit_cases)
    assessed = [(case, _assessment(case)) for case in cases]
    assessed = sorted(
        assessed,
        key=lambda item: (
            -int(item[1]["score"]),
            item[1]["verdict"],
            item[0].file,
            item[0].line or 0,
            item[0].case_id,
        ),
    )
    verdict_counts = Counter(item[1]["verdict"] for item in assessed)
    lines = [
        "# BELIEF Bug Bounty Candidate Report",
        "",
        "## Summary",
        "",
        f"Total cases: {len(cases)}",
        f"Reportable candidates: {verdict_counts.get('reportable_candidate', 0)}",
        f"Needs manual validation: {verdict_counts.get('needs_manual_validation', 0)}",
        f"Protected by guard: {verdict_counts.get('protected_by_guard', 0)}",
        f"Weak signals: {verdict_counts.get('weak_signal', 0)}",
        f"Likely false positives: {verdict_counts.get('likely_false_positive', 0)}",
    ]
    if target:
        lines.append(f"Target: `{_safe_text(target)}`")
    lines.extend([
        "",
        "---",
        "",
    ])
    for index, (case, assessment) in enumerate(assessed, start=1):
        lines.extend(_case_section(index, case, assessment))
    if not assessed:
        lines.append("_No candidate audit cases._")
        lines.append("")
    return "\n".join(lines)


def write_bug_bounty_markdown(
    audit_cases: Iterable[AuditCase],
    output_path: str | Path,
    target: str = "",
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_bug_bounty_markdown(audit_cases, target=target), encoding="utf-8")


def _case_section(index: int, case: AuditCase, assessment: dict[str, Any]) -> list[str]:
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    title = metadata.get("title") or case.case_type.replace("_", " ")
    route = case.route_context if isinstance(case.route_context, dict) else {}
    source_tools = _as_list(metadata.get("source_tools"))
    evidence = _evidence(case, metadata)
    existing_protections = list(case.guarantees) + [
        str(item) for item in _as_list(metadata.get("detected_guards"))
    ]
    lines = [
        f"## Candidate {index}: {_safe_text(title)}",
        "",
        "### Verdict",
        _safe_text(str(assessment["verdict"])),
        "",
        "### Score",
        f"{int(assessment['score'])}/100",
        "",
        "### Confidence",
        _safe_text(str(assessment["confidence"])),
        "",
        "### Affected Location",
        f"- File: `{_safe_text(case.file or '-')}`",
        f"- Line: `{case.line if case.line is not None else '-'}`",
        f"- Route: `{_safe_text(route.get('route') or metadata.get('route') or metadata.get('path') or '-')}`",
        f"- Object: `{_safe_text(metadata.get('object_type') or metadata.get('object_id_source') or '-')}`",
        f"- Action: `{_safe_text(metadata.get('action') or case.sink or '-')}`",
        "",
        "### Evidence",
    ]
    lines.extend(_bullets(evidence or [case.reason or "Imported/static evidence requires manual review."]))
    lines.extend([
        "",
        "### Why this may be exploitable",
        _safe_text(_why_exploitable(case, assessment)),
        "",
        "### Existing protections detected",
    ])
    lines.extend(_bullets(existing_protections or ["No strong protection evidence was imported or inferred."]))
    lines.extend([
        "",
        "### Missing evidence",
    ])
    lines.extend(_bullets(assessment.get("missing_evidence") or ["Manual validation result in authorized scope."]))
    lines.extend([
        "",
        "### Validation steps",
    ])
    for number, step in enumerate(assessment.get("validation_steps") or case.human_next_steps or (), start=1):
        lines.append(f"{number}. {_safe_text(step)}")
    if not (assessment.get("validation_steps") or case.human_next_steps):
        lines.append("1. Review the candidate manually in an authorized test scope.")
    lines.extend([
        "",
        "### Source tools",
    ])
    lines.extend(_bullets(source_tools or ["belief"]))
    lines.extend([
        "",
        "### Limitations",
        "This is a candidate based on local/static/imported evidence. Manual validation in authorized scope is required.",
        "",
        "---",
        "",
    ])
    return lines


def _assessment(case: AuditCase) -> dict[str, Any]:
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    existing = metadata.get("reportability")
    if isinstance(existing, dict):
        return existing
    return assess_audit_case_reportability(case).to_dict()


def _evidence(case: AuditCase, metadata: dict[str, Any]) -> list[str]:
    values: list[str] = []
    values.extend(str(item) for item in _as_list(metadata.get("tool_evidence")))
    values.extend(str(item) for item in case.dataflow_path[:8])
    if case.reason:
        values.append(case.reason)
    return _dedupe(values)


def _why_exploitable(case: AuditCase, assessment: dict[str, Any]) -> str:
    positives = assessment.get("positive_factors") or []
    if positives:
        return "The candidate has supporting factors: " + ", ".join(_safe_text(item) for item in positives) + "."
    if case.missing_guarantees:
        return "The candidate is missing local proof for: " + ", ".join(case.missing_guarantees) + "."
    return "The imported signal needs additional evidence before it can be treated as reportable."


def _bullets(values: Iterable[Any]) -> list[str]:
    items = _dedupe(str(item) for item in values)
    return [f"- {_safe_text(item)}" for item in items] if items else ["- -"]


def _safe_text(value: Any) -> str:
    cleaned = sanitize_for_json(str(value or ""))
    return str(cleaned).replace("\r", " ").replace("\n", " ").strip()


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "") else [value])


def _dedupe(values: Iterable[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


__all__ = [
    "render_bug_bounty_markdown",
    "write_bug_bounty_markdown",
]
