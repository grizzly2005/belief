"""Markdown audit report renderer for BELIEF audit cases."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

from ..audit_case import AuditCase, sort_audit_cases


def render_audit_cases_markdown(
    audit_cases: Iterable[AuditCase],
    target: str,
    include_protected: bool = False,
) -> str:
    cases = sort_audit_cases(audit_cases)
    visible = [
        case for case in cases
        if include_protected or case.status in {"actionable", "needs_review"}
    ]
    status_counts = Counter(case.status for case in cases)
    priority_counts = Counter(case.review_priority for case in cases)

    lines = [
        "# BELIEF Audit Report",
        "",
        "## Summary",
        "",
        f"* target: `{target}`",
        f"* audit cases: {len(cases)}",
        f"* actionable: {status_counts.get('actionable', 0)}",
        f"* needs_review: {status_counts.get('needs_review', 0)}",
        f"* protected: {status_counts.get('protected', 0)}",
        f"* false_positive_likely: {status_counts.get('false_positive_likely', 0)}",
        f"* critical: {priority_counts.get('critical', 0)}",
        f"* high: {priority_counts.get('high', 0)}",
        f"* medium: {priority_counts.get('medium', 0)}",
        f"* low: {priority_counts.get('low', 0)}",
        f"* info: {priority_counts.get('info', 0)}",
        "",
        "## Actionable cases",
        "",
    ]
    lines.extend(_section(case for case in visible if case.status == "actionable"))
    lines.extend(["", "## Needs review", ""])
    lines.extend(_section(case for case in visible if case.status == "needs_review"))
    lines.extend(["", "## Protected summary", ""])
    if include_protected:
        lines.extend(_section(case for case in visible if case.status in {"protected", "false_positive_likely"}))
    else:
        lines.append(f"* protected cases hidden: {status_counts.get('protected', 0)}")
        lines.append(f"* likely false positives hidden: {status_counts.get('false_positive_likely', 0)}")
    lines.append("")
    return "\n".join(lines)


def write_audit_markdown(
    audit_cases: Iterable[AuditCase],
    output_path: str | Path,
    target: str,
    include_protected: bool = False,
) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        render_audit_cases_markdown(
            audit_cases,
            target,
            include_protected=include_protected,
        ),
        encoding="utf-8",
    )


def _section(cases: Iterable[AuditCase]) -> list[str]:
    items = list(cases)
    if not items:
        return ["_None._"]
    lines = []
    for case in items:
        location = f"{case.file}:{case.line}" if case.line else case.file
        lines.extend([
            f"### [{case.review_priority.upper()}] {case.case_type} ({case.status})",
            "",
            f"* location: `{location}`",
            f"* source -> sink: `{case.source or '?'}` -> `{case.sink or '?'}`",
            f"* cwe: `{case.cwe or '-'}`",
            f"* missing guarantees: {_join(case.missing_guarantees)}",
            f"* reason: {case.reason}",
        ])
        if case.route_context:
            route = case.route_context
            methods = ",".join(route.get("methods") or []) or "-"
            lines.append(
                f"* route: `{route.get('framework', '-')}` "
                f"`{methods} {route.get('route', '-')}` "
                f"`{route.get('handler', '-')}`"
            )
        lines.append("* next steps:")
        for step in case.human_next_steps:
            lines.append(f"  * {step}")
        lines.append("")
    return lines


def _join(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "-"


__all__ = [
    "render_audit_cases_markdown",
    "write_audit_markdown",
]
