"""Dradis-style Markdown note exporter."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from belief.audit_case import AuditCase
from belief.tools.schemas import ExternalFinding


def render_dradis_markdown(items: Iterable[AuditCase | ExternalFinding]) -> str:
    lines = ["# BELIEF Findings", ""]
    for item in items:
        if isinstance(item, AuditCase):
            lines.extend([
                f"## {item.case_type}",
                "",
                f"* Priority: {item.review_priority}",
                f"* Status: {item.status}",
                f"* Location: `{item.file}:{item.line or 0}`",
                f"* CWE: `{item.cwe or '-'}`",
                "",
                item.reason or "Review required.",
                "",
            ])
        else:
            lines.extend([
                f"## {item.title}",
                "",
                f"* Tool: {item.tool_id}",
                f"* Rule: {item.rule_id or '-'}",
                f"* Severity: {item.severity or '-'}",
                f"* Location: `{item.file or ''}:{item.line or 0}`",
                "",
                item.message or "Review required.",
                "",
            ])
    return "\n".join(lines)


def write_dradis_markdown(items: Iterable[AuditCase | ExternalFinding], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_dradis_markdown(items), encoding="utf-8")


__all__ = ["render_dradis_markdown", "write_dradis_markdown"]
