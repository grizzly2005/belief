"""Markdown audit report tests."""

from __future__ import annotations

from belief.audit_case import AuditCase
from belief.exporters.markdown import render_audit_cases_markdown


def _case(status: str, case_id: str) -> AuditCase:
    return AuditCase(
        case_id=case_id,
        case_type="path_traversal_possible",
        status=status,
        review_priority="high" if status == "actionable" else "low",
        confidence=0.9,
        severity="high",
        file=f"{case_id}.py",
        line=5,
        rule_id="PATH_TRAVERSAL",
        cwe="CWE-22",
        source="request.args['path']",
        sink="open",
        missing_guarantees=("path.is_within_store == true",),
        human_next_steps=("Verify path normalization and storage boundary checks.",),
        reason="user-controlled path reaches open",
    )


def test_markdown_report_hides_protected_details_by_default():
    report = render_audit_cases_markdown(
        [_case("actionable", "visible"), _case("protected", "hidden")],
        "/tmp/project",
    )

    assert "# BELIEF Audit Report" in report
    assert "visible.py:5" in report
    assert "request.args['path']` -> `open" in report
    assert "path.is_within_store == true" in report
    assert "hidden.py:5" not in report
    assert "protected cases hidden: 1" in report


def test_markdown_report_can_include_protected_details():
    report = render_audit_cases_markdown(
        [_case("protected", "protected_case")],
        "/tmp/project",
        include_protected=True,
    )

    assert "protected_case.py:5" in report
    assert "Protected summary" in report
