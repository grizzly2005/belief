from belief.audit_case import AuditCase
from belief.exporters.bug_bounty_markdown import render_bug_bounty_markdown


def test_bug_bounty_markdown_includes_candidate_fields_and_redacts_secrets():
    case = AuditCase(
        case_id="case_x",
        case_type="idor_bola_possible",
        status="needs_review",
        review_priority="high",
        confidence=0.85,
        severity="high",
        file="app.py",
        line=10,
        rule_id="ACCESS_OBSERVATION",
        cwe="CWE-639",
        source="current_user",
        sink="invoice.read",
        missing_guarantees=("owner_or_tenant_scoped_lookup",),
        human_next_steps=("Create or identify the object as User A.",),
        reason="Authorization: Bearer should-not-leak",
        metadata={
            "title": "Candidate object authorization gap",
            "source_tools": ["belief-access-model"],
            "tool_evidence": ["Authorization: Bearer should-not-leak"],
            "reportability": {
                "score": 75,
                "verdict": "needs_manual_validation",
                "confidence": "medium",
                "positive_factors": ["access observation present"],
                "negative_factors": [],
                "missing_evidence": ["manual validation"],
                "validation_steps": ["Create or identify the object as User A."],
            },
        },
    )

    report = render_bug_bounty_markdown([case], target="/tmp/app")

    assert "# BELIEF Bug Bounty Candidate Report" in report
    assert "needs_manual_validation" in report
    assert "75/100" in report
    assert "should-not-leak" not in report
    assert "Manual validation in authorized scope is required" in report
