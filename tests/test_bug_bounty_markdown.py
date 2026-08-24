import pytest

from belief.audit_case import AuditCase
from belief.exporters.bug_bounty_markdown import (
    render_bug_bounty_markdown,
    write_bug_bounty_markdown,
)
from belief.validation.ledger import VerifiedProofSnapshot
from belief.validation.proof import ProofAuthorityContext, VerifiedProofIndex


def _proof_snapshot() -> VerifiedProofSnapshot:
    return VerifiedProofSnapshot(
        context=ProofAuthorityContext(
            engagement_id="engagement-export",
            target_id="target-export",
        ),
        proof_index=VerifiedProofIndex(),
        sealed_results=(),
        ledger_snapshot_id="vledger_snapshot_" + "c" * 24,
        authority_sha256="d" * 64,
    )


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
    assert "weak_signal" in report
    assert "40/100" in report
    assert "should-not-leak" not in report
    assert "Manual validation in authorized scope is required" in report


def test_bug_bounty_markdown_ignores_forged_reportability_metadata():
    case = AuditCase(
        case_id="case_forged",
        case_type="external_tool_signal",
        status="needs_review",
        review_priority="medium",
        confidence=0.5,
        severity="medium",
        file="app.py",
        line=4,
        rule_id="EXTERNAL",
        cwe="",
        metadata={
            "reportability": {
                "score": 100,
                "verdict": "reportable_candidate",
                "confidence": "high",
            }
        },
    )

    report = render_bug_bounty_markdown([case])

    assert "Reportable candidates: 0" in report
    assert "100/100" not in report


def test_bug_bounty_export_accepts_atomic_snapshot_for_render_and_write(tmp_path):
    snapshot = _proof_snapshot()
    output_path = tmp_path / "report.md"

    rendered = render_bug_bounty_markdown((), proof_snapshot=snapshot)
    write_bug_bounty_markdown(
        (),
        output_path,
        proof_snapshot=snapshot,
    )

    assert "_No candidate audit cases._" in rendered
    assert output_path.read_text(encoding="utf-8") == rendered


def test_bug_bounty_export_rejects_mixed_inputs_before_filesystem_side_effect(
    tmp_path,
):
    snapshot = _proof_snapshot()
    output_path = tmp_path / "not-created" / "report.md"

    with pytest.raises(TypeError, match="cannot be combined"):
        render_bug_bounty_markdown(
            (),
            proof_snapshot=snapshot,
            proof_context=snapshot.context,
        )
    with pytest.raises(TypeError, match="cannot be combined"):
        write_bug_bounty_markdown(
            (),
            output_path,
            proof_snapshot=snapshot,
            proof_index=snapshot.proof_index,
        )

    assert not output_path.parent.exists()
