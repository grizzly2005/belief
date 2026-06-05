from belief.pdx.models import PDXVerdict
from belief.audit_case import AuditCase
from belief.reportability.scoring import assess_audit_case_reportability
from belief.validation.models import ValidationResult
from belief.validation.pdx import pdx_verdict_to_validation_result


def test_validation_result_round_trip():
    result = ValidationResult(
        subject_id="case-1",
        subject_kind="audit_case",
        source="unit",
        outcome="validated_candidate",
        confidence=0.7,
        tested=False,
        human_validated=True,
        reason="reviewed",
    )

    assert ValidationResult.from_dict(result.to_dict()).to_dict() == result.to_dict()


def test_pdx_vulnerable_untested_is_inconclusive_not_confirmed():
    verdict = PDXVerdict(delta_ref="delta-1", result="VULNERABLE", tested=False, human_validated=False)
    result = pdx_verdict_to_validation_result(verdict)

    assert result.outcome == "inconclusive"
    assert result.metadata["positive_evidence"] is True


def test_pdx_vulnerable_tested_maps_to_bypassed():
    verdict = PDXVerdict(delta_ref="delta-1", result="VULNERABLE", tested=True, human_validated=False)
    result = pdx_verdict_to_validation_result(verdict)

    assert result.outcome == "bypassed"


def test_pdx_not_vuln_tested_maps_to_enforced():
    verdict = PDXVerdict(delta_ref="delta-1", result="NOT_VULN", tested=True)
    result = pdx_verdict_to_validation_result(verdict)

    assert result.outcome == "enforced"


def test_untested_pdx_positive_evidence_is_conservative_in_reportability():
    validation = pdx_verdict_to_validation_result(
        PDXVerdict(delta_ref="delta-1", result="VULNERABLE", tested=False)
    )
    case = AuditCase(
        case_id="case-1",
        case_type="external_tool_signal",
        status="needs_review",
        review_priority="medium",
        confidence=0.5,
        severity="medium",
        file="app.py",
        line=1,
        rule_id="PDX_AUTH_BYPASS",
        cwe="CWE-862",
        metadata={
            "tool_signal_type": "external_finding",
            "source_tools": ["pdx"],
            "external_raw": {
                "pdx": {
                    "validation_results": [validation.to_dict()],
                }
            },
        },
    )

    assessment = assess_audit_case_reportability(case)

    assert "positive validation evidence remains inconclusive" in assessment.positive_factors
    assert "validated bypass evidence present" not in assessment.positive_factors


def test_positive_validation_evidence_does_not_match_arbitrary_metadata_text():
    case = AuditCase(
        case_id="case-1",
        case_type="external_tool_signal",
        status="needs_review",
        review_priority="medium",
        confidence=0.5,
        severity="medium",
        file="app.py",
        line=1,
        rule_id="PDX_AUTH_BYPASS",
        cwe="CWE-862",
        metadata={
            "tool_signal_type": "external_finding",
            "source_tools": ["pdx"],
            "external_raw": {
                "pdx": {
                    "validation_results": [
                        {
                            "outcome": "inconclusive",
                            "tested": False,
                            "human_validated": False,
                            "metadata": "contains vulnerable as plain text",
                        }
                    ],
                }
            },
        },
    )

    assessment = assess_audit_case_reportability(case)

    assert "positive validation evidence remains inconclusive" not in assessment.positive_factors
