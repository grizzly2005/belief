from belief.reasoning.models import ReasoningRequest
from belief.reasoning.offline import OfflineReasoningEngine
from belief.reasoning.router import reason_audit_report


def test_offline_engine_is_deterministic():
    request = ReasoningRequest(
        case_id="case-1",
        missing_evidence=("dynamic validation",),
        validation_steps=("review in authorized scope",),
    )
    engine = OfflineReasoningEngine()

    assert engine.analyze(request).to_dict() == engine.analyze(request).to_dict()


def test_offline_engine_likely_false_positive_from_feedback():
    request = ReasoningRequest(
        case_id="case-1",
        feedback_events=({"verdict": "false_positive", "reason": "owner guard present"},),
    )

    response = OfflineReasoningEngine().analyze(request)

    assert response.recommendation == "likely_false_positive"


def test_offline_engine_lower_confidence_from_out_of_scope_feedback():
    request = ReasoningRequest(
        case_id="case-1",
        feedback_events=({"verdict": "out_of_scope", "reason": "not in authorized scope"},),
    )

    response = OfflineReasoningEngine().analyze(request)

    assert response.recommendation == "lower_confidence"


def test_offline_engine_lower_confidence_from_duplicate_feedback():
    request = ReasoningRequest(
        case_id="case-1",
        feedback_events=({"verdict": "duplicate", "reason": "same as previous case"},),
    )

    response = OfflineReasoningEngine().analyze(request)

    assert response.recommendation == "lower_confidence"


def test_offline_engine_needs_manual_validation_for_inconclusive_pdx_evidence():
    request = ReasoningRequest(
        case_id="case-1",
        validation_results=(
            {
                "outcome": "inconclusive",
                "tested": False,
                "human_validated": False,
                "metadata": {"positive_evidence": True},
            },
        ),
    )

    response = OfflineReasoningEngine().analyze(request)

    assert response.recommendation == "needs_manual_validation"


def test_offline_engine_protected_by_guard_from_enforced_validation():
    request = ReasoningRequest(
        case_id="case-1",
        validation_results=(
            {
                "outcome": "enforced",
                "tested": True,
                "human_validated": False,
            },
        ),
    )

    response = OfflineReasoningEngine().analyze(request)

    assert response.recommendation == "protected_by_guard"


def test_reason_audit_report_stable_ordering():
    report = {
        "audit_cases": [
            {"case_id": "case-b", "case_type": "external", "confidence": 0.2, "metadata": {}},
            {"case_id": "case-a", "case_type": "external", "confidence": 0.2, "metadata": {}},
        ]
    }

    reasoned = reason_audit_report(report)

    assert [item["case_id"] for item in reasoned["reasoning"]] == ["case-a", "case-b"]
    assert reasoned == reason_audit_report(report)
