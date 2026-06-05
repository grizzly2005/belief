import pytest

from belief.reasoning.models import ReasoningRequest, ReasoningResponse


def test_reasoning_request_round_trip():
    request = ReasoningRequest(
        case_id="case-1",
        title="candidate",
        case_type="idor_bola_possible",
        severity="high",
        confidence=0.7,
        evidence=("source", "sink"),
        positive_factors=("external finding present",),
        negative_factors=("weak static signal",),
        missing_evidence=("dynamic validation",),
        validation_steps=("review in authorized scope",),
        validation_results=({"outcome": "inconclusive"},),
        feedback_events=({"verdict": "needs_more_evidence"},),
        metadata={"reportability": {"verdict": "needs_manual_validation"}},
    )

    assert ReasoningRequest.from_dict(request.to_dict()).to_dict() == request.to_dict()


def test_reasoning_response_round_trip():
    response = ReasoningResponse(
        case_id="case-1",
        recommendation="needs_manual_validation",
        rationale_summary="Candidate needs manual validation.",
        suggested_missing_evidence=("dynamic validation",),
        suggested_validation_steps=("review in authorized scope",),
        confidence=0.6,
        source_engine="offline",
        safety_notes=("Offline deterministic rules only.",),
    )

    assert ReasoningResponse.from_dict(response.to_dict()).to_dict() == response.to_dict()
    assert "chain" not in response.to_dict()


def test_reasoning_response_rejects_unknown_recommendation():
    with pytest.raises(ValueError):
        ReasoningResponse(
            case_id="case-1",
            recommendation="confirmed_exploit",  # type: ignore[arg-type]
            rationale_summary="bad",
        )
