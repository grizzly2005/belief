import json
import subprocess
import sys
from pathlib import Path

from belief.feedback.apply import apply_feedback_to_audit_report, feedback_events_for_case
from belief.feedback.models import FeedbackEvent
from belief.feedback.store import append_feedback_event
from belief.reasoning.router import reason_audit_report


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def _report():
    return json.loads((FIXTURES / "audit_reportability_sample.json").read_text(encoding="utf-8"))


def _event(case_id: str, verdict: str) -> FeedbackEvent:
    return FeedbackEvent(
        case_id=case_id,
        verdict=verdict,
        reason=f"{verdict} test",
        created_at="2026-01-01T00:00:00+00:00",
    )


def _case_metadata(report: dict):
    return report["audit_cases"][0]["metadata"]


def test_feedback_events_for_case_exact_matching_only():
    events = [
        _event("case-auth-1", "false_positive"),
        _event("case-auth-10", "protected"),
    ]

    matched = feedback_events_for_case(events, "case-auth-1")

    assert len(matched) == 1
    assert matched[0]["case_id"] == "case-auth-1"


def test_false_positive_feedback_attaches_adjustment():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "false_positive")])
    metadata = _case_metadata(adjusted)

    assert metadata["feedback_adjustment"]["recommendation"] == "likely_false_positive"
    assert metadata["feedback_adjustment"]["reportability_effect"] == "lower"
    assert "human feedback marked false positive" in metadata["feedback_adjustment"]["negative_factors"]
    assert metadata["feedback_events"][0]["verdict"] == "false_positive"


def test_protected_feedback_attaches_protected_by_guard_adjustment():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "protected")])

    assert _case_metadata(adjusted)["feedback_adjustment"]["recommendation"] == "protected_by_guard"


def test_unrelated_feedback_does_not_modify_unrelated_case():
    original = _report()
    adjusted = apply_feedback_to_audit_report(original, [_event("other-case", "false_positive")])

    assert adjusted["audit_cases"] == original["audit_cases"]
    assert adjusted["feedback_application"]["matched_cases"] == 0


def test_out_of_scope_feedback_marks_metadata_flag():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "out_of_scope")])
    metadata = _case_metadata(adjusted)

    assert metadata["feedback_adjustment"]["recommendation"] == "lower_confidence"
    assert metadata["feedback_adjustment"]["reportability_effect"] == "out_of_scope"
    assert metadata["out_of_scope"] is True


def test_duplicate_feedback_marks_metadata_flag():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "duplicate")])
    metadata = _case_metadata(adjusted)

    assert metadata["feedback_adjustment"]["recommendation"] == "lower_confidence"
    assert metadata["feedback_adjustment"]["reportability_effect"] == "duplicate"
    assert metadata["duplicate"] is True


def test_feedback_apply_cli_works_with_temp_store(tmp_path):
    store_dir = tmp_path / "feedback"
    audit_output = tmp_path / "audit.feedback.json"
    append_feedback_event(_event("case-auth-1", "false_positive"), store_dir)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "feedback",
            "apply",
            "--audit",
            str(FIXTURES / "audit_reportability_sample.json"),
            "--store-dir",
            str(store_dir),
            "--output",
            str(audit_output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    adjusted = json.loads(audit_output.read_text(encoding="utf-8"))
    assert summary["matched_cases"] == 1
    assert _case_metadata(adjusted)["feedback_adjustment"]["recommendation"] == "likely_false_positive"


def test_feedback_apply_false_positive_then_reason_likely_false_positive():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "false_positive")])
    reasoned = reason_audit_report(adjusted)

    assert reasoned["reasoning"][0]["recommendation"] == "likely_false_positive"


def test_feedback_apply_protected_then_reason_protected_by_guard():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "protected")])
    reasoned = reason_audit_report(adjusted)

    assert reasoned["reasoning"][0]["recommendation"] == "protected_by_guard"


def test_feedback_apply_needs_more_evidence_then_reason_request_more_evidence():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "needs_more_evidence")])
    reasoned = reason_audit_report(adjusted)

    assert reasoned["reasoning"][0]["recommendation"] == "request_more_evidence"


def test_feedback_apply_out_of_scope_then_reason_lower_confidence():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "out_of_scope")])
    reasoned = reason_audit_report(adjusted)

    assert reasoned["reasoning"][0]["recommendation"] == "lower_confidence"


def test_feedback_apply_duplicate_then_reason_lower_confidence():
    adjusted = apply_feedback_to_audit_report(_report(), [_event("case-auth-1", "duplicate")])
    reasoned = reason_audit_report(adjusted)

    assert reasoned["reasoning"][0]["recommendation"] == "lower_confidence"
