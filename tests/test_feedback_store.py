from belief.feedback.models import FeedbackEvent
from belief.feedback.store import append_feedback_event, load_feedback_events, write_feedback_events


def test_feedback_store_append_load_export(tmp_path):
    event = FeedbackEvent(
        case_id="case-1",
        verdict="false_positive",
        reason="owner guard present",
        created_at="2026-01-01T00:00:00+00:00",
    )

    append_feedback_event(event, tmp_path)
    loaded = load_feedback_events(tmp_path)

    assert [item.to_dict() for item in loaded] == [event.to_dict()]

    output = tmp_path / "export.jsonl"
    write_feedback_events(loaded, output)
    assert event.event_id in output.read_text(encoding="utf-8")
