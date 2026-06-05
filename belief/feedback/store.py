"""Append-only JSONL feedback store."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import FeedbackEvent


DEFAULT_FEEDBACK_DIR = Path("./belief_feedback")
FEEDBACK_FILE_NAME = "feedback.jsonl"


def feedback_store_path(store_dir: Path | str | None = None) -> Path:
    base = Path(store_dir) if store_dir else DEFAULT_FEEDBACK_DIR
    return base / FEEDBACK_FILE_NAME


def append_feedback_event(event: FeedbackEvent, store_dir: Path | str | None = None) -> Path:
    path = feedback_store_path(store_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
    return path


def load_feedback_events(store_dir: Path | str | None = None) -> list[FeedbackEvent]:
    path = feedback_store_path(store_dir)
    if not path.exists():
        return []
    events = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
            events.append(FeedbackEvent.from_dict(payload))
        except (json.JSONDecodeError, ValueError) as exc:
            raise ValueError(f"invalid feedback JSONL at {path}:{line_number}: {exc}") from exc
    return sorted(events, key=lambda item: (item.created_at, item.event_id))


def write_feedback_events(
    events: Iterable[FeedbackEvent],
    output_path: Path | str,
) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(event.to_dict(), sort_keys=True)
        for event in sorted(events, key=lambda item: (item.created_at, item.event_id))
    ]
    output.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


__all__ = [
    "DEFAULT_FEEDBACK_DIR",
    "FEEDBACK_FILE_NAME",
    "append_feedback_event",
    "feedback_store_path",
    "load_feedback_events",
    "write_feedback_events",
]
