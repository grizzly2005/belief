"""Conservative exact-match feedback application for BELIEF audit reports."""

from __future__ import annotations

import copy
from typing import Any, Iterable

from .models import FeedbackEvent


FEEDBACK_APPLICATION_SCHEMA_VERSION = "belief.feedback_application.v1"


def feedback_events_for_case(
    events: Iterable[FeedbackEvent | dict[str, Any]],
    case_id: str,
) -> list[dict[str, Any]]:
    """Return feedback events whose case_id exactly matches the audit case."""
    target = str(case_id or "")
    matched = []
    for event in events:
        payload = event.to_dict() if isinstance(event, FeedbackEvent) else event
        if not isinstance(payload, dict):
            continue
        if str(payload.get("case_id") or "") != target:
            continue
        matched.append(_safe_event(payload))
    return sorted(
        matched,
        key=lambda item: (
            str(item.get("created_at") or ""),
            str(item.get("event_id") or ""),
            str(item.get("verdict") or ""),
        ),
    )


def apply_feedback_to_audit_report(
    report: dict[str, Any],
    events: Iterable[FeedbackEvent | dict[str, Any]],
) -> dict[str, Any]:
    """Attach exact-case feedback metadata to a BELIEF audit JSON payload."""
    if not isinstance(report, dict):
        raise ValueError("audit report must be a JSON object")
    audit_cases = report.get("audit_cases")
    if not isinstance(audit_cases, list):
        raise ValueError("audit report is missing audit_cases list")

    event_list = list(events)
    output = copy.deepcopy(report)
    adjusted_cases = []
    matched_case_count = 0
    matched_event_count = 0

    for raw_case in audit_cases:
        if not isinstance(raw_case, dict):
            adjusted_cases.append(copy.deepcopy(raw_case))
            continue
        case = copy.deepcopy(raw_case)
        case_id = str(case.get("case_id") or "")
        matched = feedback_events_for_case(event_list, case_id)
        if not matched:
            adjusted_cases.append(case)
            continue

        matched_case_count += 1
        matched_event_count += len(matched)
        metadata = case.get("metadata") if isinstance(case.get("metadata"), dict) else {}
        metadata = dict(metadata)
        metadata["feedback_events"] = matched
        adjustment = _feedback_adjustment(matched)
        metadata["feedback_adjustment"] = adjustment
        if adjustment.get("reportability_effect") == "out_of_scope":
            metadata["out_of_scope"] = True
        if adjustment.get("reportability_effect") == "duplicate":
            metadata["duplicate"] = True
        case["metadata"] = metadata
        adjusted_cases.append(case)

    output["audit_cases"] = adjusted_cases
    output["feedback_application"] = {
        "schema_version": FEEDBACK_APPLICATION_SCHEMA_VERSION,
        "feedback_events": len(event_list),
        "matched_events": matched_event_count,
        "matched_cases": matched_case_count,
    }
    return output


def _feedback_adjustment(events: list[dict[str, Any]]) -> dict[str, Any]:
    verdicts = {_normalize_verdict(event.get("verdict")) for event in events}
    event_ids = [str(event.get("event_id") or "") for event in events if str(event.get("event_id") or "")]

    if "false_positive" in verdicts:
        return _adjustment(
            recommendation="likely_false_positive",
            reportability_effect="lower",
            event_ids=event_ids,
            negative_factors=("human feedback marked false positive",),
        )
    if "protected" in verdicts:
        return _adjustment(
            recommendation="protected_by_guard",
            reportability_effect="lower",
            event_ids=event_ids,
            negative_factors=("human feedback indicates protection or guard",),
        )
    if verdicts & {"true_positive", "valid", "accepted_report"}:
        return _adjustment(
            recommendation="keep",
            reportability_effect="modest_support",
            event_ids=event_ids,
            positive_factors=("human feedback supports candidate",),
        )
    if "needs_more_evidence" in verdicts:
        return _adjustment(
            recommendation="request_more_evidence",
            reportability_effect="needs_evidence",
            event_ids=event_ids,
            missing_evidence=("human requested additional evidence",),
        )
    if "out_of_scope" in verdicts:
        return _adjustment(
            recommendation="lower_confidence",
            reportability_effect="out_of_scope",
            event_ids=event_ids,
        )
    if "duplicate" in verdicts:
        return _adjustment(
            recommendation="lower_confidence",
            reportability_effect="duplicate",
            event_ids=event_ids,
        )
    return _adjustment(
        recommendation="keep",
        reportability_effect="none",
        event_ids=event_ids,
    )


def _adjustment(
    *,
    recommendation: str,
    reportability_effect: str,
    event_ids: list[str],
    positive_factors: tuple[str, ...] = (),
    negative_factors: tuple[str, ...] = (),
    missing_evidence: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "schema_version": FEEDBACK_APPLICATION_SCHEMA_VERSION,
        "recommendation": recommendation,
        "reportability_effect": reportability_effect,
        "positive_factors": list(positive_factors),
        "negative_factors": list(negative_factors),
        "missing_evidence": list(missing_evidence),
        "matched_event_ids": event_ids,
    }


def _normalize_verdict(value: Any) -> str:
    text = str(value or "").strip().lower().replace("-", "_")
    aliases = {
        "fp": "false_positive",
        "false_positive": "false_positive",
        "protected": "protected",
        "protected_by_guard": "protected",
        "true_positive": "true_positive",
        "valid": "valid",
        "accepted_report": "accepted_report",
        "needs_more_evidence": "needs_more_evidence",
        "more_evidence": "needs_more_evidence",
        "out_of_scope": "out_of_scope",
        "duplicate": "duplicate",
        "dupe": "duplicate",
    }
    return aliases.get(text, text)


def _safe_event(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        str(key): value
        for key, value in sorted(payload.items(), key=lambda item: str(item[0]))
        if key in {
            "schema_version",
            "event_id",
            "case_id",
            "verdict",
            "reason",
            "source",
            "created_at",
            "metadata",
        }
    }


__all__ = [
    "FEEDBACK_APPLICATION_SCHEMA_VERSION",
    "apply_feedback_to_audit_report",
    "feedback_events_for_case",
]
