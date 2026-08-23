"""Deterministic offline reasoning engine for BELIEF audit cases."""

from __future__ import annotations

from typing import Any

from .models import ReasoningRequest, ReasoningResponse
from .prompts import OFFLINE_REASONING_SAFETY_NOTE, SAFE_REVIEW_LANGUAGE


class OfflineReasoningEngine:
    """Rule-based local engine. It never calls models, browsers, or networks."""

    name = "offline"

    def analyze(self, request: ReasoningRequest) -> ReasoningResponse:
        feedback_verdicts = _verdicts(request.feedback_events)
        validations = list(request.validation_results)

        if "false_positive" in feedback_verdicts:
            return _response(
                request,
                "likely_false_positive",
                "Human feedback marks this candidate as likely false positive.",
                confidence=0.85,
            )
        if "protected" in feedback_verdicts:
            return _response(
                request,
                "protected_by_guard",
                "Human feedback says the candidate is protected by guard evidence.",
                confidence=0.85,
            )
        if "needs_more_evidence" in feedback_verdicts:
            return _response(
                request,
                "request_more_evidence",
                "Human feedback requests more evidence before reporting.",
                missing=request.missing_evidence or ("additional validation evidence",),
                steps=request.validation_steps,
                confidence=0.7,
            )
        if "out_of_scope" in feedback_verdicts:
            return _response(
                request,
                "lower_confidence",
                "Human feedback marks this candidate as out of scope.",
                confidence=0.75,
            )
        if "duplicate" in feedback_verdicts:
            return _response(
                request,
                "lower_confidence",
                "Human feedback marks this candidate as duplicate.",
                confidence=0.75,
            )
        if _has_inconclusive_positive_evidence(validations):
            return _response(
                request,
                "needs_manual_validation",
                "Positive validation evidence is still inconclusive and needs manual validation.",
                missing=request.missing_evidence or ("manual validation result",),
                steps=request.validation_steps,
                confidence=0.65,
            )
        if request.missing_evidence:
            return _response(
                request,
                "request_more_evidence",
                "Required evidence is still missing before this candidate can be reported.",
                missing=request.missing_evidence,
                steps=request.validation_steps,
                confidence=0.6,
            )
        return _response(
            request,
            "keep",
            "No conservative offline rule changed the existing candidate classification.",
            steps=request.validation_steps,
            confidence=max(0.1, min(float(request.confidence), 0.7)),
        )


def _response(
    request: ReasoningRequest,
    recommendation: str,
    rationale: str,
    *,
    missing: tuple[str, ...] = (),
    steps: tuple[str, ...] = (),
    confidence: float,
) -> ReasoningResponse:
    return ReasoningResponse(
        case_id=request.case_id,
        recommendation=recommendation,  # type: ignore[arg-type]
        rationale_summary=rationale,
        suggested_missing_evidence=tuple(_dedupe(missing)),
        suggested_validation_steps=tuple(_dedupe(steps)),
        confidence=confidence,
        source_engine="offline",
        safety_notes=(OFFLINE_REASONING_SAFETY_NOTE, SAFE_REVIEW_LANGUAGE),
    )


def _verdicts(events: tuple[dict[str, Any], ...]) -> set[str]:
    aliases = {
        "fp": "false_positive",
        "false-positive": "false_positive",
        "false_positive": "false_positive",
        "protected": "protected",
        "protected_by_guard": "protected",
        "needs_more_evidence": "needs_more_evidence",
        "more_evidence": "needs_more_evidence",
        "out_of_scope": "out_of_scope",
        "out-of-scope": "out_of_scope",
        "duplicate": "duplicate",
        "dupe": "duplicate",
    }
    return {
        aliases.get(str(event.get("verdict") or "").strip().lower(), str(event.get("verdict") or "").strip().lower())
        for event in events
        if isinstance(event, dict)
    }


def _has_inconclusive_positive_evidence(validations: list[dict[str, Any]]) -> bool:
    for result in validations:
        if str(result.get("outcome") or "").lower() != "inconclusive":
            continue
        metadata = result.get("metadata")
        if isinstance(metadata, dict) and metadata.get("positive_evidence") is True:
            return True
    return False


def _dedupe(values: tuple[str, ...]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


__all__ = ["OfflineReasoningEngine"]
