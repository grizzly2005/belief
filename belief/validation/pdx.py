"""Adapt PDX verdicts into generic BELIEF ValidationResult objects."""

from __future__ import annotations

from typing import Iterable

from belief.pdx.models import PDXVerdict

from .models import ValidationResult


def pdx_verdict_to_validation_result(verdict: PDXVerdict) -> ValidationResult:
    result = (verdict.result or "UNCERTAIN").upper()
    tested = bool(verdict.tested)
    human_validated = bool(verdict.human_validated)

    if result == "VULNERABLE":
        if tested:
            outcome = "bypassed"
        elif human_validated:
            outcome = "validated_candidate"
        else:
            outcome = "inconclusive"
    elif result == "NOT_VULN":
        outcome = "enforced" if tested or human_validated else "inconclusive"
    elif result == "FALSE_POS":
        outcome = "false_positive" if tested or human_validated else "inconclusive"
    elif result == "INFORMATIONAL":
        outcome = "informational"
    else:
        outcome = "inconclusive"

    evidence = []
    if verdict.method:
        evidence.append(f"method: {verdict.method}")
    if verdict.reason:
        evidence.append(verdict.reason)
    evidence.extend(verdict.conditions_stack)
    evidence.extend(f"correction: {item}" for item in verdict.corrections)

    return ValidationResult(
        subject_id=verdict.delta_ref,
        subject_kind="pdx_delta",
        source="pdx",
        outcome=outcome,
        confidence=verdict.weight,
        tested=tested,
        human_validated=human_validated,
        method=verdict.method,
        reason=verdict.reason,
        evidence=tuple(evidence),
        metadata={
            "pdx_result": result,
            "train_positive": bool(verdict.train_positive),
            "train_negative": bool(verdict.train_negative),
            "human_agreement": verdict.human_agreement,
            "original_result": verdict.original_result,
            "positive_evidence": result == "VULNERABLE",
        },
    )


def pdx_verdicts_to_validation_results(verdicts: Iterable[PDXVerdict]) -> list[ValidationResult]:
    return sorted(
        [pdx_verdict_to_validation_result(verdict) for verdict in verdicts],
        key=lambda item: (item.subject_id, item.outcome, item.result_id),
    )


__all__ = [
    "pdx_verdict_to_validation_result",
    "pdx_verdicts_to_validation_results",
]
