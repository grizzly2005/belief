"""Adapt PDX verdicts into generic BELIEF ValidationResult objects."""

from __future__ import annotations

from typing import Iterable

from belief.pdx.models import PDXVerdict

from .models import ValidationResult


def pdx_verdict_to_validation_result(verdict: PDXVerdict) -> ValidationResult:
    result = (verdict.result or "UNCERTAIN").upper()
    source_tested = bool(verdict.tested)
    source_human_validated = bool(verdict.human_validated)

    # A legacy belief.pdx.v1 bundle has no joinable BELIEF Attempt, Result, or
    # Evidence references.  Producer booleans are retained as source assertions
    # but cannot be promoted into BELIEF proof state.
    outcome = "informational" if result == "INFORMATIONAL" else "inconclusive"

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
        confidence=min(verdict.weight, 0.5),
        tested=False,
        human_validated=False,
        method=verdict.method,
        reason=verdict.reason,
        evidence=tuple(evidence),
        metadata={
            "pdx_result": result,
            "train_positive": bool(verdict.train_positive),
            "train_negative": bool(verdict.train_negative),
            "human_agreement": verdict.human_agreement,
            "original_result": verdict.original_result,
            "source_tested": source_tested,
            "source_human_validated": source_human_validated,
            "positive_signal": result == "VULNERABLE",
            "positive_evidence": False,
            "proof_state": "missing_belief_attempt_result_evidence",
            "missing_proof_references": ["attempt_id", "result_id", "evidence_refs"],
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
