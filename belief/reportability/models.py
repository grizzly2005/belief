"""Reportability model for BELIEF audit candidates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .guards import GuardBlocker


ReportabilityVerdict = Literal[
    "reportable_candidate",
    "needs_manual_validation",
    "weak_signal",
    "likely_false_positive",
    "protected_by_guard",
]


ReportabilityConfidence = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ReportabilityAssessment:
    score: int
    verdict: ReportabilityVerdict
    confidence: ReportabilityConfidence
    positive_factors: list[str] = field(default_factory=list)
    negative_factors: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    guard_applicability: list[dict] = field(default_factory=list)
    blockers: list[GuardBlocker] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": int(self.score),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "positive_factors": list(self.positive_factors),
            "negative_factors": list(self.negative_factors),
            "missing_evidence": list(self.missing_evidence),
            "validation_steps": list(self.validation_steps),
            "guard_applicability": [dict(item) for item in self.guard_applicability],
            "blockers": list(self.blockers),
        }


__all__ = [
    "ReportabilityAssessment",
    "ReportabilityConfidence",
    "ReportabilityVerdict",
]
