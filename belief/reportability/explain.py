"""Small helpers for reportability explanations."""

from __future__ import annotations

from .models import ReportabilityAssessment


def summarize_assessment(assessment: ReportabilityAssessment) -> str:
    return (
        f"{assessment.verdict} "
        f"score={assessment.score}/100 confidence={assessment.confidence}"
    )


__all__ = ["summarize_assessment"]
