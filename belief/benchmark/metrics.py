"""Deterministic metrics for offline BELIEF benchmarks."""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable


def compute_confusion_matrix(expected: Iterable[str], observed: Iterable[str]) -> dict[str, dict[str, int]]:
    """Count expected/observed verdict pairs in a stable nested dictionary."""

    expected_list = [str(item) for item in expected]
    observed_list = [str(item) for item in observed]
    if len(expected_list) != len(observed_list):
        raise ValueError("expected and observed verdict lists must have the same length")

    counts: dict[str, Counter[str]] = defaultdict(Counter)
    for expected_verdict, observed_verdict in zip(expected_list, observed_list):
        counts[expected_verdict][observed_verdict] += 1

    return {
        expected_key: dict(sorted(observed_counts.items()))
        for expected_key, observed_counts in sorted(counts.items())
    }


def summarize_reportability_metrics(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Summarize reportability benchmark rows without treating static evidence as confirmation."""

    total = len(results)
    if total == 0:
        return {
            "matched_cases": 0,
            "reportable_candidate_rate": 0,
            "protected_by_guard_rate": 0,
            "false_reportable_candidate_rate": 0,
            "weak_signal_rate": 0,
            "playbook_coverage": 0,
            "missing_evidence_coverage": 0,
        }

    observed = [str(case.get("observed_verdict", "")) for case in results]
    matched = sum(1 for case in results if case.get("expected_verdict") == case.get("observed_verdict"))
    false_reportable = sum(
        1
        for case in results
        if case.get("expected_verdict") in {"protected_by_guard", "likely_false_positive"}
        and case.get("observed_verdict") == "reportable_candidate"
    )
    with_playbook = sum(1 for case in results if case.get("expected_playbook"))
    with_missing_evidence = sum(
        1
        for case in results
        if isinstance(case.get("expected_missing_evidence"), list)
        and len(case.get("expected_missing_evidence") or []) > 0
    )

    return {
        "matched_cases": matched,
        "reportable_candidate_rate": _rate(observed.count("reportable_candidate"), total),
        "protected_by_guard_rate": _rate(observed.count("protected_by_guard"), total),
        "false_reportable_candidate_rate": _rate(false_reportable, total),
        "weak_signal_rate": _rate(observed.count("weak_signal"), total),
        "playbook_coverage": _rate(with_playbook, total),
        "missing_evidence_coverage": _rate(with_missing_evidence, total),
    }


def _rate(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0


__all__ = [
    "compute_confusion_matrix",
    "summarize_reportability_metrics",
]
