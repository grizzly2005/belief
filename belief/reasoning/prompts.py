"""Static safety text for offline BELIEF reasoning outputs."""

OFFLINE_REASONING_SAFETY_NOTE = (
    "Offline deterministic rules only; no network, no LLM, no active validation."
)

SAFE_REVIEW_LANGUAGE = (
    "Use candidate, hypothesis, needs manual validation, protected by guard, "
    "likely false positive, and inconclusive language."
)

__all__ = ["OFFLINE_REASONING_SAFETY_NOTE", "SAFE_REVIEW_LANGUAGE"]
