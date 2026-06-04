"""Normalization helpers from external tool shapes to BELIEF models."""

from __future__ import annotations

from .schemas import ExternalFinding
from ..models import Finding


def external_finding_to_finding(external: ExternalFinding) -> Finding:
    """Convert one normalized external finding into BELIEF's stable Finding."""
    cwe = external.cwe[0] if external.cwe else ""
    metadata = {
        "external_tool_id": external.tool_id,
        "external_rule_id": external.rule_id,
        "external_confidence": external.confidence,
        "external_raw": external.raw,
    }
    if external.route:
        metadata["route"] = external.route
    return Finding(
        source=f"tool:{external.tool_id}",
        rule_id=external.rule_id or "",
        title=external.title,
        description=external.message or external.title,
        file=external.file or "",
        line=external.line,
        end_line=external.end_line,
        cwe=cwe,
        severity=(external.severity or "info").lower(),
        confidence=_confidence(external.confidence, external.severity),
        evidence="\n".join(external.evidence),
        metadata=metadata,
    )


def _confidence(confidence: str | None, severity: str | None) -> float:
    text = str(confidence or severity or "").lower()
    if text in {"very_high", "high", "error"}:
        return 0.85
    if text in {"medium", "warning"}:
        return 0.65
    if text in {"low", "note", "info"}:
        return 0.35
    return 0.5


__all__ = ["external_finding_to_finding"]
