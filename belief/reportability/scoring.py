"""Conservative reportability scoring for BELIEF audit cases."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from belief.audit_case import AuditCase, sort_audit_cases

from .models import ReportabilityAssessment


_HIGH_IMPACT_TOKENS = {
    "command",
    "deserialization",
    "path_traversal",
    "idor",
    "bola",
    "authz",
    "authorization",
    "access_control",
    "ssrf",
}
_SENSITIVE_OBJECTS = {
    "account",
    "admin",
    "document",
    "file",
    "invoice",
    "order",
    "organization",
    "payment",
    "permission",
    "project",
    "role",
    "secret",
    "subscription",
    "tenant",
    "token",
    "user",
}


def assess_audit_case_reportability(case: AuditCase) -> ReportabilityAssessment:
    """Assess whether an audit case is ready for human report drafting."""
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    positive: list[str] = []
    negative: list[str] = []
    missing_evidence: list[str] = []
    validation_steps = list(case.human_next_steps)
    score = 0

    source_tools = sorted({str(tool) for tool in _as_list(metadata.get("source_tools")) if str(tool)})
    signal_type = str(metadata.get("tool_signal_type") or "")
    category_text = " ".join([
        str(metadata.get("category") or ""),
        str(case.case_type or ""),
        str(case.cwe or ""),
    ]).lower()

    if signal_type == "external_finding" or source_tools:
        score += 10
        positive.append("external finding present")
    if len(source_tools) > 1:
        score += 15
        positive.append("multiple external tools agree")
    if metadata.get("has_codeflow") or _has_codeflow(metadata):
        score += 20
        positive.append("CodeQL/SARIF code-flow evidence present")
    if case.route_context or metadata.get("route") or metadata.get("path"):
        score += 15
        positive.append("route context present")
    if signal_type == "access_observation":
        score += 25
        positive.append("access observation present")
    if signal_type == "attack_path":
        score += 25
        positive.append("attack path present")
    if _missing_owner_tenant_guard(case, metadata):
        score += 25
        positive.append("missing owner/tenant guard")
    if bool(metadata.get("mutation")):
        score += 15
        positive.append("state mutation detected")
    if _sensitive_object(metadata):
        score += 15
        positive.append("sensitive object detected")
    if validation_steps:
        score += 10
        positive.append("validation steps available")
    if _high_impact(category_text):
        score += 15
        positive.append("high-impact CWE/category")

    strong_guard = _strong_guard(case, metadata)
    contradictory_evidence = bool(case.missing_guarantees or metadata.get("missing_guards"))
    if strong_guard:
        score -= 40
        negative.append("strong owner/tenant guard detected")
    if _admin_guard_for_admin_action(case, metadata):
        score -= 25
        negative.append("admin-only guard for admin action")
    if _test_generated_or_vendor_path(case.file):
        score -= 20
        negative.append("test, fixture, generated, or vendor path")
    if not (case.route_context or case.dataflow_path or signal_type == "access_observation"):
        score -= 20
        negative.append("no route, source-to-sink path, or access observation")
    if signal_type == "external_finding" and not case.dataflow_path and len(source_tools) <= 1:
        score -= 15
        negative.append("weak generic static-only signal")
    if str(case.severity or "").lower() in {"low", "info"}:
        score -= 10
        negative.append("severity is low/info")

    if not case.route_context and not metadata.get("route") and not metadata.get("path"):
        missing_evidence.append("affected route or endpoint")
    if not case.dataflow_path and signal_type != "access_observation":
        missing_evidence.append("source-to-sink evidence")
    if case.missing_guarantees:
        missing_evidence.extend(f"proof for {item}" for item in case.missing_guarantees)
    elif not strong_guard and signal_type != "attack_path":
        missing_evidence.append("existing guard or sanitizer proof")

    score = max(0, min(100, int(score)))
    if strong_guard and not contradictory_evidence:
        verdict = "protected_by_guard"
    elif score >= 80:
        verdict = "reportable_candidate"
    elif score >= 50:
        verdict = "needs_manual_validation"
    elif score >= 20:
        verdict = "weak_signal"
    else:
        verdict = "likely_false_positive"

    confidence = _confidence(
        source_tools=source_tools,
        signal_type=signal_type,
        has_route=bool(case.route_context or metadata.get("route") or metadata.get("path")),
        has_path=bool(case.dataflow_path),
        validation_steps=bool(validation_steps),
    )
    return ReportabilityAssessment(
        score=score,
        verdict=verdict,
        confidence=confidence,
        positive_factors=_dedupe(positive),
        negative_factors=_dedupe(negative),
        missing_evidence=_dedupe(missing_evidence),
        validation_steps=_dedupe(validation_steps),
    )


def assess_many(cases: Iterable[AuditCase]) -> list[tuple[AuditCase, ReportabilityAssessment]]:
    """Assess many cases in deterministic order."""
    return [
        (case, assess_audit_case_reportability(case))
        for case in sort_audit_cases(cases)
    ]


def attach_reportability_to_cases(cases: Iterable[AuditCase]) -> list[AuditCase]:
    """Return cases with reportability metadata attached."""
    enriched = []
    for case, assessment in assess_many(cases):
        metadata = dict(case.metadata or {})
        metadata["reportability"] = assessment.to_dict()
        enriched.append(replace(case, metadata=metadata))
    return sort_audit_cases(enriched)


def _confidence(
    *,
    source_tools: list[str],
    signal_type: str,
    has_route: bool,
    has_path: bool,
    validation_steps: bool,
) -> str:
    if len(source_tools) > 1 or signal_type in {"access_observation", "attack_path"} and has_route:
        return "high"
    if (source_tools or signal_type) and validation_steps and (has_route or has_path):
        return "medium"
    return "low"


def _missing_owner_tenant_guard(case: AuditCase, metadata: dict[str, Any]) -> bool:
    text = " ".join([
        " ".join(case.missing_guarantees),
        " ".join(str(item) for item in _as_list(metadata.get("missing_guards"))),
    ]).lower()
    return any(token in text for token in ("owner", "tenant", "authorization", "scoped"))


def _strong_guard(case: AuditCase, metadata: dict[str, Any]) -> bool:
    if bool(metadata.get("strong_guard")):
        return True
    text = " ".join([
        " ".join(case.guarantees),
        " ".join(str(item) for item in _as_list(metadata.get("detected_guards"))),
        " ".join(str(item) for item in _as_list((case.route_context or {}).get("auth_guarantees"))),
    ]).lower()
    return any(token in text for token in (
        "owner",
        "tenant",
        "filter_by",
        "current_user.id",
        "current_user.tenant_id",
        "admin_required",
        "permission",
        "route.requires_login == true",
    ))


def _admin_guard_for_admin_action(case: AuditCase, metadata: dict[str, Any]) -> bool:
    text = " ".join([
        str(metadata.get("action") or ""),
        str(case.sink or ""),
        " ".join(case.guarantees),
        " ".join(str(item) for item in _as_list(metadata.get("detected_guards"))),
    ]).lower()
    return "admin" in text and any(token in text for token in ("delete", "promote", "role", "permission"))


def _test_generated_or_vendor_path(path: str) -> bool:
    text = str(path or "").replace("\\", "/").lower()
    parts = set(text.split("/"))
    return bool(parts & {"tests", "test", "fixtures", "fixture", "vendor", "generated", "examples"})


def _has_codeflow(metadata: dict[str, Any]) -> bool:
    if "codeql" in {str(tool).lower() for tool in _as_list(metadata.get("source_tools"))}:
        evidence = " ".join(str(item) for item in _as_list(metadata.get("tool_evidence"))).lower()
        return bool(evidence)
    raw = str(metadata.get("external_raw") or "").lower()
    return "codeflow" in raw or "threadflow" in raw


def _sensitive_object(metadata: dict[str, Any]) -> bool:
    obj = str(metadata.get("object_type") or metadata.get("object_id_source") or "").lower()
    return any(token in obj for token in _SENSITIVE_OBJECTS)


def _high_impact(text: str) -> bool:
    return any(token in text for token in _HIGH_IMPACT_TOKENS)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "") else [value])


def _dedupe(values: Iterable[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


__all__ = [
    "assess_audit_case_reportability",
    "assess_many",
    "attach_reportability_to_cases",
]
