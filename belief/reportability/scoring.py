"""Conservative reportability scoring for BELIEF audit cases."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from belief.audit_case import AuditCase, sort_audit_cases

from .guards import GuardApplicability, blockers_for, evaluate_case_guards
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
    if _has_ordered_local_dataflow(case, metadata):
        score += 20
        positive.append("ordered local source-to-sink evidence present")
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

    validation_results = _validation_results(metadata)
    for result in validation_results:
        outcome = str(result.get("outcome") or "").lower()
        tested = bool(result.get("tested"))
        human_validated = bool(result.get("human_validated"))
        if outcome == "bypassed" and (tested or human_validated):
            score += 20
            positive.append("validated bypass evidence present")
        elif outcome == "validated_candidate" and (tested or human_validated):
            score += 10
            positive.append("human validation candidate present")
        elif outcome == "inconclusive" and _positive_validation_evidence(result):
            score += 5
            positive.append("positive validation evidence remains inconclusive")

    guard_results = evaluate_case_guards(case, metadata)
    guard_blockers = blockers_for(guard_results)
    strong_guard = _strong_guard(case, guard_results)
    contradictory_evidence = bool(metadata.get("missing_guards"))
    if strong_guard:
        score -= 40
        negative.append("causally applicable security guard detected")
    elif "authentication_only" in guard_blockers:
        negative.append("authentication present without resource authorization")
    if _admin_guard_for_admin_action(case, metadata, guard_results):
        score -= 25
        negative.append("admin-only guard for admin action")
    if _test_generated_or_vendor_path(case.file):
        score -= 20
        negative.append("test, fixture, generated, or vendor path")
    has_path = _case_has_dataflow(case, metadata)
    if not (case.route_context or has_path or signal_type == "access_observation"):
        score -= 20
        negative.append("no route, source-to-sink path, or access observation")
    if signal_type == "external_finding" and not has_path and len(source_tools) <= 1:
        score -= 15
        negative.append("weak generic static-only signal")
    if str(case.severity or "").lower() in {"low", "info"}:
        score -= 10
        negative.append("severity is low/info")
    for result in validation_results:
        outcome = str(result.get("outcome") or "").lower()
        tested = bool(result.get("tested"))
        human_validated = bool(result.get("human_validated"))
        if outcome == "enforced" and (tested or human_validated):
            score -= 25
            negative.append("validation indicates guard enforced")
        elif outcome == "false_positive" and (tested or human_validated):
            score -= 35
            negative.append("validation marked false positive")

    if _requires_manual_static_access_validation(
        case,
        source_tools=source_tools,
        signal_type=signal_type,
        validation_results=validation_results,
    ) and score >= 80:
        score = 79
        negative.append("static access-control flow requires manual authorization validation")

    if not case.route_context and not metadata.get("route") and not metadata.get("path"):
        missing_evidence.append("affected route or endpoint")
    if not has_path and signal_type != "access_observation":
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
        has_path=has_path,
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
        guard_applicability=[result.to_dict() for result in guard_results],
        blockers=list(guard_blockers),
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


def _strong_guard(case: AuditCase, results: Iterable[GuardApplicability]) -> bool:
    case_type = str(case.case_type or "").lower()
    for result in results:
        if not result.applicable:
            continue
        expression = result.expression.lower()
        if "path" in case_type:
            if result.category == "path_containment_guard":
                return True
            if result.category == "input_validation_guard" and any(
                token in expression for token in (
                    "matches_allowed_pattern",
                    "allowlist",
                    "server_generated",
                    "user_controlled == false",
                )
            ):
                return True
            if result.category == "sanitizer_guard" and "basename" in expression:
                return True
            continue
        if any(token in case_type for token in ("idor", "bola", "authorization", "access")):
            if result.category in {
                "role_authorization_guard",
                "ownership_guard",
                "tenant_guard",
                "resource_binding_guard",
            }:
                return True
            continue
        if any(token in case_type for token in ("xss", "html", "template")):
            if result.category == "sanitizer_guard" and "escape" in expression:
                return True
            continue
        return True
    return False


def _admin_guard_for_admin_action(
    case: AuditCase,
    metadata: dict[str, Any],
    guard_results: Iterable[GuardApplicability],
) -> bool:
    action = " ".join([
        str(metadata.get("action") or ""),
        str(case.sink or ""),
    ]).lower()
    privileged_action = any(
        token in action for token in ("admin", "delete", "promote", "role", "permission")
    )
    return privileged_action and any(
        result.applicable and result.category == "role_authorization_guard"
        for result in guard_results
    )


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


def _case_has_dataflow(case: AuditCase, metadata: dict[str, Any]) -> bool:
    if case.dataflow_path or _has_ordered_local_dataflow(case, metadata):
        return True
    dataflow = metadata.get("dataflow")
    return isinstance(dataflow, dict) and bool(
        dataflow.get("path") and dataflow.get("source") and dataflow.get("sink")
    )


def _has_ordered_local_dataflow(case: AuditCase, metadata: dict[str, Any]) -> bool:
    candidates = [
        getattr(case, "structured_dataflow", None),
        metadata.get("structured_dataflow"),
        metadata.get("dataflow_evidence"),
    ]
    for evidence in candidates:
        if not isinstance(evidence, dict):
            continue
        nodes = evidence.get("ordered_nodes")
        edges = evidence.get("ordered_edges")
        if not isinstance(nodes, list) or len(nodes) < 2:
            continue
        if (isinstance(edges, list) and edges) or (
            evidence.get("source") and evidence.get("sink")
        ):
            return True
    return False


def _sensitive_object(metadata: dict[str, Any]) -> bool:
    obj = str(metadata.get("object_type") or metadata.get("object_id_source") or "").lower()
    return any(token in obj for token in _SENSITIVE_OBJECTS)


def _high_impact(text: str) -> bool:
    return any(token in text for token in _HIGH_IMPACT_TOKENS)


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "") else [value])


def _validation_results(metadata: dict[str, Any]) -> list[dict[str, Any]]:
    values: list[Any] = []
    direct = metadata.get("validation_results")
    if isinstance(direct, list):
        values.extend(direct)
    external_raw = metadata.get("external_raw")
    if isinstance(external_raw, dict):
        nested = external_raw.get("validation_results")
        if isinstance(nested, list):
            values.extend(nested)
        pdx = external_raw.get("pdx")
        if isinstance(pdx, dict) and isinstance(pdx.get("validation_results"), list):
            values.extend(pdx["validation_results"])
    return [item for item in values if isinstance(item, dict)]


def _positive_validation_evidence(result: dict[str, Any]) -> bool:
    metadata = result.get("metadata")
    return isinstance(metadata, dict) and metadata.get("positive_evidence") is True


def _requires_manual_static_access_validation(
    case: AuditCase,
    *,
    source_tools: list[str],
    signal_type: str,
    validation_results: list[dict[str, Any]],
) -> bool:
    case_type = str(case.case_type or "").lower()
    if not any(token in case_type for token in ("idor", "bola", "authorization", "access")):
        return False
    if source_tools or signal_type in {"access_observation", "attack_path"}:
        return False
    return not any(
        bool(result.get("tested") or result.get("human_validated"))
        and str(result.get("outcome") or "").lower() in {
            "bypassed",
            "validated_candidate",
        }
        for result in validation_results
    )


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
