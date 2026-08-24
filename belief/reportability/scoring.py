"""Conservative reportability scoring for BELIEF audit cases."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable

from belief.audit_case import AuditCase, sort_audit_cases
from belief.validation.ledger import VerifiedProofSnapshot
from belief.validation.proof import (
    ProofAuthorityContext,
    ValidationProofError,
    VerifiedProofIndex,
    assess_validation_result_proof,
    proof_subject_digest,
)

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


def assess_audit_case_reportability(
    case: AuditCase,
    *,
    proof_snapshot: VerifiedProofSnapshot | None = None,
    proof_index: VerifiedProofIndex | None = None,
    proof_context: ProofAuthorityContext | None = None,
) -> ReportabilityAssessment:
    """Assess whether an audit case is ready for human report drafting."""
    proof_index, proof_context = _resolve_proof_inputs(
        proof_snapshot=proof_snapshot,
        proof_index=proof_index,
        proof_context=proof_context,
    )
    metadata = case.metadata if isinstance(case.metadata, dict) else {}
    positive: list[str] = []
    negative: list[str] = []
    missing_evidence: list[str] = []
    validation_steps = list(case.human_next_steps)
    score = 0

    source_tools = sorted(
        {str(tool) for tool in _as_list(metadata.get("source_tools")) if str(tool)}
    )
    source_lineages = sorted(
        {
            str(lineage)
            for lineage in _as_list(metadata.get("independent_source_lineages"))
            if str(lineage)
        }
    )
    signal_type = str(metadata.get("tool_signal_type") or "")
    category_text = " ".join(
        [
            str(metadata.get("category") or ""),
            str(case.case_type or ""),
            str(case.cwe or ""),
        ]
    ).lower()

    if signal_type == "external_finding" or source_tools:
        score += 10
        positive.append("external finding present")
    if len(source_lineages) > 1:
        score += 15
        positive.append("independent evidence lineages agree")
    elif len(source_tools) > 1:
        negative.append("external source independence not established")
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
    legacy_score = score
    if len(source_tools) > 1 and len(source_lineages) <= 1:
        legacy_score += 15
    legacy_score += _legacy_validation_delta(validation_results)

    proof_assessments = []
    verified_results: list[dict[str, Any]] = []
    verified_proof_ids: list[str] = []
    seen_verified_proof_ids: set[str] = set()
    context_mismatches = _proof_context_mismatches(metadata, proof_context)
    context_is_usable = proof_context is not None and not context_mismatches
    engagement_id = proof_context.engagement_id if context_is_usable else ""
    target_id = proof_context.target_id if context_is_usable else ""
    try:
        subject_sha256 = proof_subject_digest(case)
    except (TypeError, ValueError, ValidationProofError):
        subject_sha256 = ""
    negative.extend(context_mismatches)
    for result in validation_results:
        result_metadata = result.get("metadata")
        plan_id = (
            str(result_metadata.get("validation_plan_id") or "")
            if isinstance(result_metadata, dict)
            else ""
        )
        assessment = assess_validation_result_proof(
            result,
            proof_index=proof_index,
            engagement_id=engagement_id,
            target_id=target_id,
            subject_id=case.case_id,
            subject_kind="audit_case",
            plan_id=plan_id,
            subject_sha256=subject_sha256,
        )
        proof_assessments.append(assessment)
        if assessment.state != "verified":
            continue
        if assessment.proof_id in seen_verified_proof_ids:
            negative.append("duplicate verified validation proof ignored")
            continue
        seen_verified_proof_ids.add(assessment.proof_id)
        verified_results.append(result)
        if assessment.proof_id:
            verified_proof_ids.append(assessment.proof_id)

    proof_state = _proof_state(proof_assessments)
    verified_outcomes = {str(result.get("outcome") or "").lower() for result in verified_results}
    positive_outcomes = verified_outcomes.intersection({"bypassed", "validated_candidate"})
    negative_outcomes = verified_outcomes.intersection({"enforced", "false_positive"})
    if positive_outcomes and negative_outcomes:
        proof_state = "quarantined"
        negative.append("verified validation outcomes conflict")
    if "false_positive" in verified_outcomes:
        score -= 35
        negative.append("verified proof marks false positive")
    elif "enforced" in verified_outcomes:
        score -= 25
        negative.append("verified proof indicates guard enforced")
    elif "bypassed" in verified_outcomes:
        score += 20
        positive.append("verified bypass proof present")
    elif "validated_candidate" in verified_outcomes:
        score += 10
        positive.append("verified validation candidate present")
    for assessment in proof_assessments:
        if assessment.state == "quarantined":
            negative.extend(assessment.reasons)
    if validation_results and not verified_results:
        negative.append("unverified validation claims ignored")

    guard_results = evaluate_case_guards(case, metadata)
    guard_blockers = blockers_for(guard_results)
    strong_guard = _strong_guard(case, guard_results)
    contradictory_evidence = bool(metadata.get("missing_guards"))
    if strong_guard:
        score -= 40
        legacy_score -= 40
        negative.append("causally applicable security guard detected")
    elif "authentication_only" in guard_blockers:
        negative.append("authentication present without resource authorization")
    if _admin_guard_for_admin_action(case, metadata, guard_results):
        score -= 25
        legacy_score -= 25
        negative.append("admin-only guard for admin action")
    if _test_generated_or_vendor_path(case.file):
        score -= 20
        legacy_score -= 20
        negative.append("test, fixture, generated, or vendor path")
    has_path = _case_has_dataflow(case, metadata)
    if not (case.route_context or has_path or signal_type == "access_observation"):
        score -= 20
        legacy_score -= 20
        negative.append("no route, source-to-sink path, or access observation")
    if signal_type == "external_finding" and not has_path and len(source_tools) <= 1:
        score -= 15
        legacy_score -= 15
        negative.append("weak generic static-only signal")
    if str(case.severity or "").lower() in {"low", "info"}:
        score -= 10
        legacy_score -= 10
        negative.append("severity is low/info")

    if (
        _requires_manual_static_access_validation(
            case,
            source_tools=source_tools,
            signal_type=signal_type,
            verified_results=verified_results,
        )
        and score >= 80
    ):
        score = 79
        negative.append("static access-control flow requires manual authorization validation")

    if (
        _requires_manual_static_access_validation_legacy(
            case,
            source_tools=source_tools,
            signal_type=signal_type,
            validation_results=validation_results,
        )
        and legacy_score >= 80
    ):
        legacy_score = 79

    if not case.route_context and not metadata.get("route") and not metadata.get("path"):
        missing_evidence.append("affected route or endpoint")
    if not has_path and signal_type != "access_observation":
        missing_evidence.append("source-to-sink evidence")
    if case.missing_guarantees:
        missing_evidence.extend(f"proof for {item}" for item in case.missing_guarantees)
    elif not strong_guard and signal_type != "attack_path":
        missing_evidence.append("existing guard or sanitizer proof")

    verified_bypass = proof_state == "verified" and any(
        str(result.get("outcome") or "").lower() == "bypassed" for result in verified_results
    )
    if score >= 80 and not verified_bypass:
        score = 79
        negative.append("verified bypass proof required for reportable candidate")
    if not verified_bypass and not strong_guard:
        missing_evidence.append("verified validation proof")

    score = max(0, min(100, int(score)))
    legacy_score = max(0, min(100, int(legacy_score)))
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
        legacy_score=legacy_score,
        verdict=verdict,
        confidence=confidence,
        proof_state=proof_state,
        verified_proof_ids=_dedupe(verified_proof_ids),
        positive_factors=_dedupe(positive),
        negative_factors=_dedupe(negative),
        missing_evidence=_dedupe(missing_evidence),
        validation_steps=_dedupe(validation_steps),
        guard_applicability=[result.to_dict() for result in guard_results],
        blockers=list(guard_blockers),
    )


def assess_many(
    cases: Iterable[AuditCase],
    *,
    proof_snapshot: VerifiedProofSnapshot | None = None,
    proof_index: VerifiedProofIndex | None = None,
    proof_context: ProofAuthorityContext | None = None,
) -> list[tuple[AuditCase, ReportabilityAssessment]]:
    """Assess many cases in deterministic order."""
    proof_index, proof_context = _resolve_proof_inputs(
        proof_snapshot=proof_snapshot,
        proof_index=proof_index,
        proof_context=proof_context,
    )
    return [
        (
            case,
            assess_audit_case_reportability(
                case,
                proof_index=proof_index,
                proof_context=proof_context,
            ),
        )
        for case in sort_audit_cases(cases)
    ]


def attach_reportability_to_cases(
    cases: Iterable[AuditCase],
    *,
    proof_snapshot: VerifiedProofSnapshot | None = None,
    proof_index: VerifiedProofIndex | None = None,
    proof_context: ProofAuthorityContext | None = None,
) -> list[AuditCase]:
    """Return cases with reportability metadata attached."""
    proof_index, proof_context = _resolve_proof_inputs(
        proof_snapshot=proof_snapshot,
        proof_index=proof_index,
        proof_context=proof_context,
    )
    enriched = []
    for case, assessment in assess_many(
        cases,
        proof_index=proof_index,
        proof_context=proof_context,
    ):
        metadata = dict(case.metadata or {})
        metadata["reportability"] = assessment.to_dict()
        enriched.append(replace(case, metadata=metadata))
    return sort_audit_cases(enriched)


def _resolve_proof_inputs(
    *,
    proof_snapshot: VerifiedProofSnapshot | None,
    proof_index: VerifiedProofIndex | None,
    proof_context: ProofAuthorityContext | None,
) -> tuple[VerifiedProofIndex | None, ProofAuthorityContext | None]:
    if proof_snapshot is None:
        return proof_index, proof_context
    if not isinstance(proof_snapshot, VerifiedProofSnapshot):
        raise TypeError("proof_snapshot must be a VerifiedProofSnapshot")
    if proof_index is not None or proof_context is not None:
        raise TypeError("proof_snapshot cannot be combined with proof_index or proof_context")
    return proof_snapshot.proof_index, proof_snapshot.context


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
    text = " ".join(
        [
            " ".join(case.missing_guarantees),
            " ".join(str(item) for item in _as_list(metadata.get("missing_guards"))),
        ]
    ).lower()
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
                token in expression
                for token in (
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
    action = " ".join(
        [
            str(metadata.get("action") or ""),
            str(case.sink or ""),
        ]
    ).lower()
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
        if (isinstance(edges, list) and edges) or (evidence.get("source") and evidence.get("sink")):
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


def _legacy_validation_delta(
    validation_results: list[dict[str, Any]],
) -> int:
    """Reproduce the pre-proof-gate score delta for diagnostics only."""

    delta = 0
    for result in validation_results:
        outcome = str(result.get("outcome") or "").lower()
        claimed = bool(result.get("tested") or result.get("human_validated"))
        metadata = result.get("metadata")
        positive_evidence = isinstance(metadata, dict) and metadata.get("positive_evidence") is True
        if outcome == "bypassed" and claimed:
            delta += 20
        elif outcome == "validated_candidate" and claimed:
            delta += 10
        elif outcome == "inconclusive" and positive_evidence:
            delta += 5
        elif outcome == "enforced" and claimed:
            delta -= 25
        elif outcome == "false_positive" and claimed:
            delta -= 35
    return delta


def _proof_state(assessments: list[Any]) -> str:
    states = {assessment.state for assessment in assessments}
    if "quarantined" in states:
        return "quarantined"
    if "verified" in states:
        return "verified"
    return "signal_only"


def _proof_context_mismatches(
    metadata: dict[str, Any],
    proof_context: ProofAuthorityContext | None,
) -> list[str]:
    if proof_context is None:
        return []
    mismatches = []
    for field_name in ("engagement_id", "target_id"):
        if field_name not in metadata:
            continue
        claimed = metadata[field_name]
        if not isinstance(claimed, str) or claimed != getattr(
            proof_context,
            field_name,
        ):
            mismatches.append(f"validation_proof_{field_name}_context_mismatch")
    return mismatches


def _requires_manual_static_access_validation(
    case: AuditCase,
    *,
    source_tools: list[str],
    signal_type: str,
    verified_results: list[dict[str, Any]],
) -> bool:
    case_type = str(case.case_type or "").lower()
    if not any(token in case_type for token in ("idor", "bola", "authorization", "access")):
        return False
    if source_tools or signal_type in {"access_observation", "attack_path"}:
        return False
    return not any(
        str(result.get("outcome") or "").lower()
        in {
            "bypassed",
            "validated_candidate",
        }
        for result in verified_results
    )


def _requires_manual_static_access_validation_legacy(
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
        and str(result.get("outcome") or "").lower() in {"bypassed", "validated_candidate"}
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
