"""Map normalized external tool results into BELIEF findings and audit cases."""

from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

from dataclasses import replace

from belief.audit_case import AuditCase, sort_audit_cases
from belief.models import Finding
from belief.tools.schemas import (
    AccessObservation,
    AttackPath,
    ExternalFinding,
    NormalizedToolResult,
    RequestStep,
)

from .io import sanitize_for_json
from .playbooks import playbook_for_category
from .provenance import SignalProvenance


_CATEGORY_CASE_TYPES = {
    "xss": "xss_possible",
    "sql_injection": "sql_injection_possible",
    "path_traversal": "path_traversal_possible",
    "command_injection": "command_injection_possible",
    "unsafe_deserialization": "unsafe_deserialization_possible",
    "ssrf": "ssrf_possible",
    "secrets": "hardcoded_secret_possible",
    "access_control": "idor_bola_possible",
    "mass_assignment": "mass_assignment_possible",
}


def external_finding_to_finding(external: ExternalFinding) -> Finding:
    """Convert one normalized external finding into BELIEF's stable Finding."""
    category = infer_external_category(external)
    provenance = provenance_for_external_finding(external)
    cwe = external.cwe[0] if external.cwe else ""
    metadata = {
        "category": category,
        "tool_signal_type": "external_finding",
        "provenance": [provenance.to_dict()],
        "source_tools": [external.tool_id],
        "external_tool_id": external.tool_id,
        "external_rule_id": external.rule_id,
        "external_confidence": external.confidence,
        "tool_evidence": sanitize_for_json(list(external.evidence)),
        "external_raw": sanitize_for_json(external.raw),
    }
    if external.route:
        metadata["route"] = external.route
    if _has_code_flow_evidence(external):
        metadata["has_codeflow"] = True
    return Finding(
        source=f"tool:{external.tool_id}",
        rule_id=external.rule_id or "",
        title=external.title or external.rule_id or "External finding",
        description=external.message or external.title or "",
        file=external.file or "",
        line=external.line,
        end_line=external.end_line,
        cwe=cwe,
        severity=(external.severity or "info").lower(),
        confidence=_confidence(external.confidence, external.severity),
        evidence="\n".join(str(item) for item in external.evidence if str(item)),
        metadata=metadata,
    )


def external_finding_to_audit_case(external: ExternalFinding) -> AuditCase:
    """Build a human-auditable candidate from a passive external finding."""
    finding = external_finding_to_finding(external)
    category = infer_external_category(external)
    case_type = _CATEGORY_CASE_TYPES.get(category, "external_tool_signal")
    priority = _priority(external.severity, default="medium" if category != "unknown" else "low")
    missing = _missing_guarantees_for_category(category)
    steps = playbook_for_category(category)
    route_context = _route_context(external.route)
    metadata = dict(finding.metadata)
    metadata.update({
        "title": finding.title,
        "message": finding.description,
        "column": external.column,
        "report_language": "candidate",
    })
    return AuditCase(
        case_id=_case_id(
            "external",
            external.tool_id,
            external.rule_id,
            category,
            external.file,
            external.line,
            external.route,
            external.message or external.title,
        ),
        case_type=case_type,
        status="needs_review",
        review_priority=priority,
        confidence=finding.confidence,
        severity=finding.severity,
        file=finding.file,
        line=finding.line,
        rule_id=finding.rule_id,
        cwe=finding.cwe,
        source=_source_for_external(external),
        sink=_sink_for_external(external),
        dataflow_path=tuple(str(item) for item in external.evidence if str(item)),
        missing_guarantees=missing,
        human_next_steps=tuple(steps),
        related_finding_fingerprint=finding.fingerprint,
        reason=_candidate_reason(category, external),
        route_context=route_context,
        metadata=metadata,
    )


def access_observation_to_audit_case(observation: AccessObservation) -> AuditCase:
    """Map one access-control observation to a candidate or protected audit case."""
    category = "access_control"
    detected = tuple(str(item) for item in observation.detected_guards if str(item))
    missing = tuple(str(item) for item in observation.missing_guards if str(item))
    strong_guard = any("strong" in item.lower() or "owner" in item.lower() or "tenant" in item.lower() for item in detected)
    protected = bool(strong_guard and not missing)
    priority = "low" if protected else ("high" if observation.mutation or missing else "medium")
    object_label = observation.object_type or "object"
    action = observation.action or "access"
    route = _method_path(observation.method, observation.path)
    title = (
        f"Likely protected object authorization on {route or object_label}"
        if protected
        else f"Candidate object authorization gap on {route or object_label}"
    )
    provenance = SignalProvenance(
        source_tool=observation.source_tool,
        source_kind="access_observation",
        confidence=observation.confidence,
        raw_reference={
            "actor": observation.actor,
            "role": observation.role,
            "object_type": observation.object_type,
            "object_id_source": observation.object_id_source,
            "action": observation.action,
            "method": observation.method,
            "path": observation.path,
        },
    )
    metadata = {
        "title": title,
        "category": category,
        "tool_signal_type": "access_observation",
        "provenance": [provenance.to_dict()],
        "source_tools": [observation.source_tool],
        "actor": observation.actor,
        "role": observation.role,
        "method": observation.method,
        "path": observation.path,
        "object_type": observation.object_type,
        "object_id_source": observation.object_id_source,
        "action": action,
        "mutation": bool(observation.mutation),
        "response_exposes_object": bool(observation.response_exposes_object),
        "expected_guard": observation.expected_guard,
        "detected_guards": list(detected),
        "missing_guards": list(missing),
        "tool_evidence": sanitize_for_json(list(observation.evidence)),
        "strong_guard": bool(strong_guard),
        "report_language": "likely protected" if protected else "candidate",
    }
    steps = list(observation.evidence) + playbook_for_category(category)
    return AuditCase(
        case_id=_case_id(
            "access",
            observation.source_tool,
            observation.method,
            observation.path,
            observation.object_type,
            observation.object_id_source,
            action,
            ",".join(missing),
        ),
        case_type="idor_bola_possible",
        status="protected" if protected else "needs_review",
        review_priority=priority,
        confidence=_confidence(observation.confidence, priority),
        severity=priority,
        file="",
        line=None,
        rule_id="ACCESS_OBSERVATION",
        cwe="CWE-639" if not protected else "",
        source=observation.actor or observation.role or "actor",
        sink=f"{object_label}.{action}",
        guarantees=detected,
        missing_guarantees=missing,
        human_next_steps=tuple(_dedupe_strings(steps)),
        reason=(
            "Strong owner/tenant guard evidence was imported for this object access."
            if protected
            else f"Imported access observation is missing proof for {', '.join(missing) or 'object authorization'}."
        ),
        route_context=_route_context(observation.path, observation.method),
        metadata=metadata,
    )


def attack_path_to_audit_case(path: AttackPath) -> AuditCase:
    """Convert an imported workflow/attack-path description to an audit case."""
    steps = tuple(_request_step_text(step) for step in path.steps)
    route_context = _route_context(path.steps[0].path, path.steps[0].method) if path.steps else {}
    provenance = SignalProvenance(
        source_tool=path.source_tool,
        source_kind="attack_path",
        confidence=path.risk,
        raw_reference={"step_count": len(path.steps), "hypothesis": path.hypothesis},
    )
    metadata = {
        "title": path.title,
        "category": "attack_path",
        "tool_signal_type": "attack_path",
        "provenance": [provenance.to_dict()],
        "source_tools": [path.source_tool],
        "hypothesis": path.hypothesis,
        "evidence_needed": sanitize_for_json(list(path.evidence_needed)),
        "request_steps": [_request_step_dict(step) for step in path.steps],
        "report_language": "validation workflow candidate",
    }
    validation = list(path.evidence_needed) or [
        "Review each request step in authorized scope.",
        "Confirm produced values are scoped to the actor that consumes them.",
    ]
    return AuditCase(
        case_id=_case_id("attack_path", path.source_tool, path.title, steps),
        case_type="validation_workflow_candidate",
        status="needs_review",
        review_priority=_priority(path.risk, default="medium"),
        confidence=_confidence(path.risk, path.risk),
        severity=_priority(path.risk, default="medium"),
        file="",
        line=None,
        rule_id="ATTACK_PATH",
        cwe="",
        source=path.steps[0].actor if path.steps and path.steps[0].actor else path.source_tool,
        sink=path.steps[-1].path if path.steps else "",
        dataflow_path=steps,
        human_next_steps=tuple(_dedupe_strings(validation)),
        reason=path.hypothesis or "Imported workflow needs manual validation.",
        route_context=route_context,
        metadata=metadata,
    )


def normalized_result_to_audit_cases(result: NormalizedToolResult) -> list[AuditCase]:
    """Convert all normalized signals in one result to deterministic audit cases."""
    cases: list[AuditCase] = []
    cases.extend(external_finding_to_audit_case(finding) for finding in result.findings)
    cases.extend(access_observation_to_audit_case(obs) for obs in result.access_observations)
    cases.extend(attack_path_to_audit_case(path) for path in result.attack_paths)
    if result.artifacts:
        enriched = []
        artifacts = [str(item) for item in result.artifacts]
        for case in cases:
            metadata = dict(case.metadata)
            metadata.setdefault("source_artifacts", artifacts)
            enriched.append(replace(case, metadata=metadata))
        cases = enriched
    return sort_audit_cases(cases)


def normalized_result_to_findings(result: NormalizedToolResult) -> list[Finding]:
    """Convert only ExternalFinding entries to BELIEF Findings."""
    return sorted(
        [external_finding_to_finding(finding) for finding in result.findings],
        key=lambda item: (item.file, item.line or 0, item.rule_id, item.fingerprint),
    )


def infer_external_category(external: ExternalFinding) -> str:
    text = " ".join([
        *(external.cwe or []),
        external.rule_id or "",
        external.title or "",
        external.message or "",
        " ".join(str(item) for item in external.evidence),
    ]).lower()
    cwes = {item.upper() for item in external.cwe}
    if cwes & {"CWE-79", "CWE-080", "CWE-081", "CWE-083"} or "xss" in text:
        return "xss"
    if "sql" in text or "CWE-89" in cwes:
        return "sql_injection"
    if cwes & {"CWE-22", "CWE-73"} or "path traversal" in text or "path_traversal" in text:
        return "path_traversal"
    if "command" in text or "shell" in text or "CWE-78" in cwes:
        return "command_injection"
    if "deserial" in text or "pickle" in text or "CWE-502" in cwes:
        return "unsafe_deserialization"
    if "ssrf" in text or "server-side request forgery" in text or "CWE-918" in cwes:
        return "ssrf"
    if "hardcoded" in text or "secret" in text or "CWE-798" in cwes:
        return "secrets"
    if cwes & {"CWE-639", "CWE-862", "CWE-863"} or any(
        token in text for token in ("idor", "bola", "authz", "authorization bypass", "access control")
    ):
        return "access_control"
    if "mass assignment" in text or "mass_assignment" in text:
        return "mass_assignment"
    return "unknown"


def provenance_for_external_finding(external: ExternalFinding) -> SignalProvenance:
    return SignalProvenance(
        source_tool=external.tool_id,
        source_rule_id=external.rule_id,
        source_file=external.file,
        source_line=external.line,
        source_kind="external_finding",
        confidence=external.confidence,
        raw_reference={
            "cwe": list(external.cwe),
            "route": external.route,
            "column": external.column,
            "end_line": external.end_line,
            "raw": sanitize_for_json(_small_raw_reference(external.raw)),
        },
    )


def _candidate_reason(category: str, external: ExternalFinding) -> str:
    label = category.replace("_", " ") if category != "unknown" else "external tool signal"
    return (
        f"Imported {label} candidate from {external.tool_id}; manual validation in authorized scope is required."
    )


def _source_for_external(external: ExternalFinding) -> str:
    route = external.route or ""
    return route or external.file or f"tool:{external.tool_id}"


def _sink_for_external(external: ExternalFinding) -> str:
    return external.rule_id or external.title or "external_signal"


def _missing_guarantees_for_category(category: str) -> tuple[str, ...]:
    mapping = {
        "access_control": ("owner_or_tenant_scoped_lookup",),
        "mass_assignment": ("server_side_field_allowlist",),
        "path_traversal": ("path.is_within_base_directory == true",),
        "unsafe_deserialization": ("deserialization.input_trusted_or_signed == true",),
        "ssrf": ("outbound_url.host_allowlisted == true",),
        "command_injection": ("command.arguments_are_not_user_controlled == true",),
        "sql_injection": ("query.uses_parameter_binding == true",),
        "xss": ("output.user_values_escaped == true",),
        "secrets": ("secret.value_is_runtime_supplied == true",),
    }
    return mapping.get(category, ())


def _route_context(route: str | None, method: str | None = None) -> dict[str, Any]:
    if not route:
        return {}
    return {
        "framework": "external",
        "route": str(route),
        "methods": [str(method or "UNKNOWN")],
        "handler": "",
        "decorators": [],
        "auth_guarantees": [],
        "params": [],
        "confidence": 0.4,
    }


def _method_path(method: str | None, path: str | None) -> str:
    if method and path:
        return f"{method.upper()} {path}"
    return str(path or method or "")


def _request_step_text(step: RequestStep) -> str:
    parts = [step.method.upper(), step.path]
    if step.actor:
        parts.append(f"actor={step.actor}")
    if step.produces:
        parts.append("produces=" + ",".join(step.produces))
    if step.consumes:
        parts.append("consumes=" + ",".join(step.consumes))
    return " ".join(parts)


def _request_step_dict(step: RequestStep) -> dict[str, Any]:
    return sanitize_for_json({
        "method": step.method,
        "path": step.path,
        "actor": step.actor,
        "produces": list(step.produces),
        "consumes": list(step.consumes),
        "notes": step.notes,
    })


def _priority(value: str | None, *, default: str = "medium") -> str:
    text = str(value or "").lower()
    if text in {"critical", "high", "medium", "low", "info"}:
        return text
    if text in {"error", "warning"}:
        return "high" if text == "error" else "medium"
    if text in {"note", "none"}:
        return "info"
    return default


def _confidence(confidence: str | None, severity: str | None) -> float:
    text = str(confidence or severity or "").lower()
    if text in {"very_high", "high", "critical", "error"}:
        return 0.85
    if text in {"medium", "warning"}:
        return 0.65
    if text in {"low", "note", "info"}:
        return 0.35
    return 0.5


def _has_code_flow_evidence(external: ExternalFinding) -> bool:
    if external.tool_id.lower() == "codeql" and external.evidence:
        return True
    raw = str(external.raw or "").lower()
    return "codeflow" in raw or "codeflows" in raw or "threadflows" in raw


def _small_raw_reference(raw: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return {}
    keep = {}
    for key in ("check_id", "path", "start", "end", "extra", "ruleId", "level", "message"):
        if key in raw:
            keep[key] = raw[key]
    if not keep:
        keep["keys"] = sorted(str(key) for key in raw)[:20]
    return keep


def _dedupe_strings(values: Iterable[Any]) -> list[str]:
    seen = set()
    result = []
    for value in values:
        item = re.sub(r"\s+", " ", str(value or "").strip())
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def _case_id(*parts: object) -> str:
    raw = "\x1f".join(str(part or "") for part in parts)
    return "case_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "access_observation_to_audit_case",
    "attack_path_to_audit_case",
    "external_finding_to_audit_case",
    "external_finding_to_finding",
    "infer_external_category",
    "normalized_result_to_audit_cases",
    "normalized_result_to_findings",
    "provenance_for_external_finding",
]
