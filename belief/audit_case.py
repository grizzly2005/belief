"""Audit-case triage layer for BELIEF v4.

Audit cases are product-level summaries built from existing Findings,
hypotheses, guarantees, and local dataflow evidence. They do not replace the
stable Finding model and they do not create a new analysis framework.
"""

from __future__ import annotations

import hashlib
import re
import ast
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from .dataflow import DataFlowPath, DataFlowSummary
from .models import Belief, Finding, _json_safe


AUDIT_SCHEMA_VERSION = "belief.audit.v1"
STRUCTURED_DATAFLOW_SCHEMA_VERSION = "belief.dataflow_evidence.v1"
AUDIT_CASE_STATUSES = ("actionable", "needs_review", "protected", "false_positive_likely")
REVIEW_PRIORITIES = ("critical", "high", "medium", "low", "info")


@dataclass(frozen=True)
class AuditCase:
    case_id: str
    case_type: str
    status: str
    review_priority: str
    confidence: float
    severity: str
    file: str
    line: int | None
    rule_id: str
    cwe: str
    source: str = ""
    sink: str = ""
    dataflow_path: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    guarantees: tuple[str, ...] = ()
    missing_guarantees: tuple[str, ...] = ()
    z3_status: str = "not_applicable"
    unsat_core: tuple[str, ...] = ()
    human_next_steps: tuple[str, ...] = ()
    related_finding_fingerprint: str = ""
    reason: str = ""
    route_context: dict[str, Any] = field(default_factory=dict)
    structured_dataflow: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "status": self.status,
            "review_priority": self.review_priority,
            "confidence": round(float(self.confidence), 3),
            "severity": self.severity,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "source": self.source,
            "sink": self.sink,
            "dataflow_path": list(self.dataflow_path),
            "sanitizers": list(self.sanitizers),
            "guarantees": list(self.guarantees),
            "missing_guarantees": list(self.missing_guarantees),
            "z3_status": self.z3_status,
            "unsat_core": list(self.unsat_core),
            "human_next_steps": list(self.human_next_steps),
            "related_finding_fingerprint": self.related_finding_fingerprint,
            "reason": self.reason,
        }
        if self.route_context:
            data["route_context"] = dict(self.route_context)
        if self.structured_dataflow:
            data["structured_dataflow"] = _json_safe(self.structured_dataflow)
        if self.metadata:
            data["metadata"] = _json_safe(self.metadata)
        return data


def build_audit_cases(
    findings: Iterable[Finding],
    *,
    dataflow_summaries: dict[str, DataFlowSummary] | Iterable[DataFlowSummary] | None = None,
) -> list[AuditCase]:
    """Build deterministic audit cases from findings and optional dataflow."""
    cases: list[AuditCase] = []
    for finding in findings:
        case = audit_case_from_finding(finding)
        if case is not None:
            cases.append(case)

    existing = {
        (_norm_path(case.file), case.line or 0, case.case_type, case.source, case.sink)
        for case in cases
    }
    for path in _iter_dataflow_paths(dataflow_summaries):
        if path.sink_category != "query":
            continue
        case = audit_case_from_dataflow_path(path)
        key = (_norm_path(case.file), case.line or 0, case.case_type, case.source, case.sink)
        if key not in existing:
            existing.add(key)
            cases.append(case)

    return sort_audit_cases(_dedupe_cases(cases))


def attach_route_context_to_audit_cases(
    cases: Iterable[AuditCase],
    routes: Iterable[Any],
    *,
    source_contexts: dict[str, str] | None = None,
) -> list[AuditCase]:
    """Attach best-effort static route context to audit cases.

    Matching is intentionally conservative: same normalized file is required;
    function-span matching wins; a unique route in a file is the only fallback.
    """
    route_list = list(routes or [])
    if not route_list:
        return list(cases)

    routes_by_file: dict[str, list[Any]] = {}
    for route in route_list:
        routes_by_file.setdefault(_norm_path(_route_value(route, "file")), []).append(route)

    spans_by_file = _function_spans_by_file(source_contexts or {})
    enriched = []
    for case in cases:
        candidates = routes_by_file.get(_norm_path(case.file), [])
        context = _match_route_context(case, candidates, spans_by_file.get(_norm_path(case.file), {}))
        enriched.append(replace(case, route_context=context) if context else case)
    return sort_audit_cases(enriched)


def audit_case_from_finding(finding: Finding) -> AuditCase | None:
    """Convert one Finding into an AuditCase when it is AppSec-relevant."""
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    hypothesis = metadata.get("hypothesis") if isinstance(metadata.get("hypothesis"), dict) else {}
    dataflow = _finding_dataflow(metadata, hypothesis)
    case_type = _case_type_for_finding(finding, hypothesis)
    if case_type is None:
        return None

    guarantees = _guarantee_expressions(hypothesis, dataflow)
    missing = _missing_guarantees(hypothesis, dataflow)
    sanitizers = _strings(dataflow.get("sanitizers", []))
    z3_status = _z3_status(hypothesis)
    unsat_core = _strings((hypothesis.get("z3") or {}).get("unsat_core", []))
    review_priority = _review_priority(case_type, finding, hypothesis, dataflow, guarantees, missing)
    status = _case_status(case_type, finding, hypothesis, dataflow, guarantees, missing, z3_status, review_priority)
    reason = _case_reason(case_type, status, review_priority, z3_status, guarantees, missing)

    return AuditCase(
        case_id=_case_id(
            case_type,
            finding.file,
            finding.line,
            finding.rule_id,
            finding.cwe,
            finding.fingerprint,
            dataflow.get("source", ""),
            dataflow.get("sink", ""),
        ),
        case_type=case_type,
        status=status,
        review_priority=review_priority,
        confidence=float(finding.confidence or 0.0),
        severity=str(finding.severity or "info").lower(),
        file=finding.file,
        line=finding.line,
        rule_id=finding.rule_id,
        cwe=finding.cwe,
        source=str(dataflow.get("source", "")),
        sink=str(dataflow.get("sink", "")),
        dataflow_path=tuple(str(item) for item in dataflow.get("path", []) if item),
        sanitizers=sanitizers,
        guarantees=guarantees,
        missing_guarantees=missing,
        z3_status=z3_status,
        unsat_core=unsat_core,
        human_next_steps=tuple(_human_next_steps(case_type, status, missing)),
        related_finding_fingerprint=finding.fingerprint,
        reason=reason,
        structured_dataflow=_structured_dataflow_from_payload(
            dataflow,
            default_file=finding.file,
            hypothesis=hypothesis,
        ),
    )


def audit_case_from_dataflow_path(path: DataFlowPath) -> AuditCase:
    """Create an audit case from a dataflow-only query/path explanation."""
    case_type = _case_type_for_dataflow(path)
    guarantees = tuple(node.expression for node in path.guarantees)
    sanitizers = tuple(node.expression for node in path.sanitizers)
    missing = tuple(path.missing_sanitizers)
    severity = "high" if path.review_priority in {"critical", "high"} else "medium"
    status = "protected" if (guarantees or sanitizers) and not missing else "needs_review"
    if path.sink_category == "query" and not guarantees:
        status = "needs_review"
    review_priority = "low" if status == "protected" else ("high" if path.sink_category == "query" else path.review_priority)
    reason = _case_reason(case_type, status, review_priority, "not_applicable", guarantees, missing)

    return AuditCase(
        case_id=_case_id(
            case_type,
            path.file_path,
            path.sink_line,
            "LOCAL_DATAFLOW_PATH",
            path.cwe,
            "",
            path.source.expression,
            path.sink.expression,
        ),
        case_type=case_type,
        status=status,
        review_priority=review_priority,
        confidence=float(path.confidence),
        severity=severity,
        file=path.file_path,
        line=path.sink_line,
        rule_id="LOCAL_DATAFLOW_PATH",
        cwe=path.cwe,
        source=path.source.expression,
        sink=path.sink.expression,
        dataflow_path=tuple(node.expression for node in path.nodes),
        sanitizers=sanitizers,
        guarantees=guarantees,
        missing_guarantees=missing,
        z3_status="not_applicable",
        human_next_steps=tuple(_human_next_steps(case_type, status, missing)),
        reason=reason,
        structured_dataflow=_structured_dataflow_from_path(path),
    )


def summarize_audit_cases(cases: Iterable[AuditCase]) -> dict[str, int]:
    counts = {status: 0 for status in AUDIT_CASE_STATUSES}
    for case in cases:
        counts[case.status] = counts.get(case.status, 0) + 1
    return counts


def sort_audit_cases(cases: Iterable[AuditCase]) -> list[AuditCase]:
    status_order = {
        "actionable": 0,
        "needs_review": 1,
        "protected": 2,
        "false_positive_likely": 3,
    }
    priority_order = {name: idx for idx, name in enumerate(REVIEW_PRIORITIES)}
    return sorted(
        list(cases),
        key=lambda case: (
            status_order.get(case.status, 9),
            priority_order.get(case.review_priority, 9),
            -float(case.confidence),
            case.file,
            case.line or 0,
            case.case_type,
            case.case_id,
        ),
    )


def interesting_audit_cases(cases: Iterable[AuditCase]) -> list[AuditCase]:
    return [
        case for case in sort_audit_cases(cases)
        if case.status in {"actionable", "needs_review"}
    ]


def summarize_guarantees(guarantees: Iterable[Belief]) -> dict[str, int]:
    families = {
        "path_boundary": 0,
        "path_normalization": 0,
        "filename_validation": 0,
        "server_generated_value": 0,
        "ownership_scope": 0,
        "escaping": 0,
        "authorization": 0,
        "runtime_surface": 0,
        "serialization_safety": 0,
    }
    for belief in guarantees:
        expr = str(belief.predicate.expression or "").lower()
        if any(token in expr for token in [
            "storage.path.enforces_store_boundary",
            "storage.verify.enforces_store_boundary",
            "storage.store_contains.enforces_store_boundary",
            "path.is_within_store",
        ]):
            families["path_boundary"] += 1
        if "path.is_normalized" in expr:
            families["path_normalization"] += 1
        if any(token in expr for token in [
            "filename.matches_allowed_pattern",
            "filename.basename_only",
            "filename.user_controlled == false",
        ]):
            families["filename_validation"] += 1
        if "server_generated" in expr or "identifier.server_generated" in expr:
            families["server_generated_value"] += 1
        if "query.scoped_to_current_" in expr:
            families["ownership_scope"] += 1
        if "html_output.user_values_escaped" in expr or "markup.has_unescaped_user_input == false" in expr:
            families["escaping"] += 1
        if "route.requires_" in expr:
            families["authorization"] += 1
        if "runtime.surface." in expr:
            families["runtime_surface"] += 1
        if "deserialization.input_trusted" in expr:
            families["serialization_safety"] += 1
    return families


def _case_type_for_finding(finding: Finding, hypothesis: dict[str, Any]) -> str | None:
    htype = str(hypothesis.get("hypothesis_type") or hypothesis.get("type") or "")
    if htype == "path_traversal_possible":
        return "path_traversal_possible"
    if htype == "xss_possible":
        return "xss_possible"
    if htype == "authorization_bypass_possible":
        return "idor_bola_possible"
    if htype == "unsafe_deserialization_possible":
        return "unsafe_deserialization_possible"
    if htype == "hardcoded_credential_possible":
        return "hardcoded_secret_possible"

    cwe = str(finding.cwe or "").upper()
    text = " ".join([
        finding.rule_id,
        finding.title,
        finding.description,
        finding.evidence,
    ]).lower()
    if cwe in {"CWE-22", "CWE-73"}:
        return "path_traversal_possible"
    if cwe == "CWE-79":
        return "xss_possible"
    if cwe == "CWE-502":
        return "unsafe_deserialization_possible"
    if cwe == "CWE-798":
        return "hardcoded_secret_possible"
    if cwe == "CWE-78":
        return "command_injection_possible"
    if cwe == "CWE-918":
        return "ssrf_possible"
    if cwe == "CWE-89":
        return "sql_injection_possible"
    if cwe in {"CWE-639", "CWE-862", "CWE-863"} or "idor" in text:
        return "idor_bola_possible"
    return None


def _case_type_for_dataflow(path: DataFlowPath) -> str:
    if path.sink_category == "query":
        return "idor_bola_possible"
    if path.sink_category == "path":
        return "path_traversal_possible"
    if path.sink_category == "template":
        return "xss_possible"
    if path.sink_category == "deserialization":
        return "unsafe_deserialization_possible"
    if path.sink_category == "command":
        return "command_injection_possible"
    if path.sink_category == "network":
        return "ssrf_possible"
    return "path_traversal_possible"


def _review_priority(
    case_type: str,
    finding: Finding,
    hypothesis: dict[str, Any],
    dataflow: dict[str, Any],
    guarantees: tuple[str, ...],
    missing: tuple[str, ...],
) -> str:
    text = " ".join([finding.file, finding.title, finding.description, finding.evidence]).lower()
    if _hardcoded_header_false_positive(case_type, guarantees, text):
        return "info"
    if str(hypothesis.get("status") or "").lower() == "contradicted" and _z3_status(hypothesis) == "unsat":
        if case_type in {"path_traversal_possible", "xss_possible", "idor_bola_possible"}:
            return "low"
    guarantee_text = " ".join(guarantees).lower()
    if case_type == "xss_possible" and any(token in guarantee_text for token in [
        "html_output.user_values_escaped",
        "markup.has_unescaped_user_input == false",
    ]):
        return "low"
    if _runtime_surface_low_risk(text, guarantees) and case_type not in {"unsafe_deserialization_possible", "command_injection_possible"}:
        return "low"
    if guarantees or dataflow.get("sanitizers"):
        if case_type in {"path_traversal_possible", "xss_possible", "idor_bola_possible"} and not missing:
            return "low"
    if case_type == "unsafe_deserialization_possible":
        return "critical" if not guarantees else "low"
    if case_type == "command_injection_possible":
        return "critical" if missing or not guarantees else "low"
    if case_type == "idor_bola_possible":
        return "high" if missing or not guarantees else "low"
    if case_type == "path_traversal_possible":
        return "high" if missing and not guarantees else "low"
    if case_type in {"ssrf_possible", "sql_injection_possible"}:
        return "high"
    if case_type == "hardcoded_secret_possible":
        return "high" if not guarantees else "info"
    severity = str(finding.severity or "").lower()
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return str(dataflow.get("review_priority") or "medium")


def _case_status(
    case_type: str,
    finding: Finding,
    hypothesis: dict[str, Any],
    dataflow: dict[str, Any],
    guarantees: tuple[str, ...],
    missing: tuple[str, ...],
    z3_status: str,
    review_priority: str,
) -> str:
    hstatus = str(hypothesis.get("status") or "").lower()
    text = " ".join([finding.file, finding.title, finding.description, finding.evidence]).lower()
    if _hardcoded_header_false_positive(case_type, guarantees, text):
        return "false_positive_likely"
    if hstatus == "contradicted" and z3_status == "unsat":
        return "protected"
    if (guarantees or dataflow.get("sanitizers")) and not missing:
        return "protected"
    if hstatus == "weakened":
        return "protected" if review_priority in {"low", "info"} else "needs_review"
    if hstatus == "strengthened":
        return "actionable" if review_priority in {"critical", "high"} else "needs_review"
    if hstatus == "unproven":
        return "needs_review"
    if review_priority in {"critical", "high"}:
        return "actionable" if case_type in {"unsafe_deserialization_possible", "command_injection_possible"} else "needs_review"
    return "needs_review"


def _case_reason(
    case_type: str,
    status: str,
    review_priority: str,
    z3_status: str,
    guarantees: tuple[str, ...],
    missing: tuple[str, ...],
) -> str:
    if status == "protected" and z3_status == "unsat":
        return "Hypothesis contradicted by a Z3 UNSAT counter-proof and supporting guarantees."
    if status == "protected":
        return "Local sanitizer or guarantee covers the suspicious dataflow path."
    if status == "false_positive_likely":
        return "Evidence matches a known false-positive context rather than an exploitable secret/value."
    if missing:
        return f"Missing proof for {case_type}: {', '.join(missing)}."
    if review_priority in {"critical", "high"}:
        return f"{case_type} has high-priority evidence and no sufficient local guarantee."
    return f"{case_type} needs manual review."


def _human_next_steps(case_type: str, status: str, missing: tuple[str, ...]) -> list[str]:
    if status in {"protected", "false_positive_likely"}:
        return [
            "Confirm the mined guarantee matches the reported sink.",
            "Keep or add a regression test for the defensive pattern.",
        ]
    if case_type == "path_traversal_possible":
        return [
            "Confirm whether the path component is attacker-controlled.",
            "Trace all production callers and verify whether they pass constants or boundary-enforced paths.",
            "Verify whether all paths pass through a boundary-enforcing helper.",
            "Check whether absolute paths, symlinks, and ../ are rejected.",
        ]
    if case_type == "idor_bola_possible":
        return [
            "Confirm whether the object identifier is attacker-controlled.",
            "Check whether the query scopes by current user/source/tenant.",
            "Verify whether the object is returned, modified, or deleted.",
        ]
    if case_type == "unsafe_deserialization_possible":
        return [
            "Confirm whether serialized bytes can be attacker-controlled.",
            "Check whether signing, allowlisting, or safe serialization is enforced.",
        ]
    if case_type == "xss_possible":
        return [
            "Confirm whether interpolated values are user-controlled.",
            "Check whether all interpolated values are escaped before Markup/rendering.",
        ]
    if case_type == "hardcoded_secret_possible":
        return [
            "Check whether the value is a real secret, not a header or parameter name.",
            "Verify whether it is active and in production scope.",
        ]
    if case_type == "command_injection_possible":
        return [
            "Confirm whether the command argument is attacker-controlled.",
            "Check whether shell=True is necessary and whether arguments are escaped.",
        ]
    if case_type == "ssrf_possible":
        return [
            "Confirm whether the URL host is attacker-controlled.",
            "Check whether hosts are allowlisted before outbound requests.",
        ]
    if case_type == "sql_injection_possible":
        return [
            "Confirm whether SQL fragments include attacker-controlled data.",
            "Check whether parameterized queries are enforced.",
        ]
    return [f"Review missing proof: {item}." for item in missing] or ["Review the evidence manually."]


def _finding_dataflow(metadata: dict[str, Any], hypothesis: dict[str, Any]) -> dict[str, Any]:
    dataflow = metadata.get("dataflow")
    if not isinstance(dataflow, dict):
        dataflow = hypothesis.get("dataflow")
    return dataflow if isinstance(dataflow, dict) else {}


def _guarantee_expressions(hypothesis: dict[str, Any], dataflow: dict[str, Any]) -> tuple[str, ...]:
    values = []
    for guarantee in hypothesis.get("guarantee_beliefs", []):
        if isinstance(guarantee, dict):
            values.append(str(guarantee.get("expression", "")))
        else:
            values.append(str(guarantee))
    values.extend(str(item) for item in dataflow.get("guarantees", []))
    return _strings(values)


def _missing_guarantees(hypothesis: dict[str, Any], dataflow: dict[str, Any]) -> tuple[str, ...]:
    values = [str(item) for item in hypothesis.get("missing_guarantees", [])]
    values.extend(str(item) for item in dataflow.get("missing_guarantees", []))
    return _strings(values)


def _z3_status(hypothesis: dict[str, Any]) -> str:
    z3 = hypothesis.get("z3")
    if isinstance(z3, dict):
        return str(z3.get("status") or "not_applicable")
    return "not_applicable"


def _iter_dataflow_paths(
    summaries: dict[str, DataFlowSummary] | Iterable[DataFlowSummary] | None,
) -> list[DataFlowPath]:
    if summaries is None:
        return []
    values = summaries.values() if isinstance(summaries, dict) else summaries
    return sorted(
        [path for summary in values for path in summary.paths],
        key=lambda path: (
            path.file_path,
            path.function_name,
            path.sink_line or 0,
            path.source.expression,
            path.sink.expression,
        ),
    )


def _hardcoded_header_false_positive(case_type: str, guarantees: tuple[str, ...], text: str) -> bool:
    if case_type != "hardcoded_secret_possible":
        return False
    guarantee_text = " ".join(guarantees).lower()
    if "credential.value_is_header_name" in guarantee_text or "credential.value_is_runtime_supplied" in guarantee_text:
        return True
    return "authorization" in text and ("header" in text or "bearer" in text)


def _runtime_surface_low_risk(text: str, guarantees: tuple[str, ...]) -> bool:
    guarantee_text = " ".join(guarantees).lower()
    return any(token in text or token in guarantee_text for token in [
        "tests/",
        "/test",
        "migration",
        "alembic",
        "runtime.surface.test",
        "runtime.surface.migration",
        "runtime.surface.deployment_or_packaging",
    ])


def _strings(values: Iterable[Any]) -> tuple[str, ...]:
    seen = set()
    result = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        result.append(item)
    return tuple(result)


def _dedupe_cases(cases: Iterable[AuditCase]) -> list[AuditCase]:
    seen = set()
    result = []
    for case in cases:
        key = (
            case.case_type,
            _norm_path(case.file),
            case.line or 0,
            case.source,
            case.sink,
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(case)
    return result


def _case_id(*parts: object) -> str:
    raw = "\x1f".join(str(part or "") for part in parts)
    raw = re.sub(r"\s+", " ", raw)
    return "case_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _norm_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower()


def _match_route_context(
    case: AuditCase,
    candidates: list[Any],
    function_spans: dict[str, tuple[int, int]],
) -> dict[str, Any]:
    if not candidates:
        return {}

    line = case.line or 0
    span_matches = []
    if line:
        for route in candidates:
            handler = _short_handler(_route_value(route, "handler"))
            span = function_spans.get(handler)
            if span and span[0] <= line <= span[1]:
                span_matches.append(route)
    if span_matches:
        return _route_context(span_matches[0], confidence=0.9)

    if len(candidates) == 1:
        return _route_context(candidates[0], confidence=0.55)

    return {}


def _route_context(route: Any, *, confidence: float) -> dict[str, Any]:
    return {
        "framework": _route_value(route, "framework"),
        "route": _route_value(route, "route"),
        "methods": list(_route_values(route, "methods")),
        "handler": _route_value(route, "handler"),
        "decorators": list(_route_values(route, "decorators")),
        "auth_guarantees": list(_route_values(route, "auth_guarantees")),
        "params": list(_route_values(route, "params")),
        "confidence": round(float(confidence), 2),
    }


def _function_spans_by_file(source_contexts: dict[str, str]) -> dict[str, dict[str, tuple[int, int]]]:
    spans_by_file: dict[str, dict[str, tuple[int, int]]] = {}
    for file_path, source in source_contexts.items():
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        spans = {}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                start = int(getattr(node, "lineno", 0) or 0)
                end = int(getattr(node, "end_lineno", start) or start)
                if start:
                    spans[node.name] = (start, end)
        spans_by_file[_norm_path(file_path)] = spans
    return spans_by_file


def _route_value(route: Any, name: str) -> str:
    if isinstance(route, dict):
        return str(route.get(name) or "")
    return str(getattr(route, name, "") or "")


def _route_values(route: Any, name: str) -> tuple[str, ...]:
    value = route.get(name, ()) if isinstance(route, dict) else getattr(route, name, ())
    if isinstance(value, str):
        return (value,) if value else ()
    return tuple(str(item) for item in value if str(item))


def _short_handler(handler: str) -> str:
    return str(handler or "").rsplit(".", 1)[-1]


def _structured_dataflow_from_path(path: DataFlowPath) -> dict[str, Any]:
    """Keep the rich path proof alongside AuditCase's legacy string fields."""

    guard_applicability = getattr(path, "guard_applicability", None)
    if not isinstance(guard_applicability, dict):
        guards = tuple((*path.guarantees, *path.sanitizers))
        source_order = _node_order(path.source)
        sink_order = _node_order(path.sink)
        guard_orders = tuple(_node_order(node) for node in guards)
        positions_known = bool(
            source_order is not None
            and sink_order is not None
            and all(order is not None for order in guard_orders)
        )
        ordered_guards = bool(
            positions_known
            and source_order <= sink_order
            and all(
                source_order <= order <= sink_order
                for order in guard_orders
                if order is not None
            )
            and _guards_are_on_serialized_path(path, guards)
        )
        if guards and ordered_guards:
            guard_applicability = {
                "guard_applicable": True,
                "reason": "guard_on_dataflow_path_before_sink",
            }
        elif guards:
            guard_applicability = {
                "guard_applicable": False,
                "reason": (
                    "guard_after_sink"
                    if positions_known
                    and any(
                        order > sink_order
                        for order in guard_orders
                        if order is not None and sink_order is not None
                    )
                    else "flow_not_demonstrated"
                ),
            }
        else:
            guard_applicability = {
                "guard_applicable": False,
                "reason": "no_applicable_guard",
            }

    diagnostics = list(getattr(path, "diagnostics", ()) or ())
    rejection_reason = str(getattr(path, "rejection_reason", "") or "")
    truncation_reason = str(getattr(path, "truncation_reason", "") or "")
    if not truncation_reason:
        for diagnostic in diagnostics:
            reason = (
                diagnostic.get("reason") or diagnostic.get("code")
                if isinstance(diagnostic, dict)
                else diagnostic
            )
            if str(reason).startswith("analysis_truncated_") or reason == "cycle_detected":
                truncation_reason = str(reason)
                break

    return {
        "schema_version": STRUCTURED_DATAFLOW_SCHEMA_VERSION,
        "source": _structured_node(path.source, path.file_path),
        "sink": _structured_node(path.sink, path.file_path),
        "ordered_nodes": [node.to_dict() for node in path.nodes],
        "ordered_edges": [edge.to_dict() for edge in path.edges],
        "function_context": path.function_name,
        "guard_applicability": _json_safe(guard_applicability),
        "rejection_reason": rejection_reason,
        "truncation_reason": truncation_reason,
    }


def _structured_dataflow_from_payload(
    dataflow: dict[str, Any],
    *,
    default_file: str,
    hypothesis: dict[str, Any],
) -> dict[str, Any]:
    if not dataflow:
        return {}

    source_value = dataflow.get("source", "")
    sink_value = dataflow.get("sink", "")
    guard_applicability = (
        dataflow.get("guard_applicability")
        or hypothesis.get("guard_applicability")
    )
    if not isinstance(guard_applicability, (dict, list)):
        applicable = hypothesis.get("guard_applicable")
        reason = hypothesis.get("guard_applicability_reason") or hypothesis.get("reason")
        if isinstance(applicable, bool):
            guard_applicability = {
                "guard_applicable": applicable,
                "reason": str(reason or ("applicable_guard" if applicable else "no_applicable_guard")),
            }
        else:
            guard_applicability = {
                "guard_applicable": bool(dataflow.get("guarantees") or dataflow.get("sanitizers")),
                "reason": (
                    "guard_on_dataflow_path_before_sink"
                    if dataflow.get("guarantees") or dataflow.get("sanitizers")
                    else "no_applicable_guard"
                ),
            }

    nodes = dataflow.get("nodes")
    if not isinstance(nodes, list):
        nodes = [
            {
                "kind": "flow_step",
                "expression": str(expression),
            }
            for expression in dataflow.get("path", [])
        ]
    edges = dataflow.get("edges")
    if not isinstance(edges, list):
        edges = []

    file_path = str(dataflow.get("file") or default_file)
    return {
        "schema_version": STRUCTURED_DATAFLOW_SCHEMA_VERSION,
        "source": _structured_payload_endpoint(
            source_value,
            file_path=file_path,
            line=dataflow.get("source_line"),
            column=dataflow.get("source_column"),
        ),
        "sink": _structured_payload_endpoint(
            sink_value,
            file_path=file_path,
            line=dataflow.get("sink_line"),
            column=dataflow.get("sink_column"),
        ),
        "ordered_nodes": _json_safe(nodes),
        "ordered_edges": _json_safe(edges),
        "function_context": str(dataflow.get("function") or ""),
        "guard_applicability": _json_safe(guard_applicability),
        "rejection_reason": str(
            dataflow.get("rejection_reason")
            or hypothesis.get("rejection_reason")
            or ""
        ),
        "truncation_reason": str(
            dataflow.get("truncation_reason")
            or hypothesis.get("truncation_reason")
            or ""
        ),
    }


def _structured_node(node: Any, default_file: str) -> dict[str, Any]:
    metadata = getattr(node, "metadata", None)
    metadata = metadata if isinstance(metadata, dict) else {}
    column = getattr(node, "column", None)
    if column is None:
        column = metadata.get("column")
    return {
        "file": str(getattr(node, "file_path", "") or metadata.get("file") or default_file),
        "line": getattr(node, "line", None),
        "column": column,
        "symbol": str(getattr(node, "expression", "") or ""),
    }


def _structured_payload_endpoint(
    value: Any,
    *,
    file_path: str,
    line: Any,
    column: Any,
) -> dict[str, Any]:
    if isinstance(value, dict):
        return {
            "file": str(value.get("file") or file_path),
            "line": value.get("line", line),
            "column": value.get("column", column),
            "symbol": str(value.get("symbol") or value.get("expression") or ""),
        }
    return {
        "file": file_path,
        "line": line,
        "column": column,
        "symbol": str(value or ""),
    }


def _node_order(node: Any) -> int | None:
    value = getattr(node, "statement_order", None)
    if isinstance(value, int):
        return value
    line = getattr(node, "line", None)
    return line if isinstance(line, int) else None


def _guards_are_on_serialized_path(path: DataFlowPath, guards: tuple[Any, ...]) -> bool:
    node_ids = [str(getattr(node, "node_id", "") or "") for node in path.nodes]
    source_id = str(getattr(path.source, "node_id", "") or "")
    sink_id = str(getattr(path.sink, "node_id", "") or "")
    guard_ids = [str(getattr(node, "node_id", "") or "") for node in guards]
    if (
        not source_id
        or not sink_id
        or any(not guard_id for guard_id in guard_ids)
        or source_id not in node_ids
        or sink_id not in node_ids
        or any(guard_id not in node_ids for guard_id in guard_ids)
    ):
        return False
    source_index = node_ids.index(source_id)
    sink_index = node_ids.index(sink_id)
    if not all(source_index <= node_ids.index(guard_id) <= sink_index for guard_id in guard_ids):
        return False
    edge_pairs = {
        (
            str(getattr(edge, "source_id", "") or ""),
            str(getattr(edge, "target_id", "") or ""),
        )
        for edge in path.edges
    }
    return bool(
        source_index < sink_index
        and all(
            (left, right) in edge_pairs
            for left, right in zip(
                node_ids[source_index:sink_index],
                node_ids[source_index + 1:sink_index + 1],
            )
        )
    )


__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "STRUCTURED_DATAFLOW_SCHEMA_VERSION",
    "AUDIT_CASE_STATUSES",
    "REVIEW_PRIORITIES",
    "AuditCase",
    "audit_case_from_finding",
    "audit_case_from_dataflow_path",
    "attach_route_context_to_audit_cases",
    "build_audit_cases",
    "interesting_audit_cases",
    "sort_audit_cases",
    "summarize_audit_cases",
    "summarize_guarantees",
]
