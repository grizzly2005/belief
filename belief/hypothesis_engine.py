"""Hypothesis enrichment for BELIEF quick-scan findings.

The engine attaches optional metadata that explains whether mined guarantees
weaken, contradict, or fail to address a potential danger. It does not create
new findings and it does not force arbitrary predicates into Z3.
"""

from __future__ import annotations

import ast
import hashlib
import re
from typing import Iterable

from .belief_logic_adapter import check_belief_boolean_contradictions
from .guarantee_index import GuaranteeIndex, attach_called_function_guarantees
from .models import (
    Belief,
    EpistemicStatus,
    Finding,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from .reportability.guards import (
    GuardApplicability,
    assess_guard_applicability,
    blockers_for,
    classify_guard,
)

HYPOTHESIS_STATUSES = {"unproven", "weakened", "strengthened", "contradicted", "all"}


def attach_hypotheses_to_findings(
    findings: Iterable[Finding],
    guarantee_beliefs: Iterable[Belief],
    *,
    show_proofs: bool = False,
    guarantee_index: GuaranteeIndex | None = None,
    local_contexts: dict[str, str] | None = None,
    dataflow_summaries: dict | Iterable | None = None,
    show_dataflow: bool = False,
) -> list[Finding]:
    """Attach hypothesis metadata to classified findings in place."""
    guarantees = _sort_guarantees(guarantee_beliefs)
    enriched = list(findings)
    for finding in enriched:
        hypothesis = hypothesis_for_finding(
            finding,
            guarantees,
            show_proofs=show_proofs,
            guarantee_index=guarantee_index,
            local_context=local_contexts,
            dataflow_summaries=dataflow_summaries,
            show_dataflow=show_dataflow,
        )
        if hypothesis is None:
            continue
        metadata = dict(finding.metadata or {})
        metadata["hypothesis"] = hypothesis
        finding.metadata = metadata
    return enriched


def hypothesis_for_finding(
    finding: Finding,
    guarantee_beliefs: Iterable[Belief],
    *,
    show_proofs: bool = False,
    guarantee_index: GuaranteeIndex | None = None,
    local_context: str | dict[str, str] | None = None,
    dataflow_summaries: dict | Iterable | None = None,
    show_dataflow: bool = False,
) -> dict | None:
    """Build one hypothesis metadata object for a finding, if classified."""
    hypothesis_type = classify_finding_hypothesis(finding)
    if hypothesis_type is None:
        return None

    propagated_guarantees = attach_called_function_guarantees(
        finding,
        local_context,
        guarantee_index,
    )
    candidate_guarantees = _matching_guarantees(
        hypothesis_type,
        [*list(guarantee_beliefs), *propagated_guarantees],
        finding,
    )
    sink_function = _finding_function_context(finding, local_context, guarantee_index)
    evaluated_guards = [
        _guard_applicability_for_belief(
            hypothesis_type,
            finding,
            belief,
            sink_function=sink_function,
        )
        for belief in candidate_guarantees
    ]
    guarantees = [
        belief
        for belief, applicability in zip(candidate_guarantees, evaluated_guards, strict=True)
        if applicability.applicable
    ]
    guarantee_exprs = {belief.predicate.expression.lower() for belief in guarantees}
    missing = _missing_guarantees(hypothesis_type, guarantee_exprs)
    danger_beliefs = _danger_beliefs(hypothesis_type, finding)
    proof_payload = _try_counterproof(hypothesis_type, finding, guarantees)
    contradictions: list[dict] = []

    status = _initial_status(hypothesis_type, guarantees)
    if proof_payload and proof_payload.get("status") == "unsat":
        status = "contradicted"
        contradictions.append({
            "backend": proof_payload.get("backend", "z3_logic_ir"),
            "unsat_core": proof_payload.get("unsat_core", []),
        })
    elif guarantees:
        status = "weakened"

    payload = {
        "hypothesis_type": hypothesis_type,
        "type": hypothesis_type,
        "danger_beliefs": danger_beliefs,
        "guarantee_beliefs": [_guarantee_to_dict(belief) for belief in guarantees],
        "missing_guarantees": missing,
        "contradictions": contradictions,
        "status": status,
        "human_next_steps": _human_next_steps(hypothesis_type, status, missing),
        "guard_applicability": [item.to_dict() for item in evaluated_guards],
        "blockers": list(blockers_for(evaluated_guards)),
    }
    if proof_payload is not None:
        payload["z3"] = {
            "checked": True,
            "status": proof_payload.get("status"),
            "unsat_core": proof_payload.get("unsat_core", []),
            "backend": proof_payload.get("backend", "z3_logic_ir"),
        }
        if show_proofs:
            payload["proof"] = proof_payload
    else:
        payload["z3"] = {"checked": False, "status": "not_applicable"}

    if dataflow_summaries:
        from .dataflow import dataflow_for_finding

        dataflow_payload = dataflow_for_finding(
            finding,
            dataflow_summaries,
            show_dataflow=show_dataflow,
        )
        if dataflow_payload:
            payload["dataflow"] = dataflow_payload
            payload["status"] = _status_with_dataflow(
                payload["status"],
                dataflow_payload,
            )
    return payload


def filter_findings_by_hypothesis_status(
    findings: Iterable[Finding],
    status: str,
) -> list[Finding]:
    """Filter findings by hypothesis status, accepting `all` as a no-op."""
    normalized = (status or "all").strip().lower()
    if normalized not in HYPOTHESIS_STATUSES:
        accepted = ", ".join(sorted(HYPOTHESIS_STATUSES))
        raise ValueError(f"invalid hypothesis status: {status}. Accepted: {accepted}")
    if normalized == "all":
        return list(findings)
    return [
        finding for finding in findings
        if (
            isinstance(finding.metadata, dict)
            and isinstance(finding.metadata.get("hypothesis"), dict)
            and finding.metadata["hypothesis"].get("status") == normalized
        )
    ]


def classify_finding_hypothesis(finding: Finding) -> str | None:
    """Return the hypothesis family a finding belongs to."""
    cwe = str(finding.cwe or "").upper()
    text = " ".join([
        str(finding.rule_id or ""),
        str(finding.title or ""),
        str(finding.description or ""),
        str(finding.evidence or ""),
    ]).lower()

    if cwe in {"CWE-22", "CWE-73"} or "path traversal" in text:
        return "path_traversal_possible"
    if cwe == "CWE-79" or "xss" in text or "markup" in text or "html" in text:
        return "xss_possible"
    if cwe in {"CWE-639", "CWE-862", "CWE-863"} or any(
        token in text for token in ["idor", "access control", "owner_id", "source_id", "user_id"]
    ):
        return "authorization_bypass_possible"
    if cwe == "CWE-502" or any(token in text for token in ["pickle", "deserial", "yaml.load"]):
        return "unsafe_deserialization_possible"
    if cwe == "CWE-798" or "hardcoded credential" in text or "credential" in text:
        return "hardcoded_credential_possible"
    return None


def _matching_guarantees(
    hypothesis_type: str,
    guarantee_beliefs: Iterable[Belief],
    finding: Finding,
) -> list[Belief]:
    expressions = _guarantee_expression_fragments(hypothesis_type, finding)
    matched = []
    for belief in guarantee_beliefs:
        expr = str(belief.predicate.expression or "").lower()
        metadata = getattr(belief, "source_metadata", {}) or {}
        if metadata.get("category") != "guarantee" and metadata.get("source") != "invariant_miner":
            continue
        is_propagated = bool(metadata.get("propagated"))
        propagated_to_this_finding = (
            not metadata.get("propagated_to_finding_id")
            or metadata.get("propagated_to_finding_id") == finding.id
        )
        if is_propagated and not propagated_to_this_finding:
            continue
        if any(fragment in expr for fragment in expressions):
            matched.append(belief)
    return _sort_guarantees(matched)


def _guarantee_expression_fragments(hypothesis_type: str, finding: Finding) -> list[str]:
    if hypothesis_type == "path_traversal_possible":
        return [
            "path.is_normalized",
            "path.is_within_store",
            "storage.path.enforces_store_boundary",
            "storage.verify.enforces_store_boundary",
            "storage.store_contains.enforces_store_boundary",
            "filename.matches_allowed_pattern",
            "filename.server_generated",
            "filename.user_controlled == false",
            "filename.basename_only",
        ]
    if hypothesis_type == "xss_possible":
        return [
            "html_output.user_values_escaped",
            "markup.has_unescaped_user_input == false",
        ]
    if hypothesis_type == "authorization_bypass_possible":
        return [
            "route.requires_login",
            "route.requires_admin",
            "query.scoped_to_current_source",
            "query.scoped_to_current_user",
        ]
    if hypothesis_type == "unsafe_deserialization_possible":
        return [
            "deserialization.input_trusted",
            "runtime.surface.test",
            "runtime.surface.deployment_or_packaging",
        ]
    if hypothesis_type == "hardcoded_credential_possible":
        return [
            "credential.value_is_header_name",
            "credential.value_is_runtime_supplied",
            "runtime.surface.test",
        ]
    return []


def _guard_applicability_for_belief(
    hypothesis_type: str,
    finding: Finding,
    belief: Belief,
    *,
    sink_function: str = "",
) -> GuardApplicability:
    metadata = belief.source_metadata or {}
    expression = str(belief.predicate.expression or "")
    category = classify_guard(expression, str(metadata.get("guard_category") or ""))
    propagated_to_finding = bool(metadata.get("propagated")) and (
        not metadata.get("propagated_to_finding_id")
        or metadata.get("propagated_to_finding_id") == finding.id
    )
    explicit_call_path = bool(metadata.get("call_path"))
    propagated = propagated_to_finding and (
        explicit_call_path or _propagated_call_matches(metadata)
    )
    finding_metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    finding_dataflow = (
        finding_metadata.get("dataflow")
        if isinstance(finding_metadata.get("dataflow"), dict)
        else {}
    )
    sink_line = (
        _int_or_none(finding_metadata.get("sink_line"))
        or _int_or_none(finding_dataflow.get("sink_line"))
        or _int_or_none(finding.end_line)
        or _int_or_none(finding.line)
    )
    precise_variables = (
        ",".join(str(item) for item in belief.predicate.variables if str(item))
        if "result_used" in metadata
        else ""
    )
    guard_value = str(
        metadata.get("guard_value")
        or metadata.get("validated_value")
        or precise_variables
    )
    sink_value = str(
        finding_metadata.get("sink_value")
        or finding_metadata.get("object_id_source")
        or finding_metadata.get("source_value")
        or _metadata_variables(finding_metadata.get("predicate_variables"))
        or _metadata_variables(finding_dataflow.get("intermediate_variables"))
        or finding_dataflow.get("source")
        or finding_dataflow.get("sink")
        or finding_metadata.get("predicate_expression")
        or ""
    )
    result_used = _bool_or_none(
        metadata.get("result_used")
        if "result_used" in metadata
        else metadata.get("return_value_used")
    )
    guard_function = str(metadata.get("function_qualname") or belief.scope.function_name or "")
    finding_function_name = str(
        finding_metadata.get("function_name")
        or finding_metadata.get("function")
        or ""
    )
    finding_class_name = str(finding_metadata.get("class_name") or "")
    finding_qualname = str(finding_metadata.get("function_qualname") or "") or (
        f"{finding_class_name}.{finding_function_name}"
        if finding_class_name and finding_function_name
        else ""
    )
    effective_sink_function = str(
        finding_qualname
        or sink_function
        or finding_function_name
        or ""
    )
    same_execution_context = bool(
        _paths_related(str(finding.file or ""), str(belief.scope.file_path or ""))
        and guard_function
        and effective_sink_function
        and _function_contexts_match(guard_function, effective_sink_function)
    )
    if propagated and sink_value:
        # attach_called_function_guarantees traced this helper call into the
        # concrete sink value; helper-local variable names need not match.
        guard_value = sink_value
    sink_local_query_guard = str(metadata.get("rule_id") or "").startswith(
        "INVARIANT_QUERY_"
    )
    query_result_linked = bool(
        propagated
        or (
            _int_or_none(belief.scope.line_start) is not None
            and sink_line is not None
            and _int_or_none(belief.scope.line_start) == sink_line
        )
    )
    return assess_guard_applicability(
        expression,
        category=category or "",
        guard_file=str(belief.scope.file_path or ""),
        guard_line=_int_or_none(belief.scope.line_start),
        guard_function=guard_function,
        guard_route=str(metadata.get("route") or ""),
        guard_value=guard_value,
        sink_file=str(finding.file or ""),
        source_line=_int_or_none(finding_dataflow.get("source_line")),
        sink_line=sink_line,
        sink_function=effective_sink_function,
        sink_route=str(finding_metadata.get("route") or finding_metadata.get("path") or ""),
        sink_value=sink_value,
        case_type=" ".join([
            hypothesis_type,
            str(finding.title or ""),
            str(finding.description or ""),
        ]),
        direct_context=same_execution_context,
        propagated=propagated,
        call_path=bool(propagated or explicit_call_path),
        result_used=result_used,
        bypass_possible=bool(
            metadata.get("bypass_possible")
            or metadata.get("bypass")
            or (sink_local_query_guard and not query_result_linked)
        ),
    )


def _propagated_call_matches(metadata: dict) -> bool:
    via = str(metadata.get("propagated_via") or "")
    registered = str(metadata.get("registered_function") or "")
    via_tokens = re.findall(r"[a-z_][a-z0-9_]*", via.lower())
    registered_tokens = re.findall(r"[a-z_][a-z0-9_]*", registered.lower())
    if not via_tokens or not registered_tokens:
        return False
    if via_tokens[-1] != registered_tokens[-1]:
        return False
    if len(registered_tokens) == 1:
        return True
    return registered_tokens[-2] in via_tokens[:-1]


def _finding_function_context(
    finding: Finding,
    local_context: str | dict[str, str] | None,
    guarantee_index: GuaranteeIndex | None,
) -> str:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    explicit_qualname = str(metadata.get("function_qualname") or "")
    function_name = str(metadata.get("function_name") or metadata.get("function") or "")
    class_name = str(metadata.get("class_name") or "")
    explicit = explicit_qualname or (
        f"{class_name}.{function_name}" if class_name and function_name else function_name
    )
    if explicit_qualname:
        return explicit_qualname

    source = ""
    if isinstance(local_context, str):
        source = local_context
    elif isinstance(local_context, dict):
        normalized_file = str(finding.file or "").replace("\\", "/")
        source = str(local_context.get(normalized_file) or "")
        if not source:
            for path, candidate in local_context.items():
                if str(path).replace("\\", "/").endswith(normalized_file):
                    source = str(candidate)
                    break
    if not source and guarantee_index is not None:
        normalized_file = str(finding.file or "").replace("\\", "/")
        source = str(guarantee_index.sources.get(normalized_file) or "")
    if not source and "\n" in str(finding.evidence or ""):
        source = str(finding.evidence)
    if not source:
        return explicit
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return explicit

    finding_dataflow = (
        metadata.get("dataflow")
        if isinstance(metadata.get("dataflow"), dict)
        else {}
    )
    target_line = (
        _int_or_none(metadata.get("sink_line"))
        or _int_or_none(finding_dataflow.get("sink_line"))
        or _int_or_none(finding.end_line)
        or _int_or_none(finding.line)
    )
    if target_line is None:
        return explicit
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    matches: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        end_line = _int_or_none(getattr(node, "end_lineno", None)) or node.lineno
        if node.lineno <= target_line <= end_line:
            names = [node.name]
            current = node
            while (parent := parents.get(id(current))) is not None:
                if isinstance(parent, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    names.append(parent.name)
                current = parent
            matches.append((end_line - node.lineno, node.lineno, ".".join(reversed(names))))
    inferred = min(matches)[2] if matches else ""
    if inferred and (
        not explicit
        or inferred.rsplit(".", 1)[-1].lower() == explicit.rsplit(".", 1)[-1].lower()
    ):
        return inferred
    return explicit


def _function_contexts_match(left: str, right: str) -> bool:
    normalized_left = str(left or "").strip().lower()
    normalized_right = str(right or "").strip().lower()
    if not normalized_left or not normalized_right:
        return False
    if "." in normalized_left and "." in normalized_right:
        return normalized_left == normalized_right
    return normalized_left.rsplit(".", 1)[-1] == normalized_right.rsplit(".", 1)[-1]


def _missing_guarantees(hypothesis_type: str, guarantee_exprs: set[str]) -> list[str]:
    def has(fragment: str) -> bool:
        return any(fragment in expr for expr in guarantee_exprs)

    if hypothesis_type == "path_traversal_possible":
        missing = []
        if not (
            has("path.is_within_store")
            or has("storage.path.enforces_store_boundary")
            or has("storage.verify.enforces_store_boundary")
            or has("storage.store_contains.enforces_store_boundary")
        ):
            missing.append("store boundary proof")
        if not (
            has("filename.matches_allowed_pattern")
            or has("filename.server_generated")
            or has("filename.user_controlled == false")
        ):
            missing.append("filename allow-list or server-generated filename")
        return missing
    if hypothesis_type == "xss_possible":
        if has("html_output.user_values_escaped") or has("markup.has_unescaped_user_input == false"):
            return []
        return ["HTML escaping proof at the sink"]
    if hypothesis_type == "authorization_bypass_possible":
        missing = []
        if not (has("route.requires_login") or has("route.requires_admin")):
            missing.append("route authentication decorator")
        if not (has("query.scoped_to_current_source") or has("query.scoped_to_current_user")):
            missing.append("query scoped to current principal")
        return missing
    if hypothesis_type == "unsafe_deserialization_possible":
        if has("deserialization.input_trusted"):
            return []
        return ["trusted deserialization boundary or safe loader proof"]
    if hypothesis_type == "hardcoded_credential_possible":
        if has("credential.value_is_header_name") or has("credential.value_is_runtime_supplied"):
            return []
        return ["proof that value is not a stored secret"]
    return []


def _danger_beliefs(hypothesis_type: str, finding: Finding) -> list[dict]:
    expression = {
        "path_traversal_possible": "path.may_escape_store == true",
        "xss_possible": "markup.has_unescaped_user_input == true",
        "authorization_bypass_possible": "object.access_unscoped == true",
        "unsafe_deserialization_possible": "deserialized_data.is_attacker_controlled == true",
        "hardcoded_credential_possible": "credentials.stored_in_code == true",
    }.get(hypothesis_type, "danger.exists == true")
    return [{
        "expression": expression,
        "source_finding_id": finding.id,
        "file": finding.file,
        "line": finding.line,
    }]


def _try_counterproof(
    hypothesis_type: str,
    finding: Finding,
    guarantees: list[Belief],
) -> dict | None:
    counter_expr = {
        "path_traversal_possible": "path.may_escape_store == false",
        "xss_possible": "markup.has_unescaped_user_input == false",
        "authorization_bypass_possible": "object.access_unscoped == false",
    }.get(hypothesis_type)
    danger_expr = _danger_beliefs(hypothesis_type, finding)[0]["expression"]
    if counter_expr is None:
        return None

    proof_guarantee = _strongest_counterproof_guarantee(hypothesis_type, guarantees)
    if proof_guarantee is None:
        return None

    danger = _synthetic_belief(
        expression=danger_expr,
        belief_id=_stable_id("danger", finding.id, hypothesis_type),
        file=finding.file,
        line=finding.line,
        description=f"Finding danger hypothesis for {hypothesis_type}.",
    )
    counter = _synthetic_belief(
        expression=counter_expr,
        belief_id=proof_guarantee.id,
        file=proof_guarantee.scope.file_path,
        line=proof_guarantee.scope.line_start,
        description=f"Counter-proof derived from guarantee {proof_guarantee.id}.",
    )
    proof = check_belief_boolean_contradictions([danger, counter])
    if proof is None:
        return None
    payload = proof.to_dict()
    payload["derived_from_guarantee_id"] = proof_guarantee.id
    payload["derived_from_guarantee_expression"] = proof_guarantee.predicate.expression
    return payload


def _strongest_counterproof_guarantee(
    hypothesis_type: str,
    guarantees: list[Belief],
) -> Belief | None:
    if not guarantees:
        return None
    strong_fragments = {
        "path_traversal_possible": [
            "storage.path.enforces_store_boundary",
            "storage.verify.enforces_store_boundary",
            "storage.store_contains.enforces_store_boundary",
            "path.is_within_store",
        ],
        "xss_possible": [
            "markup.has_unescaped_user_input == false",
            "html_output.user_values_escaped",
        ],
        "authorization_bypass_possible": [
            "query.scoped_to_current_source",
            "query.scoped_to_current_user",
            "route.requires_admin",
        ],
    }.get(hypothesis_type, [])
    for belief in guarantees:
        expr = belief.predicate.expression.lower()
        if any(fragment in expr for fragment in strong_fragments):
            return belief
    return None


def _initial_status(hypothesis_type: str, guarantees: list[Belief]) -> str:
    if guarantees:
        return "weakened"
    if hypothesis_type in {
        "path_traversal_possible",
        "unsafe_deserialization_possible",
        "hardcoded_credential_possible",
    }:
        return "strengthened"
    return "unproven"


def _human_next_steps(
    hypothesis_type: str,
    status: str,
    missing: list[str],
) -> list[str]:
    if status == "contradicted":
        return [
            "Review the mined guarantee and linked finding together before suppressing.",
            "Add a regression test that covers the guarantee at the vulnerable-looking sink.",
        ]
    if status == "weakened":
        return [
            "Confirm the guarantee dominates the reported sink across call boundaries.",
            "Promote the guarantee into an explicit unit/integration test if it is security-critical.",
        ]
    if missing:
        return [f"Look for missing proof: {item}." for item in missing]
    if hypothesis_type == "unsafe_deserialization_possible":
        return ["Verify the serialized payload source and replace unsafe deserialization if untrusted."]
    return ["Inspect the dataflow manually; BELIEF found no local counter-proof."]


def _status_with_dataflow(status: str, dataflow_payload: dict) -> str:
    """Adjust only when local dataflow provides useful support."""
    if status == "contradicted":
        return status
    has_counter_evidence = bool(
        dataflow_payload.get("sanitizers") or dataflow_payload.get("guarantees")
    )
    missing = dataflow_payload.get("missing_guarantees") or dataflow_payload.get("missing_sanitizers")
    if has_counter_evidence and status in {"unproven", "strengthened"}:
        return "weakened"
    if missing and not has_counter_evidence and status == "unproven":
        return "strengthened"
    return status


def _guarantee_to_dict(belief: Belief) -> dict:
    metadata = belief.source_metadata or {}
    return {
        "belief_id": belief.id,
        "expression": belief.predicate.expression,
        "file": belief.scope.file_path,
        "line": belief.scope.line_start,
        "function_qualname": metadata.get("function_qualname", ""),
        "rule_id": metadata.get("rule_id", ""),
        "invariant_type": metadata.get("invariant_type", ""),
        "propagated": bool(metadata.get("propagated")),
        "propagated_via": metadata.get("propagated_via", ""),
        "registered_function": metadata.get("registered_function", ""),
    }


def _sort_guarantees(guarantees: Iterable[Belief]) -> list[Belief]:
    return sorted(
        list(guarantees),
        key=lambda belief: (
            belief.scope.file_path,
            belief.scope.line_start or 0,
            belief.scope.function_name or "",
            belief.predicate.expression,
            belief.id,
        ),
    )


def _paths_related(finding_path: str, guarantee_path: str) -> bool:
    if not finding_path or not guarantee_path:
        return False
    finding = finding_path.replace("\\", "/").lower()
    guarantee = guarantee_path.replace("\\", "/").lower()
    return finding == guarantee


def _int_or_none(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    return bool(value)


def _metadata_variables(value: object) -> str:
    if isinstance(value, (list, tuple)):
        return ",".join(str(item) for item in value if str(item))
    return str(value or "")


def _synthetic_belief(
    *,
    expression: str,
    belief_id: str,
    file: str,
    line: int | None,
    description: str,
) -> Belief:
    return Belief(
        predicate=Predicate(
            expression=expression,
            anchor_lines=(line,) if line else (),
            natural_language=description,
        ),
        scope=Scope(file_path=file, line_start=line, line_end=line),
        justification=JustificationCategory.C1_FORMAL_VERIFICATION,
        epistemic_status=EpistemicStatus.BELIEF,
        logic_type=LogicType.FOL,
        confidence_score=1.0,
        id=belief_id,
        source_metadata={
            "source": "hypothesis_engine",
            "rule_id": "HYPOTHESIS_BOOLEAN_COUNTERPROOF",
            "severity": "info",
        },
    )


def _stable_id(*parts: object) -> str:
    text = "\x1f".join(str(part or "") for part in parts)
    text = re.sub(r"\s+", " ", text)
    return "hyp_" + hashlib.sha256(text.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "HYPOTHESIS_STATUSES",
    "attach_hypotheses_to_findings",
    "hypothesis_for_finding",
    "filter_findings_by_hypothesis_status",
    "classify_finding_hypothesis",
]
