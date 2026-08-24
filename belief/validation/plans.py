"""Deterministic, non-executing validation plans for BELIEF audit cases."""

from __future__ import annotations

import copy
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .models import VALIDATION_OUTCOMES, VALIDATION_RESULT_SCHEMA_VERSION
from .models import ValidationResult
from .plan_models import (
    VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION,
    VALIDATION_PLAN_SCHEMA_VERSION,
    VALIDATION_REACHABILITY_SCHEMA_VERSION,
    VALIDATION_STRATEGIES,
    ValidationOracle,
    ValidationPlan,
    ValidationStimulus,
    canonical_digest,
    clean_text,
    json_object,
    normalize_priority,
    unique_strings,
)
from .plan_templates import STOP_CONDITIONS, safety_contract, strategy_spec
from .proof import proof_subject_digest

_PRIORITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_STATUS_ORDER = {
    "actionable": 0,
    "needs_review": 1,
    "protected": 2,
    "false_positive_likely": 3,
}
_WEB_CASES = {
    "idor_bola_possible",
    "path_traversal_possible",
    "sql_injection_possible",
    "ssrf_possible",
    "xss_possible",
}


def build_validation_plan(case: Mapping[str, Any] | Any) -> ValidationPlan:
    """Convert one audit case or explicit contract seed into a safe plan."""

    payload = _case_payload(case)
    subject_kind = clean_text(
        payload.get("subject_kind")
    ) or "audit_case"
    subject_id = clean_text(
        payload.get(
            "seed_id"
            if subject_kind == "validation_contract_seed"
            else "case_id"
        )
    )
    if not subject_id:
        raise ValueError("validation subject is missing its identifier")

    case_type = clean_text(payload.get("case_type")) or "unknown"
    status = clean_text(payload.get("status")) or "unknown"
    spec = strategy_spec(case_type, status)
    return ValidationPlan(
        subject_id=subject_id,
        case_type=case_type,
        case_status=status,
        subject_kind=subject_kind,
        strategy=spec["strategy"],
        objective=spec["objective"],
        priority=normalize_priority(payload.get("review_priority")),
        target=_target(payload),
        evidence_gaps=_evidence_gaps(payload),
        prerequisites=spec["prerequisites"],
        stimuli=spec["stimuli"],
        oracles=spec["oracles"],
        reachability_hints=_reachability(payload),
        stop_conditions=STOP_CONDITIONS,
        safety=safety_contract(case_type),
        metadata=_metadata(payload),
    )


def validation_result_from_plan(
    plan: ValidationPlan,
    *,
    source: str,
    outcome: str,
    confidence: float = 0.5,
    tested: bool = False,
    human_validated: bool = False,
    method: str = "",
    reason: str = "",
    evidence: Sequence[str] = (),
    metadata: Mapping[str, Any] | None = None,
) -> ValidationResult:
    """Create a ValidationResult linked to a plan and its audit case.

    ``tested`` and ``human_validated`` are retained as legacy input claims,
    but they cannot authorize proof promotion.  A separate verified proof
    index must resolve ``metadata.validation_proof`` before reportability or
    reasoning may treat the result as conclusive.
    """

    normalized = clean_text(outcome).lower()
    if normalized not in VALIDATION_OUTCOMES:
        raise ValueError(f"unsupported validation outcome: {normalized!r}")
    if not isinstance(tested, bool) or not isinstance(human_validated, bool):
        raise ValueError(
            "tested and human_validated legacy claims must be booleans"
        )
    supplied_metadata = json_object(metadata)
    reserved_metadata = {
        "validation_plan_id",
        "validation_strategy",
        "case_type",
        "claimed_tested",
        "claimed_human_validated",
        "proof_state",
    }
    overwritten = sorted(reserved_metadata.intersection(supplied_metadata))
    if overwritten:
        raise ValueError(
            "validation result metadata cannot override reserved bindings: "
            + ", ".join(overwritten)
        )
    result_metadata = {
        **supplied_metadata,
        "validation_plan_id": plan.plan_id,
        "validation_strategy": plan.strategy,
        "case_type": plan.case_type,
        "claimed_tested": tested,
        "claimed_human_validated": human_validated,
        "proof_state": "unverified_legacy_claim",
    }
    return ValidationResult(
        subject_id=plan.subject_id,
        subject_kind=plan.subject_kind,
        source=clean_text(source) or "validation_plan",
        outcome=normalized,
        confidence=confidence,
        tested=tested,
        human_validated=human_validated,
        method=clean_text(method),
        reason=clean_text(reason),
        evidence=tuple(str(item) for item in evidence if str(item)),
        metadata=result_metadata,
    )


def build_validation_plan_bundle(audit: Mapping[str, Any]) -> dict[str, Any]:
    """Build a deterministic, offline sidecar without mutating the audit."""

    if not isinstance(audit, Mapping):
        raise ValueError("audit report must be a JSON object")
    rows = audit.get("audit_cases")
    if not isinstance(rows, list):
        raise ValueError("audit report must contain an audit_cases list")

    plans = [build_validation_plan(row) for row in rows]
    ids = [plan.subject_id for plan in plans]
    if len(ids) != len(set(ids)):
        duplicate = next(item for item in ids if ids.count(item) > 1)
        raise ValueError(f"duplicate audit case id: {duplicate}")
    plans.sort(key=_sort_key)

    payload: dict[str, Any] = {
        "schema_version": VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION,
        "source_audit": {
            "schema_version": str(audit.get("schema_version") or "unknown"),
            "target": str(audit.get("target") or ""),
            "sha256": canonical_digest(copy.deepcopy(dict(audit))),
            "audit_case_count": len(rows),
        },
        "execution_boundary": {
            "offline_generation": True,
            "executes_target": False,
            "network_required": False,
            "confirms_vulnerability": False,
            "requires_human_or_harness_result": True,
        },
        "result_schema_version": VALIDATION_RESULT_SCHEMA_VERSION,
        "plan_count": len(plans),
        "counts": {
            "by_strategy": dict(
                sorted(Counter(plan.strategy for plan in plans).items())
            ),
            "by_case_status": dict(
                sorted(Counter(plan.case_status for plan in plans).items())
            ),
        },
        "plans": [plan.to_dict() for plan in plans],
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_validation_plan_bundle(
    audit_path: str | Path,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Create a sidecar file and refuse accidental input replacement."""

    source = Path(audit_path).resolve()
    destination = Path(output_path).resolve()
    if source == destination:
        raise ValueError("validation plan output must differ from audit input")

    audit = json.loads(source.read_text(encoding="utf-8"))
    payload = build_validation_plan_bundle(audit)
    destination.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    try:
        if overwrite:
            destination.write_text(
                rendered,
                encoding="utf-8",
                errors="strict",
            )
        else:
            with destination.open("x", encoding="utf-8") as handle:
                handle.write(rendered)
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite validation plan bundle: {destination}"
        ) from exc
    return payload


def load_validation_plan_bundle(
    path: str | Path,
) -> tuple[dict[str, Any], tuple[ValidationPlan, ...]]:
    """Load a bundle and verify digest, canonical plans, and identifiers."""

    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("validation plan bundle must be a JSON object")
    if payload.get("schema_version") != VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION:
        raise ValueError("unsupported validation plan bundle schema")

    unsigned = dict(payload)
    expected = str(unsigned.pop("deterministic_digest", ""))
    if expected != canonical_digest(unsigned):
        raise ValueError("validation plan bundle deterministic digest mismatch")

    rows = payload.get("plans")
    if not isinstance(rows, list):
        raise ValueError("validation plan bundle plans must be a list")
    plans = tuple(ValidationPlan.from_dict(row) for row in rows)
    if any(
        plan.to_dict() != row
        for plan, row in zip(plans, rows, strict=True)
    ):
        raise ValueError(
            "validation plan bundle contains a non-canonical plan"
        )
    if int(payload.get("plan_count", -1)) != len(plans):
        raise ValueError("validation plan bundle plan_count mismatch")
    if len({plan.plan_id for plan in plans}) != len(plans):
        raise ValueError("validation plan bundle has duplicate plan ids")
    return payload, plans


def _target(case: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        key: copy.deepcopy(case[key])
        for key in ("file", "line", "source", "sink", "rule_id", "cwe")
        if case.get(key) not in (None, "", [], {})
    }
    route = case.get("route_context")
    if isinstance(route, Mapping) and route:
        result["route_context"] = json_object(route)
    return result


def _evidence_gaps(case: Mapping[str, Any]) -> tuple[str, ...]:
    gaps = list(unique_strings(case.get("missing_guarantees")))
    case_type = clean_text(case.get("case_type"))
    status = clean_text(case.get("status"))

    if not clean_text(case.get("source")):
        gaps.append("attacker_controlled_source_not_located")
    if not clean_text(case.get("sink")):
        gaps.append("security_sensitive_sink_not_located")
    if not isinstance(case.get("structured_dataflow"), Mapping):
        gaps.append("ordered_source_to_sink_path_missing")
    if (
        case_type in _WEB_CASES
        and not isinstance(case.get("route_context"), Mapping)
    ):
        gaps.append("runtime_entrypoint_not_mapped")
    gaps.append(
        "runtime_guard_enforcement_not_observed"
        if status in {"protected", "false_positive_likely"}
        else "dynamic_exploitability_not_observed"
    )

    metadata = case.get("metadata")
    if isinstance(metadata, Mapping):
        reportability = metadata.get("reportability")
        if isinstance(reportability, Mapping):
            gaps.extend(
                f"reportability_blocker:{item}"
                for item in unique_strings(
                    reportability.get("blocking_factors")
                )
            )
    return unique_strings(gaps)


def _reachability(case: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {
        "schema_version": VALIDATION_REACHABILITY_SCHEMA_VERSION
    }
    structured = case.get("structured_dataflow")
    if isinstance(structured, Mapping):
        for key in (
            "source",
            "sink",
            "function_context",
            "guard_applicability",
            "rejection_reason",
            "truncation_reason",
        ):
            if structured.get(key) not in (None, "", [], {}):
                result[key] = copy.deepcopy(structured[key])
        for key, limit in (("ordered_nodes", 32), ("ordered_edges", 64)):
            value = structured.get(key)
            if isinstance(value, Sequence) and not isinstance(
                value,
                (str, bytes),
            ):
                result[key] = [
                    json_object(item)
                    for item in list(value)[:limit]
                    if isinstance(item, Mapping)
                ]

    if "source" not in result and clean_text(case.get("source")):
        result["source"] = {"symbol": clean_text(case.get("source"))}
    if "sink" not in result and clean_text(case.get("sink")):
        result["sink"] = {"symbol": clean_text(case.get("sink"))}
    legacy = unique_strings(case.get("dataflow_path"))
    if legacy:
        result["legacy_path"] = list(legacy[:32])
    return result


def _metadata(case: Mapping[str, Any]) -> dict[str, Any]:
    contract_seed = (
        case.get("subject_kind") == "validation_contract_seed"
    )
    result: dict[str, Any] = {
        "generator": (
            "belief.explicit_fixture_contract.v1"
            if contract_seed
            else "belief.evidence_guided_validation.v1"
        ),
        (
            "source_seed_sha256"
            if contract_seed
            else "source_case_sha256"
        ): canonical_digest(dict(case)),
        "proof_subject_sha256": proof_subject_digest(case),
        "human_next_steps": list(
            unique_strings(case.get("human_next_steps"))
        ),
        "guarantees": list(unique_strings(case.get("guarantees"))),
        "sanitizers": list(unique_strings(case.get("sanitizers"))),
    }
    fingerprint = clean_text(case.get("related_finding_fingerprint"))
    if fingerprint:
        result["related_finding_fingerprint"] = fingerprint
    if contract_seed:
        result["origin"] = clean_text(case.get("origin"))
        result["static_support"] = case.get("static_support") is True
        provenance = case.get("static_case_provenance")
        if isinstance(provenance, Sequence) and not isinstance(
            provenance,
            (str, bytes),
        ):
            result["static_case_provenance"] = [
                json_object(item)
                for item in provenance
                if isinstance(item, Mapping)
            ]
        result["validation_contract_seed_schema"] = str(
            case.get("schema_version") or ""
        )
    return result


def _case_payload(case: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(case, Mapping):
        return copy.deepcopy(dict(case))
    serializer = getattr(case, "to_dict", None)
    if callable(serializer):
        payload = serializer()
        if isinstance(payload, Mapping):
            return copy.deepcopy(dict(payload))
    raise ValueError(
        "audit case must be a JSON object or expose to_dict()"
    )


def _sort_key(plan: ValidationPlan) -> tuple[Any, ...]:
    return (
        _STATUS_ORDER.get(plan.case_status, 9),
        _PRIORITY_ORDER.get(plan.priority, 9),
        str(plan.target.get("file") or ""),
        int(plan.target.get("line") or 0),
        plan.case_type,
        plan.subject_id,
    )


__all__ = [
    "VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION",
    "VALIDATION_PLAN_SCHEMA_VERSION",
    "VALIDATION_REACHABILITY_SCHEMA_VERSION",
    "VALIDATION_STRATEGIES",
    "ValidationOracle",
    "ValidationPlan",
    "ValidationStimulus",
    "build_validation_plan",
    "build_validation_plan_bundle",
    "load_validation_plan_bundle",
    "validation_result_from_plan",
    "write_validation_plan_bundle",
]
