"""Trusted preparation and evidence projection for MCP fixture validation.

This module deliberately accepts fixture identifiers only.  It never resolves a
caller-provided path, module, callable, URL, or source string.
"""

from __future__ import annotations

import copy
import hashlib
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from belief.static_analysis_pipeline import (
    STATIC_ANALYSIS_CATEGORIES,
    StaticAnalysisOptions,
    analyze_static_target,
)
from belief.validation.plan_models import ValidationPlan, canonical_digest
from belief.validation.plans import build_validation_plan
from belief.validation.worker.registry import (
    FixtureSpec,
    fixture_registry_digest,
    fixture_source_digest,
    fixture_source_documents,
    get_fixture_spec,
)


REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION = (
    "belief.registered_fixture_binding.v1"
)
MCP_FIXTURE_PREPARATION_SCHEMA_VERSION = (
    "belief.mcp_fixture_preparation.v1"
)
MCP_VALIDATION_RESULT_SCHEMA_VERSION = "belief.mcp_validation_result.v1"
REGISTERED_FIXTURE_EXECUTION_SCOPE = (
    "registered_transparent_fixture_only"
)
REGISTERED_FIXTURE_BINDING_CREATOR = (
    "belief_prepare_validation_fixture"
)
MCP_MAX_STORED_RUNS = 32
MCP_MAX_RESULTS_PER_RUN = 32
MCP_MAX_TOTAL_RESULTS = 128
MCP_MAX_CONCURRENT_VALIDATIONS = 1
MCP_MAX_IN_FLIGHT_REQUESTS = 4
MCP_MIN_VALIDATION_TIMEOUT_MS = 100
MCP_MAX_VALIDATION_TIMEOUT_MS = 10_000

_SOURCE_TARGET_SCHEMA_VERSION = "belief.registered_fixture_source_target.v1"
_STATIC_SCAN_SCHEMA_VERSION = "belief.registered_fixture_static_scan.v1"
_ALLOWED_MATURITY = {
    "candidate",
    "statically_supported",
    "locally_reproduced_on_registered_fixture",
}


class FixtureBindingError(ValueError):
    """A trusted fixture preparation or binding invariant failed."""


@dataclass(frozen=True)
class PreparedFixtureValidation:
    """Canonical artifacts produced from one immutable registry entry."""

    fixture_id: str
    fixture_case_type: str
    fixture_registry_digest: str
    fixture_source_digest: str
    source_target_digest: str
    source_revision: str
    case: dict[str, Any]
    plan: ValidationPlan
    analysis_snapshot: dict[str, Any]
    static_scan: dict[str, Any]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class RegisteredFixtureBinding:
    """Exact executable binding between a run, plan, and first-party fixture."""

    run_id: str
    audit_case_id: str
    fixture_id: str
    fixture_registry_digest: str
    fixture_source_digest: str
    fixture_case_type: str
    validation_plan_id: str
    validation_plan_digest: str
    source_revision: str
    source_target_digest: str
    binding_kind: str = REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION
    created_by: str = REGISTERED_FIXTURE_BINDING_CREATOR
    execution_scope: str = REGISTERED_FIXTURE_EXECUTION_SCOPE

    def to_dict(self) -> dict[str, Any]:
        return {
            "binding_kind": self.binding_kind,
            "run_id": self.run_id,
            "audit_case_id": self.audit_case_id,
            "fixture_id": self.fixture_id,
            "fixture_registry_digest": self.fixture_registry_digest,
            "fixture_source_digest": self.fixture_source_digest,
            "fixture_case_type": self.fixture_case_type,
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "source_revision": self.source_revision,
            "source_target_digest": self.source_target_digest,
            "created_by": self.created_by,
            "execution_scope": self.execution_scope,
        }

    @property
    def digest(self) -> str:
        return canonical_digest(self.to_dict())


def prepare_registered_fixture(
    fixture_id: str,
) -> PreparedFixtureValidation:
    """Scan the exact transparent fixture source and build one bound-plan input."""

    spec = get_fixture_spec(fixture_id)
    if spec is None:
        raise FixtureBindingError("fixture is not registered")

    registry_digest = fixture_registry_digest()
    source_digest = fixture_source_digest(spec)
    documents = fixture_source_documents(spec)
    target_digest = registered_source_target_digest(documents)
    analysis = _scan_registered_source(documents)
    static_scan = _static_scan_projection(
        analysis,
        source_target_digest=target_digest,
        fixture_case_type=spec.case_type,
    )
    case = _registered_fixture_case(
        spec,
        registry_digest=registry_digest,
        source_digest=source_digest,
        source_target_digest=target_digest,
        static_scan=static_scan,
    )
    plan = build_validation_plan(case)
    source_revision = f"fixture-{source_digest[:24]}"
    limitations = (
        "Evidence is scoped to one transparent first-party registered fixture.",
        "The static scan and local worker do not execute or confirm an arbitrary project.",
        "A human must separately confirm any real target before reporting.",
    )
    snapshot = {
        "schema_version": _STATIC_SCAN_SCHEMA_VERSION,
        "target": f"registered-fixture:{spec.fixture_id}",
        "files": [
            {"logical_name": name}
            for name in sorted(documents)
        ],
        "findings": [],
        "audit_cases": [copy.deepcopy(case)],
        "diagnostics": [],
        "totals": {
            "registered_source_files": len(documents),
            "static_findings": static_scan["finding_count"],
            "static_audit_cases": static_scan["audit_case_count"],
            "matching_static_audit_cases": static_scan[
                "matching_case_count"
            ],
        },
        "mcp_origin": "registered_fixture_preparation",
        "registered_fixture_id": spec.fixture_id,
        "fixture_registry_digest": registry_digest,
        "fixture_source_digest": source_digest,
        "source_target_digest": target_digest,
        "source_revision": source_revision,
        "static_scan": copy.deepcopy(static_scan),
    }
    return PreparedFixtureValidation(
        fixture_id=spec.fixture_id,
        fixture_case_type=spec.case_type,
        fixture_registry_digest=registry_digest,
        fixture_source_digest=source_digest,
        source_target_digest=target_digest,
        source_revision=source_revision,
        case=case,
        plan=plan,
        analysis_snapshot=snapshot,
        static_scan=static_scan,
        limitations=limitations,
    )


def build_registered_fixture_binding(
    prepared: PreparedFixtureValidation,
    *,
    run_id: str,
) -> RegisteredFixtureBinding:
    """Create the exact binding after the content-derived run ID exists."""

    return RegisteredFixtureBinding(
        run_id=run_id,
        audit_case_id=str(prepared.case["case_id"]),
        fixture_id=prepared.fixture_id,
        fixture_registry_digest=prepared.fixture_registry_digest,
        fixture_source_digest=prepared.fixture_source_digest,
        fixture_case_type=prepared.fixture_case_type,
        validation_plan_id=prepared.plan.plan_id,
        validation_plan_digest=canonical_digest(
            prepared.plan.to_dict()
        ),
        source_revision=prepared.source_revision,
        source_target_digest=prepared.source_target_digest,
    )


def validate_registered_fixture_binding(
    payload: Mapping[str, Any],
    *,
    run_id: str,
    plan: ValidationPlan,
    case: Mapping[str, Any],
    fixture_id: str,
) -> RegisteredFixtureBinding:
    """Recompute and verify every executable binding component."""

    if not isinstance(payload, Mapping):
        raise FixtureBindingError("validation plan is not fixture-bound")
    expected_fields = set(RegisteredFixtureBinding(
        run_id="",
        audit_case_id="",
        fixture_id="",
        fixture_registry_digest="",
        fixture_source_digest="",
        fixture_case_type="",
        validation_plan_id="",
        validation_plan_digest="",
        source_revision="",
        source_target_digest="",
    ).to_dict())
    if set(payload) != expected_fields or any(
        not isinstance(payload.get(field_name), str)
        for field_name in expected_fields
    ):
        raise FixtureBindingError("registered fixture binding fields are invalid")

    spec = get_fixture_spec(fixture_id)
    if spec is None:
        raise FixtureBindingError("fixture is not registered")
    documents = fixture_source_documents(spec)
    current_source_digest = fixture_source_digest(spec)
    current_target_digest = registered_source_target_digest(documents)
    current_registry_digest = fixture_registry_digest()
    expected = RegisteredFixtureBinding(
        run_id=run_id,
        audit_case_id=str(case.get("case_id") or ""),
        fixture_id=spec.fixture_id,
        fixture_registry_digest=current_registry_digest,
        fixture_source_digest=current_source_digest,
        fixture_case_type=spec.case_type,
        validation_plan_id=plan.plan_id,
        validation_plan_digest=canonical_digest(plan.to_dict()),
        source_revision=f"fixture-{current_source_digest[:24]}",
        source_target_digest=current_target_digest,
    )
    if dict(payload) != expected.to_dict():
        raise FixtureBindingError(
            "registered fixture binding does not match the run, plan, or source"
        )
    if plan.subject_id != expected.audit_case_id:
        raise FixtureBindingError("validation plan subject does not match its bound case")
    if plan.case_type != expected.fixture_case_type:
        raise FixtureBindingError("fixture does not support the validation plan type")
    return expected


def registered_source_target_digest(
    documents: Mapping[str, str],
) -> str:
    """Digest exact logical source bytes without retaining source in MCP state."""

    rows = []
    for logical_name in sorted(documents):
        source = documents[logical_name]
        rows.append(
            {
                "logical_name": logical_name,
                "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            }
        )
    return canonical_digest(
        {
            "schema_version": _SOURCE_TARGET_SCHEMA_VERSION,
            "documents": rows,
        }
    )


def project_validation_result(
    result: Mapping[str, Any],
    *,
    run_id: str,
    plan: ValidationPlan,
    binding: RegisteredFixtureBinding,
) -> dict[str, Any]:
    """Project worker evidence into the narrow, non-reportable MCP contract."""

    metadata = result.get("metadata")
    if not isinstance(metadata, Mapping):
        raise FixtureBindingError("validation result metadata is unavailable")
    execution = metadata.get("execution")
    worker = metadata.get("isolated_worker")
    if not isinstance(execution, Mapping) or not isinstance(worker, Mapping):
        raise FixtureBindingError("isolated worker evidence is unavailable")
    result_expected = {
        "subject_id": plan.subject_id,
        "subject_kind": "audit_case",
    }
    if any(
        result.get(field_name) != expected
        for field_name, expected in result_expected.items()
    ) or result.get("human_validated") is not False:
        raise FixtureBindingError(
            "validation result does not match the trusted plan subject"
        )
    execution_expected = {
        "validation_plan_id": binding.validation_plan_id,
        "validation_plan_digest": binding.validation_plan_digest,
        "subject_id": binding.audit_case_id,
        "source_revision": binding.source_revision,
        "fixture_id": binding.fixture_id,
    }
    if any(
        execution.get(field_name) != expected
        for field_name, expected in execution_expected.items()
    ):
        raise FixtureBindingError(
            "validation summary does not match the trusted fixture binding"
        )
    attestation = worker.get("attestation")
    if not isinstance(attestation, Mapping):
        raise FixtureBindingError("isolated worker attestation is unavailable")
    attestation_expected = {
        "fixture_id": binding.fixture_id,
        "fixture_registry_digest": binding.fixture_registry_digest,
        "fixture_source_digest": binding.fixture_source_digest,
        "validation_plan_id": binding.validation_plan_id,
        "validation_plan_digest": binding.validation_plan_digest,
        "source_revision": binding.source_revision,
    }
    if any(
        attestation.get(field_name) != expected
        for field_name, expected in attestation_expected.items()
    ):
        raise FixtureBindingError(
            "worker attestation does not match the trusted fixture binding"
        )

    raw_observations = execution.get("observations")
    observations = []
    if isinstance(raw_observations, list):
        for raw in raw_observations[:32]:
            if not isinstance(raw, Mapping):
                continue
            observations.append(
                {
                    "observation_id": str(raw.get("observation_id") or ""),
                    "scenario": str(raw.get("scenario") or ""),
                    "baseline": raw.get("baseline"),
                    "oracle": str(raw.get("oracle") or ""),
                    "oracle_evaluated": raw.get("oracle_evaluated"),
                    "oracle_passed": raw.get("oracle_passed"),
                    "evidence": _bounded_strings(raw.get("evidence"), limit=16),
                    "limitations": _bounded_strings(
                        raw.get("limitations"),
                        limit=16,
                    ),
                }
            )

    limitations = _bounded_strings(execution.get("limitations"), limit=32)
    limitations.extend(
        item
        for item in _bounded_strings(attestation.get("limitations"), limit=16)
        if item not in limitations
    )
    outcome = str(result.get("outcome") or "inconclusive")
    locally_reproduced = bool(
        result.get("tested")
        and execution.get("executed")
        and execution.get("baseline_passed") is True
    )
    maturity = (
        "locally_reproduced_on_registered_fixture"
        if locally_reproduced
        else "statically_supported"
    )
    if maturity not in _ALLOWED_MATURITY:
        raise FixtureBindingError("validation result maturity is invalid")

    unsigned = {
        "schema_version": MCP_VALIDATION_RESULT_SCHEMA_VERSION,
        "run_id": run_id,
        "plan_id": plan.plan_id,
        "case_id": plan.subject_id,
        "fixture_id": binding.fixture_id,
        "binding_digest": binding.digest,
        "validation_plan_digest": binding.validation_plan_digest,
        "fixture_registry_digest": binding.fixture_registry_digest,
        "fixture_source_digest": binding.fixture_source_digest,
        "source_target_digest": binding.source_target_digest,
        "source_revision": binding.source_revision,
        "semantic_digest": str(worker.get("semantic_digest") or ""),
        "outcome": outcome,
        "baseline": execution.get("baseline_passed"),
        "observations": observations,
        "limitations": limitations,
        "execution_boundaries": {
            "isolated_process_with_python_level_controls": True,
            "registered_fixture_executed": bool(execution.get("executed")),
            "arbitrary_target_executed": False,
            "target_files_written": False,
            "network_allowed": False,
            "subprocess_allowed": False,
            "shell_allowed": False,
            "custom_import_allowed": False,
            "environment_policy_installed": attestation.get(
                "environment_policy_installed"
            ),
            "filesystem_policy_installed": attestation.get(
                "filesystem_policy_installed"
            ),
            "network_policy_installed": attestation.get(
                "network_policy_installed"
            ),
            "process_policy_installed": attestation.get(
                "process_policy_installed"
            ),
            "timeout_enforced": attestation.get("timeout_enforced"),
            "cleanup_completed": attestation.get("cleanup_completed"),
        },
        "evidence_scope": REGISTERED_FIXTURE_EXECUTION_SCOPE,
        "maturity": maturity,
        "target_vulnerability_confirmed": False,
        "human_confirmation_required": True,
        "human_confirmed": False,
        "report_ready": False,
        "confirmed_vulnerability": False,
    }
    return {
        "result_id": "mvr_" + canonical_digest(unsigned)[:24],
        **unsigned,
    }


def _scan_registered_source(
    documents: Mapping[str, str],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="belief-mcp-registered-fixture-"
    ) as raw_root:
        root = Path(raw_root)
        for logical_name, source in sorted(documents.items()):
            relative = PurePosixPath(logical_name)
            if (
                relative.is_absolute()
                or ".." in relative.parts
                or relative.suffix != ".py"
            ):
                raise FixtureBindingError(
                    "registered fixture source manifest is invalid"
                )
            destination = root.joinpath(*relative.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                source,
                encoding="utf-8",
                newline="\n",
            )
        result = analyze_static_target(
            root,
            StaticAnalysisOptions(
                max_files=max(1, len(documents)),
                selected_categories=frozenset(STATIC_ANALYSIS_CATEGORIES),
                audit_mode=True,
                include_routes=True,
                reportability=True,
                dedup_audit_cases=True,
            ),
        )
        return result.to_dict()


def _static_scan_projection(
    analysis: Mapping[str, Any],
    *,
    source_target_digest: str,
    fixture_case_type: str,
) -> dict[str, Any]:
    files = analysis.get("files")
    findings = analysis.get("findings")
    cases = analysis.get("audit_cases")
    rows = cases if isinstance(cases, list) else []
    matching = sorted(
        str(item.get("case_id") or "")
        for item in rows
        if isinstance(item, Mapping)
        and item.get("case_type") == fixture_case_type
        and item.get("case_id")
    )
    payload = {
        "schema_version": _STATIC_SCAN_SCHEMA_VERSION,
        "source_target_digest": source_target_digest,
        "files_scanned": len(files) if isinstance(files, list) else 0,
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "audit_case_count": len(rows),
        "matching_case_count": len(matching),
        "matching_case_ids": matching,
    }
    payload["static_scan_digest"] = canonical_digest(payload)
    return payload


def _registered_fixture_case(
    spec: FixtureSpec,
    *,
    registry_digest: str,
    source_digest: str,
    source_target_digest: str,
    static_scan: Mapping[str, Any],
) -> dict[str, Any]:
    if spec.case_type == "path_traversal_possible":
        source = "registered_fixture.requested_path"
        sink = "registered_fixture.path_boundary"
        cwe = "CWE-22"
        missing = ["runtime path boundary behavior"]
    elif spec.case_type == "idor_bola_possible":
        source = "registered_fixture.principal_and_resource_id"
        sink = "registered_fixture.authorization_boundary"
        cwe = "CWE-639"
        missing = ["runtime ownership and tenant enforcement"]
    else:
        raise FixtureBindingError("fixture case type is not supported")

    seed = {
        "fixture_id": spec.fixture_id,
        "fixture_registry_digest": registry_digest,
        "fixture_source_digest": source_digest,
        "source_target_digest": source_target_digest,
        "case_type": spec.case_type,
        "static_scan_digest": static_scan["static_scan_digest"],
    }
    case_id = "case_" + canonical_digest(seed)[:16]
    adapter_file = f"web/{spec.framework}_adapter.py"
    return {
        "case_id": case_id,
        "case_type": spec.case_type,
        "status": "needs_review",
        "review_priority": "high",
        "confidence": 0.5,
        "severity": "medium",
        "file": adapter_file,
        "line": None,
        "rule_id": "registered_transparent_fixture",
        "cwe": cwe,
        "source": source,
        "sink": sink,
        "dataflow_path": [source, sink],
        "sanitizers": [],
        "guarantees": [],
        "missing_guarantees": missing,
        "z3_status": "not_applicable",
        "unsat_core": [],
        "human_next_steps": [
            "Execute only the exactly bound transparent fixture locally.",
            "Do not attribute fixture behavior to an arbitrary scanned target.",
            "Require separate human confirmation for any real target.",
        ],
        "related_finding_fingerprint": canonical_digest(seed)[:16],
        "reason": (
            "Generated from an exact static scan of the registered transparent "
            "fixture source; runtime behavior remains unconfirmed."
        ),
        "route_context": {
            "framework": spec.framework,
            "scope": REGISTERED_FIXTURE_EXECUTION_SCOPE,
        },
        "structured_dataflow": {
            "source": {"symbol": source},
            "sink": {"symbol": sink},
            "ordered_nodes": [
                {"symbol": source},
                {"symbol": sink},
            ],
            "ordered_edges": [
                {"source": source, "sink": sink},
            ],
        },
        "metadata": {
            "registered_fixture_preparation": {
                **copy.deepcopy(dict(seed)),
                "static_scan": copy.deepcopy(dict(static_scan)),
            }
        },
    }


def _bounded_strings(value: object, *, limit: int) -> list[str]:
    if not isinstance(value, (list, tuple)):
        return []
    result: list[str] = []
    for item in value:
        text = str(item).strip()
        if not text or text in result:
            continue
        result.append(text[:512])
        if len(result) >= limit:
            break
    return result


__all__ = [
    "FixtureBindingError",
    "MCP_FIXTURE_PREPARATION_SCHEMA_VERSION",
    "MCP_MAX_CONCURRENT_VALIDATIONS",
    "MCP_MAX_IN_FLIGHT_REQUESTS",
    "MCP_MAX_RESULTS_PER_RUN",
    "MCP_MAX_STORED_RUNS",
    "MCP_MAX_TOTAL_RESULTS",
    "MCP_MAX_VALIDATION_TIMEOUT_MS",
    "MCP_MIN_VALIDATION_TIMEOUT_MS",
    "MCP_VALIDATION_RESULT_SCHEMA_VERSION",
    "PreparedFixtureValidation",
    "REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION",
    "REGISTERED_FIXTURE_EXECUTION_SCOPE",
    "RegisteredFixtureBinding",
    "build_registered_fixture_binding",
    "prepare_registered_fixture",
    "project_validation_result",
    "registered_source_target_digest",
    "validate_registered_fixture_binding",
]
