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
from belief.validation.evidence_policy import (
    evaluate_evidence,
    infer_legacy_oracle_role,
)
from belief.validation.plan_models import (
    ValidationPlan,
    canonical_digest,
    clean_text,
)
from belief.validation.plans import build_validation_plan
from belief.validation.worker.registry import (
    FixtureSpec,
    execution_bundle_identity,
    get_fixture_spec,
    prepare_execution_bundle,
)


REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION = (
    "belief.registered_fixture_binding.v3"
)
MCP_FIXTURE_PREPARATION_SCHEMA_VERSION = (
    "belief.mcp_fixture_preparation.v3"
)
MCP_VALIDATION_RESULT_SCHEMA_VERSION = "belief.mcp_validation_result.v4"
VALIDATION_CONTRACT_SEED_SCHEMA_VERSION = (
    "belief.validation_contract_seed.v1"
)
REGISTERED_FIXTURE_EXECUTION_SCOPE = (
    "registered_transparent_fixture_only"
)
REGISTERED_FIXTURE_BINDING_CREATOR = (
    "belief_prepare_validation_fixture"
)
MCP_MAX_STORED_RUNS = 32
MCP_MAX_RESULTS_PER_RUN = 32
MCP_MAX_TOTAL_RESULTS = 128
MCP_MAX_CASES_PER_RUN = 512
MCP_MAX_SERIALIZED_BYTES_PER_CASE = 64 * 1024
MCP_MAX_BYTES_PER_RUN = 4 * 1024 * 1024
MCP_MAX_TOTAL_STORE_BYTES = 16 * 1024 * 1024
MCP_MAX_TOTAL_MEMORY_BYTES = 64 * 1024 * 1024
MCP_MAX_RESOURCE_PAGE_SIZE = 32
MCP_MAX_RESPONSE_BYTES = 512 * 1024
MCP_MAX_CONCURRENT_VALIDATIONS = 1
MCP_MAX_IN_FLIGHT_REQUESTS = 4
MCP_MIN_VALIDATION_TIMEOUT_MS = 100
MCP_MAX_VALIDATION_TIMEOUT_MS = 10_000

_SOURCE_TARGET_SCHEMA_VERSION = "belief.registered_fixture_source_target.v1"
_STATIC_SCAN_SCHEMA_VERSION = "belief.registered_fixture_static_scan.v2"
_ALLOWED_MATURITY = {
    "contract_prepared",
    "candidate",
    "statically_supported",
    "locally_evaluated",
    "human_confirmed",
    "report_ready",
}


class FixtureBindingError(ValueError):
    """A trusted fixture preparation or binding invariant failed."""


@dataclass(frozen=True)
class ValidationContractSeed:
    """Explicit non-finding contract used to prepare one fixture plan."""

    seed_id: str
    fixture_id: str
    fixture_registry_digest: str
    fixture_source_digest: str
    fixture_descriptor_digest: str
    fixture_execution_bundle_digest: str
    fixture_code_object_digest: str
    source_target_digest: str
    source_revision: str
    case_type: str
    framework: str
    file: str
    cwe: str
    source: str
    sink: str
    missing_guarantees: tuple[str, ...]
    static_case_provenance: tuple[dict[str, Any], ...] = ()
    origin: str = "explicit_fixture_contract"
    static_support: bool = False
    schema_version: str = VALIDATION_CONTRACT_SEED_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_CONTRACT_SEED_SCHEMA_VERSION:
            raise FixtureBindingError(
                "unsupported validation contract seed schema"
            )
        if self.origin != "explicit_fixture_contract":
            raise FixtureBindingError(
                "validation contract seed origin is invalid"
            )
        if self.static_support is not False:
            raise FixtureBindingError(
                "explicit fixture contract cannot claim static support"
            )
        if not self.seed_id.startswith("vcs_"):
            raise FixtureBindingError(
                "validation contract seed ID is invalid"
            )
        if self.case_type not in {
            "path_traversal_possible",
            "idor_bola_possible",
        }:
            raise FixtureBindingError(
                "validation contract seed case type is unsupported"
            )
        for field_name in (
            "fixture_id",
            "source_revision",
            "framework",
            "file",
            "cwe",
            "source",
            "sink",
        ):
            if not clean_text(getattr(self, field_name)):
                raise FixtureBindingError(
                    f"validation contract seed {field_name} is required"
                )
        for field_name in (
            "fixture_registry_digest",
            "fixture_source_digest",
            "fixture_descriptor_digest",
            "fixture_execution_bundle_digest",
            "fixture_code_object_digest",
            "source_target_digest",
        ):
            value = str(getattr(self, field_name))
            if len(value) != 64 or any(
                character not in "0123456789abcdef"
                for character in value
            ):
                raise FixtureBindingError(
                    f"validation contract seed {field_name} is invalid"
                )
        provenance = tuple(
            copy.deepcopy(dict(item))
            for item in self.static_case_provenance
            if isinstance(item, Mapping)
        )
        if len(provenance) != len(self.static_case_provenance):
            raise FixtureBindingError(
                "validation contract seed provenance is invalid"
            )
        for item in provenance:
            if (
                not clean_text(item.get("case_id"))
                or item.get("pipeline")
                != "belief.static_analysis_pipeline"
                or item.get("source_target_digest")
                != self.source_target_digest
            ):
                raise FixtureBindingError(
                    "validation contract seed provenance is incomplete"
                )
        object.__setattr__(self, "static_case_provenance", provenance)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "seed_id": self.seed_id,
            "subject_kind": "validation_contract_seed",
            "origin": self.origin,
            "static_support": self.static_support,
            "static_case_provenance": [
                copy.deepcopy(item)
                for item in self.static_case_provenance
            ],
            "fixture_id": self.fixture_id,
            "fixture_registry_digest": self.fixture_registry_digest,
            "fixture_source_digest": self.fixture_source_digest,
            "fixture_descriptor_digest": self.fixture_descriptor_digest,
            "fixture_execution_bundle_digest": (
                self.fixture_execution_bundle_digest
            ),
            "fixture_code_object_digest": self.fixture_code_object_digest,
            "source_target_digest": self.source_target_digest,
            "source_revision": self.source_revision,
            "case_type": self.case_type,
            "status": "needs_review",
            "review_priority": "high",
            "confidence": 0.0,
            "severity": "informational",
            "file": self.file,
            "line": None,
            "rule_id": "explicit_registered_fixture_contract",
            "cwe": self.cwe,
            "source": self.source,
            "sink": self.sink,
            "dataflow_path": [self.source, self.sink],
            "sanitizers": [],
            "guarantees": [],
            "missing_guarantees": list(self.missing_guarantees),
            "z3_status": "not_applicable",
            "unsat_core": [],
            "human_next_steps": [
                "Execute only the exactly bound transparent fixture locally.",
                "Do not attribute fixture behavior to an arbitrary target.",
                "Require separate human confirmation before reporting.",
            ],
            "related_finding_fingerprint": canonical_digest(
                {
                    "seed_id": self.seed_id,
                    "source_target_digest": self.source_target_digest,
                }
            )[:16],
            "reason": (
                "This is an explicit fixture validation contract, not a "
                "finding or a statically supported AuditCase."
            ),
            "route_context": {
                "framework": self.framework,
                "scope": REGISTERED_FIXTURE_EXECUTION_SCOPE,
            },
            "structured_dataflow": {
                "source": {"symbol": self.source},
                "sink": {"symbol": self.sink},
                "ordered_nodes": [
                    {"symbol": self.source},
                    {"symbol": self.sink},
                ],
                "ordered_edges": [
                    {"source": self.source, "sink": self.sink},
                ],
            },
        }


@dataclass(frozen=True)
class PreparedFixtureValidation:
    """Canonical artifacts produced from one immutable registry entry."""

    fixture_id: str
    fixture_case_type: str
    fixture_registry_digest: str
    fixture_source_digest: str
    fixture_descriptor_digest: str
    fixture_execution_bundle_digest: str
    fixture_code_object_digest: str
    source_target_digest: str
    source_revision: str
    contract_seed: ValidationContractSeed
    plan: ValidationPlan
    analysis_snapshot: dict[str, Any]
    static_scan: dict[str, Any]
    limitations: tuple[str, ...]


@dataclass(frozen=True)
class RegisteredFixtureBinding:
    """Exact executable binding between a run, plan, and first-party fixture."""

    run_id: str
    validation_contract_seed_id: str
    fixture_id: str
    fixture_registry_digest: str
    fixture_source_digest: str
    fixture_descriptor_digest: str
    fixture_execution_bundle_digest: str
    fixture_code_object_digest: str
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
            "validation_contract_seed_id": (
                self.validation_contract_seed_id
            ),
            "fixture_id": self.fixture_id,
            "fixture_registry_digest": self.fixture_registry_digest,
            "fixture_source_digest": self.fixture_source_digest,
            "fixture_descriptor_digest": self.fixture_descriptor_digest,
            "fixture_execution_bundle_digest": (
                self.fixture_execution_bundle_digest
            ),
            "fixture_code_object_digest": self.fixture_code_object_digest,
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

    bundle = prepare_execution_bundle(spec)
    identity = execution_bundle_identity(bundle)
    registry_digest = identity["fixture_registry_digest"]
    source_digest = identity["fixture_source_digest"]
    descriptor_digest = identity["fixture_descriptor_digest"]
    execution_bundle_digest = identity[
        "fixture_execution_bundle_digest"
    ]
    code_object_digest = identity["fixture_code_object_digest"]
    documents = bundle.application_source_documents()
    target_digest = registered_source_target_digest(documents)
    analysis = _scan_registered_source(
        documents,
        target_identity=f"registered-fixture:{spec.fixture_id}",
    )
    static_scan = _static_scan_projection(
        analysis,
        source_target_digest=target_digest,
        fixture_case_type=spec.case_type,
    )
    source_revision = f"fixture-{source_digest[:24]}"
    contract_seed = _registered_fixture_contract_seed(
        spec,
        registry_digest=registry_digest,
        source_digest=source_digest,
        descriptor_digest=descriptor_digest,
        execution_bundle_digest=execution_bundle_digest,
        code_object_digest=code_object_digest,
        source_target_digest=target_digest,
        source_revision=source_revision,
        static_scan=static_scan,
    )
    plan = build_validation_plan(contract_seed)
    limitations = (
        "Evidence is scoped to one transparent first-party registered fixture.",
        "The static scan and local worker do not execute or confirm an arbitrary project.",
        "A human must separately confirm any real target before reporting.",
    )
    snapshot = copy.deepcopy(analysis)
    snapshot.update({
        "target": f"registered-fixture:{spec.fixture_id}",
        "mcp_origin": "registered_fixture_preparation",
        "registered_fixture_id": spec.fixture_id,
        "fixture_registry_digest": registry_digest,
        "fixture_source_digest": source_digest,
        "fixture_descriptor_digest": descriptor_digest,
        "fixture_execution_bundle_digest": execution_bundle_digest,
        "fixture_code_object_digest": code_object_digest,
        "source_target_digest": target_digest,
        "source_revision": source_revision,
        "static_scan": copy.deepcopy(static_scan),
        "validation_contract_seeds": [contract_seed.to_dict()],
    })
    return PreparedFixtureValidation(
        fixture_id=spec.fixture_id,
        fixture_case_type=spec.case_type,
        fixture_registry_digest=registry_digest,
        fixture_source_digest=source_digest,
        fixture_descriptor_digest=descriptor_digest,
        fixture_execution_bundle_digest=execution_bundle_digest,
        fixture_code_object_digest=code_object_digest,
        source_target_digest=target_digest,
        source_revision=source_revision,
        contract_seed=contract_seed,
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
        validation_contract_seed_id=prepared.contract_seed.seed_id,
        fixture_id=prepared.fixture_id,
        fixture_registry_digest=prepared.fixture_registry_digest,
        fixture_source_digest=prepared.fixture_source_digest,
        fixture_descriptor_digest=prepared.fixture_descriptor_digest,
        fixture_execution_bundle_digest=(
            prepared.fixture_execution_bundle_digest
        ),
        fixture_code_object_digest=prepared.fixture_code_object_digest,
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
    contract_seed: Mapping[str, Any],
    fixture_id: str,
) -> RegisteredFixtureBinding:
    """Recompute and verify every executable binding component."""

    if not isinstance(payload, Mapping):
        raise FixtureBindingError("validation plan is not fixture-bound")
    expected_fields = set(RegisteredFixtureBinding(
        run_id="",
        validation_contract_seed_id="",
        fixture_id="",
        fixture_registry_digest="",
        fixture_source_digest="",
        fixture_descriptor_digest="",
        fixture_execution_bundle_digest="",
        fixture_code_object_digest="",
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
    bundle = prepare_execution_bundle(spec)
    current_identity = execution_bundle_identity(bundle)
    documents = bundle.application_source_documents()
    current_source_digest = current_identity["fixture_source_digest"]
    current_target_digest = registered_source_target_digest(documents)
    current_registry_digest = current_identity["fixture_registry_digest"]
    expected = RegisteredFixtureBinding(
        run_id=run_id,
        validation_contract_seed_id=str(
            contract_seed.get("seed_id") or ""
        ),
        fixture_id=spec.fixture_id,
        fixture_registry_digest=current_registry_digest,
        fixture_source_digest=current_source_digest,
        fixture_descriptor_digest=current_identity[
            "fixture_descriptor_digest"
        ],
        fixture_execution_bundle_digest=current_identity[
            "fixture_execution_bundle_digest"
        ],
        fixture_code_object_digest=current_identity[
            "fixture_code_object_digest"
        ],
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
    if (
        plan.subject_id != expected.validation_contract_seed_id
        or plan.subject_kind != "validation_contract_seed"
    ):
        raise FixtureBindingError(
            "validation plan subject does not match its bound contract seed"
        )
    if plan.case_type != expected.fixture_case_type:
        raise FixtureBindingError("fixture does not support the validation plan type")
    return expected


def registered_source_target_digest(
    documents: Mapping[str, bytes],
) -> str:
    """Digest exact logical source bytes without retaining source in MCP state."""

    rows = []
    for logical_name in sorted(documents):
        source = documents[logical_name]
        if not isinstance(source, bytes):
            raise FixtureBindingError(
                "registered fixture source must be exact bytes"
            )
        rows.append(
            {
                "logical_name": logical_name,
                "size": len(source),
                "sha256": hashlib.sha256(source).hexdigest(),
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
        "subject_kind": plan.subject_kind,
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
        "subject_id": binding.validation_contract_seed_id,
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
        "fixture_descriptor_digest": binding.fixture_descriptor_digest,
        "fixture_execution_bundle_digest": (
            binding.fixture_execution_bundle_digest
        ),
        "fixture_code_object_digest": binding.fixture_code_object_digest,
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
    child_policy = attestation.get("child_policy_attestation")
    parent_lifecycle = attestation.get(
        "parent_lifecycle_attestation"
    )
    if not isinstance(child_policy, Mapping) or not isinstance(
        parent_lifecycle,
        Mapping,
    ):
        raise FixtureBindingError(
            "worker policy and lifecycle attestations are unavailable"
        )

    raw_observations = execution.get("observations")
    observations = []
    policy_observations = []
    if isinstance(raw_observations, list):
        for raw in raw_observations[:32]:
            if not isinstance(raw, Mapping):
                continue
            policy_observation = dict(raw)
            if "oracle_role" not in policy_observation:
                role, required = infer_legacy_oracle_role(
                    baseline=policy_observation["baseline"],
                    oracle=policy_observation["oracle"],
                    scenario=policy_observation["scenario"],
                )
                policy_observation["oracle_role"] = role
                policy_observation["required_for_conclusion"] = required
            policy_observations.append(policy_observation)
            observations.append(
                {
                    "observation_id": str(raw.get("observation_id") or ""),
                    "scenario": str(raw.get("scenario") or ""),
                    "baseline": raw.get("baseline"),
                    "oracle": str(raw.get("oracle") or ""),
                    "oracle_role": str(
                        policy_observation.get("oracle_role") or ""
                    ),
                    "required_for_conclusion": policy_observation.get(
                        "required_for_conclusion"
                    ),
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
    worker_status = str(worker.get("worker_status") or "unavailable")
    worker_error_codes = sorted({
        item.removeprefix("worker_error:")
        for item in limitations
        if item.startswith("worker_error:")
    })
    outcome = str(result.get("outcome") or "inconclusive")
    decision = evaluate_evidence(
        policy_observations,
        completed=execution.get("executed") is True,
        safe_outcome=(
            "false_positive"
            if outcome == "false_positive"
            else "enforced"
        ),
    )
    if (
        decision.outcome != outcome
        or decision.baseline_passed != execution.get("baseline_passed")
    ):
        raise FixtureBindingError(
            "validation result contradicts the shared evidence policy"
        )
    maturity = _validation_maturity(
        plan,
        execution=execution,
        decision=decision,
    )
    if maturity not in _ALLOWED_MATURITY:
        raise FixtureBindingError("validation result maturity is invalid")

    unsigned = {
        "schema_version": MCP_VALIDATION_RESULT_SCHEMA_VERSION,
        "run_id": run_id,
        "plan_id": plan.plan_id,
        "validation_contract_seed_id": plan.subject_id,
        "subject_kind": plan.subject_kind,
        "fixture_id": binding.fixture_id,
        "binding_digest": binding.digest,
        "validation_plan_digest": binding.validation_plan_digest,
        "fixture_registry_digest": binding.fixture_registry_digest,
        "fixture_source_digest": binding.fixture_source_digest,
        "fixture_descriptor_digest": binding.fixture_descriptor_digest,
        "fixture_execution_bundle_digest": (
            binding.fixture_execution_bundle_digest
        ),
        "fixture_code_object_digest": binding.fixture_code_object_digest,
        "source_target_digest": binding.source_target_digest,
        "source_revision": binding.source_revision,
        "evidence_digest": str(worker.get("evidence_digest") or ""),
        "attestation_digest": str(
            worker.get("attestation_digest") or ""
        ),
        "environment_digest": str(
            attestation.get("environment_digest") or ""
        ),
        "semantic_digest": str(worker.get("semantic_digest") or ""),
        "execution_status": (
            "completed" if worker_status == "completed" else "abstained"
        ),
        "worker_status": worker_status,
        "worker_error_codes": worker_error_codes,
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
            "environment_policy_installed": child_policy.get(
                "environment_policy_installed"
            ),
            "filesystem_policy_installed": child_policy.get(
                "filesystem_policy_installed"
            ),
            "network_policy_installed": child_policy.get(
                "network_policy_installed"
            ),
            "process_policy_installed": child_policy.get(
                "process_policy_installed"
            ),
            "timeout_enforced": parent_lifecycle.get("timeout_enforced"),
            "cleanup_completed": parent_lifecycle.get(
                "cleanup_completed"
            ),
        },
        "evidence_scope": REGISTERED_FIXTURE_EXECUTION_SCOPE,
        "maturity": maturity,
        "static_support": plan.metadata.get("static_support") is True,
        "static_case_provenance": copy.deepcopy(
            plan.metadata.get("static_case_provenance") or []
        ),
        "target_vulnerability_confirmed": False,
        "human_confirmation_required": True,
        "human_confirmed": False,
        "report_ready": False,
        "confirmed_vulnerability": False,
    }
    stable_identity = {
        key: value
        for key, value in unsigned.items()
        if key != "attestation_digest"
    }
    return {
        "result_id": "mvr_" + canonical_digest(stable_identity)[:24],
        **unsigned,
    }


def _validation_maturity(
    plan: ValidationPlan,
    *,
    execution: Mapping[str, Any],
    decision: Any,
) -> str:
    observations = execution.get("observations")
    if (
        execution.get("executed") is True
        and isinstance(observations, list)
        and any(
            isinstance(item, Mapping)
            and item.get("oracle_evaluated") is True
            for item in observations
        )
    ):
        return "locally_evaluated"

    if plan.metadata.get("static_support") is True:
        provenance = plan.metadata.get("static_case_provenance")
        if (
            not isinstance(provenance, list)
            or not provenance
            or any(
                not isinstance(item, Mapping)
                or not clean_text(item.get("case_id"))
                or item.get("pipeline")
                != "belief.static_analysis_pipeline"
                or not clean_text(item.get("source_target_digest"))
                for item in provenance
            )
        ):
            raise FixtureBindingError(
                "static maturity requires real pipeline case provenance"
            )
        return "statically_supported"

    if decision.conclusive:
        raise FixtureBindingError(
            "conclusive evidence cannot remain below local evaluation"
        )
    return (
        "contract_prepared"
        if plan.subject_kind == "validation_contract_seed"
        else "candidate"
    )


def _scan_registered_source(
    documents: Mapping[str, bytes],
    *,
    target_identity: str,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(
        prefix="belief-mcp-registered-fixture-"
    ) as raw_root:
        root = Path(raw_root)
        for logical_name, source in sorted(documents.items()):
            if not isinstance(source, bytes):
                raise FixtureBindingError(
                    "registered fixture source must be exact bytes"
                )
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
            destination.write_bytes(source)
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
            target_identity=target_identity,
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
    matching_cases = sorted(
        (
            {
                "case_id": str(item.get("case_id") or ""),
                "case_type": str(item.get("case_type") or ""),
                "related_finding_fingerprint": str(
                    item.get("related_finding_fingerprint") or ""
                ),
                "file": str(item.get("file") or ""),
                "line": item.get("line"),
                "rule_id": str(item.get("rule_id") or ""),
                "pipeline": "belief.static_analysis_pipeline",
                "analysis_schema_version": str(
                    analysis.get("schema_version") or ""
                ),
                "source_target_digest": source_target_digest,
            }
            for item in rows
            if isinstance(item, Mapping)
            and item.get("case_type") == fixture_case_type
            and item.get("case_id")
        ),
        key=lambda item: item["case_id"],
    )
    payload = {
        "schema_version": _STATIC_SCAN_SCHEMA_VERSION,
        "source_target_digest": source_target_digest,
        "files_scanned": len(files) if isinstance(files, list) else 0,
        "finding_count": len(findings) if isinstance(findings, list) else 0,
        "audit_case_count": len(rows),
        "matching_case_count": len(matching_cases),
        "matching_case_ids": [
            item["case_id"] for item in matching_cases
        ],
        "matching_case_provenance": matching_cases,
    }
    payload["static_scan_digest"] = canonical_digest(payload)
    return payload


def _registered_fixture_contract_seed(
    spec: FixtureSpec,
    *,
    registry_digest: str,
    source_digest: str,
    descriptor_digest: str,
    execution_bundle_digest: str,
    code_object_digest: str,
    source_target_digest: str,
    source_revision: str,
    static_scan: Mapping[str, Any],
) -> ValidationContractSeed:
    if spec.case_type == "path_traversal_possible":
        source = "registered_fixture.requested_path"
        sink = "registered_fixture.path_boundary"
        cwe = "CWE-22"
        missing = ("runtime path boundary behavior",)
    elif spec.case_type == "idor_bola_possible":
        source = "registered_fixture.principal_and_resource_id"
        sink = "registered_fixture.authorization_boundary"
        cwe = "CWE-639"
        missing = ("runtime ownership and tenant enforcement",)
    else:
        raise FixtureBindingError("fixture case type is not supported")

    seed_material = {
        "fixture_id": spec.fixture_id,
        "fixture_registry_digest": registry_digest,
        "fixture_source_digest": source_digest,
        "fixture_descriptor_digest": descriptor_digest,
        "fixture_execution_bundle_digest": execution_bundle_digest,
        "fixture_code_object_digest": code_object_digest,
        "source_target_digest": source_target_digest,
        "source_revision": source_revision,
        "case_type": spec.case_type,
        "static_scan_digest": static_scan["static_scan_digest"],
    }
    return ValidationContractSeed(
        seed_id="vcs_" + canonical_digest(seed_material)[:20],
        fixture_id=spec.fixture_id,
        fixture_registry_digest=registry_digest,
        fixture_source_digest=source_digest,
        fixture_descriptor_digest=descriptor_digest,
        fixture_execution_bundle_digest=execution_bundle_digest,
        fixture_code_object_digest=code_object_digest,
        source_target_digest=source_target_digest,
        source_revision=source_revision,
        case_type=spec.case_type,
        framework=spec.framework,
        file=f"web/{spec.framework}_adapter.py",
        cwe=cwe,
        source=source,
        sink=sink,
        missing_guarantees=missing,
        static_case_provenance=tuple(
            copy.deepcopy(
                static_scan.get("matching_case_provenance") or ()
            )
        ),
    )


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
    "MCP_MAX_BYTES_PER_RUN",
    "MCP_MAX_CASES_PER_RUN",
    "MCP_MAX_CONCURRENT_VALIDATIONS",
    "MCP_MAX_IN_FLIGHT_REQUESTS",
    "MCP_MAX_RESOURCE_PAGE_SIZE",
    "MCP_MAX_RESPONSE_BYTES",
    "MCP_MAX_RESULTS_PER_RUN",
    "MCP_MAX_SERIALIZED_BYTES_PER_CASE",
    "MCP_MAX_STORED_RUNS",
    "MCP_MAX_TOTAL_STORE_BYTES",
    "MCP_MAX_TOTAL_RESULTS",
    "MCP_MAX_TOTAL_MEMORY_BYTES",
    "MCP_MAX_VALIDATION_TIMEOUT_MS",
    "MCP_MIN_VALIDATION_TIMEOUT_MS",
    "MCP_VALIDATION_RESULT_SCHEMA_VERSION",
    "PreparedFixtureValidation",
    "REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION",
    "REGISTERED_FIXTURE_EXECUTION_SCOPE",
    "RegisteredFixtureBinding",
    "VALIDATION_CONTRACT_SEED_SCHEMA_VERSION",
    "ValidationContractSeed",
    "build_registered_fixture_binding",
    "prepare_registered_fixture",
    "project_validation_result",
    "registered_source_target_digest",
    "validate_registered_fixture_binding",
]
