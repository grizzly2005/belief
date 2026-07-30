"""Public contracts for BELIEF's dependency-free MCP facade."""

from __future__ import annotations

from typing import Any

from belief import __version__
from belief.audit_case import AUDIT_SCHEMA_VERSION
from belief.validation.metrics import VALIDATION_METRICS_SCHEMA_VERSION
from belief.validation.models import (
    VALIDATION_OUTCOMES,
    VALIDATION_RESULT_SCHEMA_VERSION as CORE_VALIDATION_RESULT_SCHEMA_VERSION,
)
from belief.validation.plan_models import (
    VALIDATION_PLAN_SCHEMA_VERSION,
    VALIDATION_STRATEGIES,
)

from .authorized_project import (
    AUTHORIZED_PROJECT_BINDING_SCHEMA_VERSION,
    AUTHORIZED_PROJECT_EXECUTION_SCOPE,
    FLASKJWT_PILOT_ADAPTER_ID,
    FLASKJWT_PILOT_PROJECT_ID,
    FLASKJWT_PILOT_SOURCE_DIGEST,
    FLASKJWT_PILOT_SOURCE_FILE_COUNT,
    FLASKJWT_PILOT_SOURCE_REVISION,
    FLASKJWT_PILOT_SOURCE_TOTAL_BYTES,
)
from .validation import (
    MCP_MAX_CONCURRENT_VALIDATIONS,
    MCP_MAX_IN_FLIGHT_REQUESTS,
    MCP_MAX_RESULTS_PER_RUN,
    MCP_MAX_STORED_RUNS,
    MCP_MAX_TOTAL_RESULTS,
    MCP_MAX_VALIDATION_TIMEOUT_MS,
    MCP_MIN_VALIDATION_TIMEOUT_MS,
    MCP_VALIDATION_RESULT_SCHEMA_VERSION,
    REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION,
    REGISTERED_FIXTURE_EXECUTION_SCOPE,
)

MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    MCP_PROTOCOL_VERSION,
)
MCP_SERVER_NAME = "belief"
MCP_SERVER_VERSION = __version__
MCP_RUN_SCHEMA_VERSION = "belief.mcp_run.v1"
MCP_SCAN_RESPONSE_SCHEMA_VERSION = "belief.mcp_scan_response.v1"
MCP_COMPARISON_SCHEMA_VERSION = "belief.mcp_run_comparison.v1"
MCP_EXPLANATION_SCHEMA_VERSION = "belief.mcp_case_explanation.v1"

SUPPORTED_VALIDATION_VERTICALS = (
    "idor_bola_possible",
    "path_traversal_possible",
)

SERVER_INSTRUCTIONS = (
    "BELIEF is a local AppSec evidence engine. Treat every AuditCase as candidate "
    "evidence, never as a confirmed vulnerability. Arbitrary project scan plans "
    "are never executable. Local dynamic validation is limited to plans prepared "
    "from and cryptographically bound to transparent first-party registered "
    "fixtures. Fixture evidence never confirms the scanned target. This server "
    "also exposes one separately authorized, exact-source flask-jwt-extended "
    "static pilot that always abstains from target execution. This server has "
    "no network, shell, target-write, custom-import, Docker, or SusVibes holdout "
    "capability."
)

_READ_ONLY_ANNOTATIONS = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
_LOCAL_EXECUTION_ANNOTATIONS = {
    "readOnlyHint": False,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}
_NO_BACKGROUND_EXECUTION = {"taskSupport": "forbidden"}


def _string(*, min_length: int = 0, enum: list[str] | None = None) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string"}
    if min_length:
        schema["minLength"] = min_length
    if enum is not None:
        schema["enum"] = enum
    return schema


def _object(
    properties: dict[str, Any],
    *,
    required: tuple[str, ...] = (),
    additional: bool = False,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "properties": properties,
        "additionalProperties": additional,
    }
    if required:
        schema["required"] = list(required)
    return schema


AUDIT_CASE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "belief://schemas/audit-case",
    "title": "BELIEF AuditCase v1",
    **_object(
        {
            "case_id": _string(min_length=1),
            "case_type": _string(min_length=1),
            "status": _string(
                enum=[
                    "actionable",
                    "needs_review",
                    "protected",
                    "false_positive_likely",
                ]
            ),
            "review_priority": _string(
                enum=["critical", "high", "medium", "low", "info"]
            ),
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "severity": _string(min_length=1),
            "file": _string(),
            "line": {"type": ["integer", "null"], "minimum": 1},
            "rule_id": _string(),
            "cwe": _string(),
            "source": _string(),
            "sink": _string(),
            "dataflow_path": {"type": "array", "items": _string()},
            "sanitizers": {"type": "array", "items": _string()},
            "guarantees": {"type": "array", "items": _string()},
            "missing_guarantees": {"type": "array", "items": _string()},
            "z3_status": _string(),
            "unsat_core": {"type": "array", "items": _string()},
            "human_next_steps": {"type": "array", "items": _string()},
            "related_finding_fingerprint": _string(),
            "reason": _string(),
            "route_context": {"type": "object"},
            "structured_dataflow": {"type": "object"},
            "metadata": {"type": "object"},
        },
        required=(
            "case_id",
            "case_type",
            "status",
            "review_priority",
            "confidence",
            "severity",
            "file",
            "line",
            "rule_id",
            "cwe",
            "source",
            "sink",
            "dataflow_path",
            "sanitizers",
            "guarantees",
            "missing_guarantees",
            "z3_status",
            "unsat_core",
            "human_next_steps",
            "related_finding_fingerprint",
            "reason",
        ),
        additional=True,
    ),
}

VALIDATION_PLAN_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "belief://schemas/validation-plan",
    "title": "BELIEF ValidationPlan v1",
    **_object(
        {
            "schema_version": {"const": VALIDATION_PLAN_SCHEMA_VERSION},
            "plan_id": _string(min_length=1),
            "subject_id": _string(min_length=1),
            "subject_kind": {"const": "audit_case"},
            "case_type": _string(min_length=1),
            "case_status": _string(min_length=1),
            "strategy": _string(enum=sorted(VALIDATION_STRATEGIES)),
            "objective": _string(),
            "priority": _string(
                enum=["critical", "high", "medium", "low", "info"]
            ),
            "target": {"type": "object"},
            "evidence_gaps": {"type": "array", "items": _string()},
            "prerequisites": {"type": "array", "items": _string()},
            "stimuli": {"type": "array", "items": {"type": "object"}},
            "oracles": {"type": "array", "items": {"type": "object"}},
            "reachability_hints": {"type": "object"},
            "stop_conditions": {"type": "array", "items": _string()},
            "safety": {"type": "object"},
            "result_contract": {"type": "object"},
            "metadata": {"type": "object"},
            "registered_fixture_binding": {
                "$ref": "belief://schemas/registered-fixture-binding"
            },
        },
        required=(
            "schema_version",
            "plan_id",
            "subject_id",
            "subject_kind",
            "case_type",
            "case_status",
            "strategy",
            "objective",
            "priority",
            "target",
            "evidence_gaps",
            "prerequisites",
            "stimuli",
            "oracles",
            "reachability_hints",
            "stop_conditions",
            "safety",
            "result_contract",
            "metadata",
        ),
    ),
}

REGISTERED_FIXTURE_BINDING_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "belief://schemas/registered-fixture-binding",
    "title": "BELIEF registered fixture binding v1",
    **_object(
        {
            "binding_kind": {
                "const": REGISTERED_FIXTURE_BINDING_SCHEMA_VERSION
            },
            "run_id": _string(min_length=5),
            "audit_case_id": _string(min_length=1),
            "fixture_id": _string(min_length=1),
            "fixture_registry_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "fixture_source_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "fixture_case_type": _string(
                enum=list(SUPPORTED_VALIDATION_VERTICALS)
            ),
            "validation_plan_id": _string(min_length=1),
            "validation_plan_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_revision": _string(min_length=1),
            "source_target_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "created_by": {
                "const": "belief_prepare_validation_fixture"
            },
            "execution_scope": {
                "const": REGISTERED_FIXTURE_EXECUTION_SCOPE
            },
        },
        required=(
            "binding_kind",
            "run_id",
            "audit_case_id",
            "fixture_id",
            "fixture_registry_digest",
            "fixture_source_digest",
            "fixture_case_type",
            "validation_plan_id",
            "validation_plan_digest",
            "source_revision",
            "source_target_digest",
            "created_by",
            "execution_scope",
        ),
    ),
}

AUTHORIZED_PROJECT_BINDING_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "belief://schemas/authorized-project-binding",
    "title": "BELIEF authorized project static binding v1",
    **_object(
        {
            "binding_kind": {
                "const": AUTHORIZED_PROJECT_BINDING_SCHEMA_VERSION
            },
            "adapter_id": {"const": FLASKJWT_PILOT_ADAPTER_ID},
            "project_id": {"const": FLASKJWT_PILOT_PROJECT_ID},
            "run_id": _string(min_length=5),
            "audit_case_id": _string(min_length=1),
            "validation_plan_id": _string(min_length=1),
            "validation_plan_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_revision": {
                "const": FLASKJWT_PILOT_SOURCE_REVISION
            },
            "source_digest": {"const": FLASKJWT_PILOT_SOURCE_DIGEST},
            "source_file_count": {
                "type": "integer",
                "const": FLASKJWT_PILOT_SOURCE_FILE_COUNT,
            },
            "source_total_bytes": {
                "type": "integer",
                "const": FLASKJWT_PILOT_SOURCE_TOTAL_BYTES,
            },
            "authorization_id": {
                "type": "string",
                "pattern": "^auth_[0-9a-f]{64}$",
            },
            "authorization_grant_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "created_by": {
                "const": "belief_prepare_authorized_project_pilot"
            },
            "execution_scope": {
                "const": AUTHORIZED_PROJECT_EXECUTION_SCOPE
            },
            "dynamic_execution_authorized": {"const": False},
        },
        required=(
            "binding_kind",
            "adapter_id",
            "project_id",
            "run_id",
            "audit_case_id",
            "validation_plan_id",
            "validation_plan_digest",
            "source_revision",
            "source_digest",
            "source_file_count",
            "source_total_bytes",
            "authorization_id",
            "authorization_grant_digest",
            "created_by",
            "execution_scope",
            "dynamic_execution_authorized",
        ),
    ),
}

VALIDATION_RESULT_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "belief://schemas/validation-result",
    "title": "BELIEF MCP fixture validation result v1",
    **_object(
        {
            "schema_version": {"const": MCP_VALIDATION_RESULT_SCHEMA_VERSION},
            "result_id": _string(min_length=1),
            "run_id": _string(min_length=5),
            "plan_id": _string(min_length=1),
            "case_id": _string(min_length=1),
            "fixture_id": _string(min_length=1),
            "binding_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "validation_plan_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "fixture_registry_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "fixture_source_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_target_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "source_revision": _string(min_length=1),
            "semantic_digest": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$",
            },
            "outcome": _string(enum=sorted(VALIDATION_OUTCOMES)),
            "baseline": {"type": ["boolean", "null"]},
            "observations": {"type": "array", "items": {"type": "object"}},
            "limitations": {"type": "array", "items": _string()},
            "execution_boundaries": {"type": "object"},
            "evidence_scope": {
                "const": REGISTERED_FIXTURE_EXECUTION_SCOPE
            },
            "maturity": _string(
                enum=[
                    "candidate",
                    "statically_supported",
                    "locally_reproduced_on_registered_fixture",
                ]
            ),
            "target_vulnerability_confirmed": {"const": False},
            "human_confirmation_required": {"const": True},
            "human_confirmed": {"const": False},
            "report_ready": {"const": False},
            "confirmed_vulnerability": {"const": False},
        },
        required=(
            "schema_version",
            "result_id",
            "run_id",
            "plan_id",
            "case_id",
            "fixture_id",
            "binding_digest",
            "validation_plan_digest",
            "fixture_registry_digest",
            "fixture_source_digest",
            "source_target_digest",
            "source_revision",
            "semantic_digest",
            "outcome",
            "baseline",
            "observations",
            "limitations",
            "execution_boundaries",
            "evidence_scope",
            "maturity",
            "target_vulnerability_confirmed",
            "human_confirmation_required",
        ),
    ),
}

PUBLIC_SCHEMAS = {
    "belief://schemas/audit-case": AUDIT_CASE_SCHEMA,
    "belief://schemas/validation-plan": VALIDATION_PLAN_SCHEMA,
    "belief://schemas/validation-result": VALIDATION_RESULT_SCHEMA,
    "belief://schemas/registered-fixture-binding": (
        REGISTERED_FIXTURE_BINDING_SCHEMA
    ),
    "belief://schemas/authorized-project-binding": (
        AUTHORIZED_PROJECT_BINDING_SCHEMA
    ),
}

_RUN_ID_INPUT = _string(min_length=5)
_CASE_ID_INPUT = _string(min_length=1)
_GENERIC_OUTPUT = {"type": "object", "additionalProperties": True}


def tool_definitions() -> list[dict[str, Any]]:
    """Return the complete, closed MCP v0.2 tool surface."""

    definitions = [
        {
            "name": "belief_status",
            "title": "BELIEF status",
            "description": (
                "Return the local server version, schemas, supported validation "
                "verticals, and enforced safety boundaries."
            ),
            "inputSchema": _object({}),
            "outputSchema": _GENERIC_OUTPUT,
        },
        {
            "name": "belief_scan",
            "title": "Scan a local workspace",
            "description": (
                "Run BELIEF's existing offline static-analysis pipeline in audit "
                "mode on a path confined to the configured workspace root. "
                "Returns a run ID and resource URIs, not a vulnerability verdict."
            ),
            "inputSchema": _object(
                {
                    "workspace": _string(min_length=1),
                    "audit_mode": {"type": "boolean", "const": True, "default": True},
                    "reportability": {"type": "boolean", "default": True},
                    "max_files": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 200,
                        "default": 200,
                    },
                },
                required=("workspace",),
            ),
            "outputSchema": _GENERIC_OUTPUT,
        },
        {
            "name": "belief_get_case",
            "title": "Get an audit case",
            "description": (
                "Return one complete structured AuditCase from an in-memory scan run."
            ),
            "inputSchema": _object(
                {"run_id": _RUN_ID_INPUT, "case_id": _CASE_ID_INPUT},
                required=("run_id", "case_id"),
            ),
            "outputSchema": AUDIT_CASE_SCHEMA,
        },
        {
            "name": "belief_explain_case",
            "title": "Explain an audit case",
            "description": (
                "Normalize one AuditCase into deterministic source, sink, path, "
                "guarantee, blocker, contradiction, and missing-evidence fields."
            ),
            "inputSchema": _object(
                {"run_id": _RUN_ID_INPUT, "case_id": _CASE_ID_INPUT},
                required=("run_id", "case_id"),
            ),
            "outputSchema": _GENERIC_OUTPUT,
        },
        {
            "name": "belief_build_validation_plan",
            "title": "Build a validation plan",
            "description": (
                "Build and store BELIEF's canonical non-executing ValidationPlan "
                "for one AuditCase. This tool never runs the plan or target code."
            ),
            "inputSchema": _object(
                {"run_id": _RUN_ID_INPUT, "case_id": _CASE_ID_INPUT},
                required=("run_id", "case_id"),
            ),
            "outputSchema": VALIDATION_PLAN_SCHEMA,
        },
        {
            "name": "belief_prepare_validation_fixture",
            "title": "Prepare a registered validation fixture",
            "description": (
                "Statically scan the exact transparent source of one immutable "
                "registered fixture and store a canonical plan with a trusted "
                "fixture-only binding. No arbitrary source or path is accepted."
            ),
            "inputSchema": _object(
                {"fixture_id": _string(min_length=1)},
                required=("fixture_id",),
            ),
            "outputSchema": _GENERIC_OUTPUT,
        },
        {
            "name": "belief_prepare_authorized_project_pilot",
            "title": "Prepare the authorized flask-jwt-extended pilot",
            "description": (
                "Verify the configured workspace against the one pinned "
                "flask-jwt-extended revision and canonical source digest, then "
                "perform static analysis and create non-executable bindings. "
                "A separate startup authorization is mandatory. This tool "
                "accepts no path, module, callable, or source and always "
                "abstains from dynamic target execution."
            ),
            "inputSchema": _object(
                {
                    "adapter_id": {
                        "type": "string",
                        "const": FLASKJWT_PILOT_ADAPTER_ID,
                    },
                    "authorization_id": {
                        "type": "string",
                        "pattern": "^auth_[0-9a-f]{64}$",
                    },
                    "source_revision": {
                        "type": "string",
                        "const": FLASKJWT_PILOT_SOURCE_REVISION,
                    },
                    "source_digest": {
                        "type": "string",
                        "const": FLASKJWT_PILOT_SOURCE_DIGEST,
                    },
                    "acknowledge_authorized_project_access": {
                        "type": "boolean",
                        "const": True,
                    },
                },
                required=(
                    "adapter_id",
                    "authorization_id",
                    "source_revision",
                    "source_digest",
                    "acknowledge_authorized_project_access",
                ),
            ),
            "outputSchema": _GENERIC_OUTPUT,
        },
        {
            "name": "belief_validate_plan",
            "title": "Validate a bound registered fixture plan",
            "description": (
                "Run only an existing plan prepared and exactly bound to one "
                "transparent registered fixture in the hardened local worker. "
                "The result never confirms an arbitrary scanned target."
            ),
            "inputSchema": _object(
                {
                    "run_id": _RUN_ID_INPUT,
                    "plan_id": _string(min_length=1),
                    "fixture_id": _string(min_length=1),
                    "timeout_ms": {
                        "type": "integer",
                        "minimum": MCP_MIN_VALIDATION_TIMEOUT_MS,
                        "maximum": MCP_MAX_VALIDATION_TIMEOUT_MS,
                    },
                    "acknowledge_local_execution": {
                        "type": "boolean",
                        "const": True,
                    },
                },
                required=(
                    "run_id",
                    "plan_id",
                    "fixture_id",
                    "timeout_ms",
                    "acknowledge_local_execution",
                ),
            ),
            "outputSchema": VALIDATION_RESULT_SCHEMA,
        },
        {
            "name": "belief_compare_runs",
            "title": "Compare two scan runs",
            "description": (
                "Compare two in-memory runs of the same target and report new, "
                "resolved, changed, and fingerprint-matched audit cases."
            ),
            "inputSchema": _object(
                {
                    "before_run_id": _RUN_ID_INPUT,
                    "after_run_id": _RUN_ID_INPUT,
                },
                required=("before_run_id", "after_run_id"),
            ),
            "outputSchema": _GENERIC_OUTPUT,
        },
        {
            "name": "belief_run_local_benchmark",
            "title": "Run the transparent local benchmark",
            "description": (
                "Run only BELIEF's transparent eight-case local_validation_v2 "
                "corpus. The SusVibes holdout is never accepted or opened."
            ),
            "inputSchema": _object(
                {
                    "benchmark": {
                        "type": "string",
                        "const": "local_validation_v2",
                    }
                },
                required=("benchmark",),
            ),
            "outputSchema": _GENERIC_OUTPUT,
        },
    ]
    for definition in definitions:
        definition["annotations"] = dict(
            _LOCAL_EXECUTION_ANNOTATIONS
            if definition["name"] == "belief_validate_plan"
            else _READ_ONLY_ANNOTATIONS
        )
        definition["execution"] = dict(_NO_BACKGROUND_EXECUTION)
    return definitions


def static_resource_definitions() -> list[dict[str, Any]]:
    return [
        {
            "uri": "belief://status",
            "name": "belief-status",
            "title": "BELIEF MCP status",
            "description": "Versioned server status and enforced execution boundaries.",
            "mimeType": "application/json",
        },
        {
            "uri": "belief://capabilities",
            "name": "belief-capabilities",
            "title": "BELIEF MCP capabilities",
            "description": "Closed tool surface, resources, and explicit limitations.",
            "mimeType": "application/json",
        },
        *[
            {
                "uri": uri,
                "name": uri.rsplit("/", 1)[-1],
                "title": schema["title"],
                "description": f"JSON Schema for {schema['title']}.",
                "mimeType": "application/schema+json",
            }
            for uri, schema in PUBLIC_SCHEMAS.items()
        ],
    ]


def resource_template_definitions() -> list[dict[str, Any]]:
    return [
        {
            "uriTemplate": "belief://runs/{run_id}",
            "name": "belief-run",
            "title": "BELIEF scan run",
            "description": "Deterministic summary of an in-memory static-analysis run.",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "belief://runs/{run_id}/audit-cases",
            "name": "belief-run-audit-cases",
            "title": "BELIEF run audit cases",
            "description": "All AuditCase objects produced by an in-memory run.",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "belief://runs/{run_id}/validation-plans",
            "name": "belief-run-validation-plans",
            "title": "BELIEF run validation plans",
            "description": "Plans explicitly built for cases in an in-memory run.",
            "mimeType": "application/json",
        },
        {
            "uriTemplate": "belief://runs/{run_id}/validation-results",
            "name": "belief-run-validation-results",
            "title": "BELIEF run validation results",
            "description": (
                "Bounded results from registered transparent fixture validation."
            ),
            "mimeType": "application/json",
        },
    ]


def status_payload(
    *,
    workspace_root: str,
    benchmark_available: bool,
    authorized_project_pilot_available: bool,
) -> dict[str, Any]:
    return {
        "version": MCP_SERVER_VERSION,
        "protocol_version": MCP_PROTOCOL_VERSION,
        "phase": "v0.2-registered-fixture-validation",
        "workspace_root": workspace_root,
        "supported_verticals": list(SUPPORTED_VALIDATION_VERTICALS),
        "audit_case_schema": AUDIT_SCHEMA_VERSION,
        "validation_plan_schema": VALIDATION_PLAN_SCHEMA_VERSION,
        "validation_result_schema": MCP_VALIDATION_RESULT_SCHEMA_VERSION,
        "core_validation_result_schema": (
            CORE_VALIDATION_RESULT_SCHEMA_VERSION
        ),
        "metrics_schema": VALIDATION_METRICS_SCHEMA_VERSION,
        "transparent_benchmark_available": benchmark_available,
        "authorized_project_pilot_available": (
            authorized_project_pilot_available
        ),
        "authorized_project_pilot_adapter_id": FLASKJWT_PILOT_ADAPTER_ID,
        "authorized_project_pilot_execution_scope": (
            AUTHORIZED_PROJECT_EXECUTION_SCOPE
        ),
        "authorized_project_dynamic_execution_enabled": False,
        "network_enabled": False,
        "subprocess_enabled": False,
        "shell_enabled": False,
        "docker_enabled": False,
        "dynamic_import_enabled": False,
        "dynamic_execution_enabled": True,
        "dynamic_execution_scope": REGISTERED_FIXTURE_EXECUTION_SCOPE,
        "local_worker_execution_enabled": True,
        "max_concurrent_validations": MCP_MAX_CONCURRENT_VALIDATIONS,
        "max_in_flight_requests": MCP_MAX_IN_FLIGHT_REQUESTS,
        "max_stored_runs": MCP_MAX_STORED_RUNS,
        "max_validation_results_per_run": MCP_MAX_RESULTS_PER_RUN,
        "max_total_validation_results": MCP_MAX_TOTAL_RESULTS,
        "write_tools_enabled": False,
        "custom_adapters_enabled": False,
        "holdout_access_enabled": False,
        "confirmed_vulnerability_verdict_enabled": False,
    }
