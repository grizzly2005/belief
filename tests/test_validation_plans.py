"""Contracts for deterministic evidence-guided validation planning."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from belief.validation.plans import (
    VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION,
    VALIDATION_PLAN_SCHEMA_VERSION,
    VALIDATION_STRATEGIES,
    ValidationPlan,
    build_validation_plan,
    build_validation_plan_bundle,
    load_validation_plan_bundle,
    validation_result_from_plan,
    write_validation_plan_bundle,
)


pytestmark = pytest.mark.security


def _case(
    *,
    case_id: str = "case_path",
    case_type: str = "path_traversal_possible",
    status: str = "needs_review",
) -> dict:
    return {
        "case_id": case_id,
        "case_type": case_type,
        "status": status,
        "review_priority": "high",
        "confidence": 0.91,
        "severity": "high",
        "file": "app.py",
        "line": 12,
        "rule_id": "BELIEF_PATH",
        "cwe": "CWE-22",
        "source": 'request.args["path"]',
        "sink": "open(user_path)",
        "dataflow_path": [
            'request.args["path"]',
            "user_path",
            "open(user_path)",
        ],
        "sanitizers": [],
        "guarantees": [],
        "missing_guarantees": ["path.is_within_store"],
        "human_next_steps": ["Confirm whether the path is attacker-controlled."],
        "route_context": {
            "framework": "flask",
            "methods": ["GET"],
            "route": "/download",
            "handler": "download",
            "confidence": 1.0,
        },
        "structured_dataflow": {
            "schema_version": "belief.dataflow_evidence.v1",
            "source": {
                "file": "app.py",
                "line": 11,
                "symbol": 'request.args["path"]',
            },
            "sink": {
                "file": "app.py",
                "line": 12,
                "symbol": "open(user_path)",
            },
            "function_context": "download",
            "ordered_nodes": [
                {
                    "line": 11,
                    "symbol": 'request.args["path"]',
                },
                {"line": 12, "symbol": "open(user_path)"},
            ],
            "guard_applicability": {"applicable": False},
            "rejection_reason": "guard_missing",
            "truncation_reason": "",
        },
        "related_finding_fingerprint": "fp_path",
        "metadata": {
            "reportability": {
                "verdict": "needs_manual_validation",
                "blocking_factors": ["runtime_validation_missing"],
            }
        },
    }


def _audit(*cases: dict) -> dict:
    return {
        "schema_version": "belief.audit.v1",
        "target": "sample-project",
        "audit_cases": list(cases),
    }


def test_path_plan_is_versioned_safe_and_oracle_driven():
    plan = build_validation_plan(_case())
    payload = plan.to_dict()

    assert payload["schema_version"] == VALIDATION_PLAN_SCHEMA_VERSION
    assert payload["strategy"] == "property_guided_path_boundary"
    assert payload["subject_id"] == "case_path"
    assert payload["target"]["route_context"]["route"] == "/download"
    assert "path.is_within_store" in payload["evidence_gaps"]
    assert "dynamic_exploitability_not_observed" in payload["evidence_gaps"]
    assert (
        "reportability_blocker:runtime_validation_missing"
        in payload["evidence_gaps"]
    )
    assert any(
        oracle["kind"] == "path_boundary_invariant"
        for oracle in payload["oracles"]
    )
    assert payload["safety"] == {
        "authorized_scope_required": True,
        "automatic_scope_expansion": False,
        "destructive_actions_allowed": False,
        "network_mode": "forbidden",
        "payload_policy": "benign_markers_only",
        "production_data_allowed": False,
        "real_secrets_allowed": False,
    }
    assert payload["result_contract"] == {
        "schema_version": "belief.validation_result.v1",
        "subject_id": "case_path",
        "subject_kind": "audit_case",
        "required_metadata": {"validation_plan_id": plan.plan_id},
        "allowed_outcomes": [
            "bypassed",
            "enforced",
            "false_positive",
            "inconclusive",
            "informational",
            "unknown",
            "validated_candidate",
        ],
    }
    assert payload["reachability_hints"]["schema_version"] == (
        "belief.validation_reachability.v1"
    )
    assert payload["reachability_hints"]["source"]["line"] == 11
    assert payload["reachability_hints"]["sink"]["line"] == 12
    assert payload["reachability_hints"]["ordered_nodes"]


def test_idor_plan_uses_stateful_authorization_differential():
    case = _case(
        case_id="case_idor",
        case_type="idor_bola_possible",
    )
    case.update(
        {
            "cwe": "CWE-639",
            "source": "item_id",
            "sink": "Item.query.get(item_id)",
            "missing_guarantees": ["query.scoped_to_current_user"],
        }
    )

    plan = build_validation_plan(case)

    assert plan.strategy == "stateful_authorization_differential"
    assert any(
        stimulus.kind == "ownership_counterfactual"
        for stimulus in plan.stimuli
    )
    assert {oracle.kind for oracle in plan.oracles} == {
        "authorization_differential",
        "functional_baseline",
        "state_invariant",
    }


@pytest.mark.parametrize(
    "case_type",
    [
        "idor_bola_possible",
        "command_injection_possible",
        "ssrf_possible",
        "sql_injection_possible",
        "xss_possible",
        "unsafe_deserialization_possible",
    ],
)
def test_runtime_strategies_include_independent_functional_baseline(case_type):
    plan = build_validation_plan(
        _case(case_id=f"case_{case_type}", case_type=case_type)
    )

    assert any(
        oracle.kind.startswith("functional_")
        for oracle in plan.oracles
    )


def test_protected_case_generates_defensive_regression_plan():
    case = _case(status="protected")
    case["guarantees"] = ["path.is_within_store"]
    case["missing_guarantees"] = []

    plan = build_validation_plan(case)

    assert plan.strategy == "defensive_regression"
    assert "runtime_guard_enforcement_not_observed" in plan.evidence_gaps
    assert {oracle.kind for oracle in plan.oracles} == {
        "functional_non_regression",
        "guard_enforcement",
    }


def test_ssrf_plan_never_requests_live_network():
    case = _case(
        case_id="case_ssrf",
        case_type="ssrf_possible",
    )
    case.update(
        {
            "cwe": "CWE-918",
            "source": "request.args['url']",
            "sink": "httpx.get(url)",
        }
    )

    plan = build_validation_plan(case)

    assert plan.strategy == "mocked_network_policy_differential"
    assert plan.safety["network_mode"] == "mocked_only"
    assert plan.safety["destructive_actions_allowed"] is False
    assert any(
        "recording fakes" in prerequisite
        for prerequisite in plan.prerequisites
    )


def test_plan_round_trip_preserves_semantics_and_id():
    original = build_validation_plan(_case())

    restored = ValidationPlan.from_dict(original.to_dict())

    assert restored == original
    assert restored.plan_id == original.plan_id
    assert restored.to_dict() == original.to_dict()


def test_plan_rejects_content_with_forged_plan_id():
    payload = build_validation_plan(_case()).to_dict()
    payload["plan_id"] = "vp_forged"

    with pytest.raises(ValueError, match="plan_id does not match"):
        ValidationPlan.from_dict(payload)


def test_validation_result_adapter_links_plan_to_audit_case():
    plan = build_validation_plan(_case())

    result = validation_result_from_plan(
        plan,
        source="pytest_local_harness",
        outcome="enforced",
        confidence=0.93,
        tested=True,
        method="temporary_directory_boundary_check",
        reason="Every resolved fixture path remained under the allowed root.",
        evidence=("baseline_passed", "counterfactuals_blocked"),
    )

    assert result.subject_id == "case_path"
    assert result.subject_kind == "audit_case"
    assert result.outcome == "enforced"
    assert result.tested is True
    assert result.human_validated is False
    assert result.metadata["claimed_tested"] is True
    assert result.metadata["claimed_human_validated"] is False
    assert result.metadata["proof_state"] == "unverified_legacy_claim"
    assert result.metadata["validation_plan_id"] == plan.plan_id
    assert result.metadata["validation_strategy"] == plan.strategy


def test_validation_result_adapter_rejects_reserved_metadata_overrides():
    plan = build_validation_plan(_case())

    with pytest.raises(ValueError, match="reserved bindings"):
        validation_result_from_plan(
            plan,
            source="test",
            outcome="inconclusive",
            metadata={"validation_plan_id": "attacker-plan"},
        )


def test_validation_result_adapter_rejects_unknown_outcome():
    with pytest.raises(ValueError, match="unsupported validation outcome"):
        validation_result_from_plan(
            build_validation_plan(_case()),
            source="test",
            outcome="definitely_confirmed",
        )


def test_bundle_is_deterministic_sorted_and_does_not_mutate_input():
    path_case = _case()
    idor_case = _case(
        case_id="case_idor",
        case_type="idor_bola_possible",
    )
    idor_case["review_priority"] = "critical"
    audit = _audit(path_case, idor_case)
    before = copy.deepcopy(audit)

    first = build_validation_plan_bundle(audit)
    second = build_validation_plan_bundle(audit)

    assert audit == before
    assert first == second
    assert first["schema_version"] == VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION
    assert first["plan_count"] == 2
    assert first["plans"][0]["subject_id"] == "case_idor"
    assert first["execution_boundary"] == {
        "offline_generation": True,
        "executes_target": False,
        "network_required": False,
        "confirms_vulnerability": False,
        "requires_human_or_harness_result": True,
    }
    unsigned = dict(first)
    digest = unsigned.pop("deterministic_digest")
    assert len(digest) == 64
    assert json.dumps(first, sort_keys=True) == json.dumps(
        second,
        sort_keys=True,
    )


def test_bundle_rejects_duplicate_case_ids():
    with pytest.raises(ValueError, match="duplicate audit case id"):
        build_validation_plan_bundle(_audit(_case(), _case()))


def test_bundle_requires_audit_cases_list():
    with pytest.raises(ValueError, match="audit_cases list"):
        build_validation_plan_bundle({"schema_version": "belief.audit.v1"})


def test_write_is_create_only_and_load_verifies_digest(tmp_path):
    audit_path = tmp_path / "audit.json"
    output_path = tmp_path / "plans.json"
    audit_path.write_text(
        json.dumps(_audit(_case()), indent=2),
        encoding="utf-8",
    )

    written = write_validation_plan_bundle(audit_path, output_path)
    loaded, plans = load_validation_plan_bundle(output_path)

    assert loaded == written
    assert len(plans) == 1
    assert plans[0].subject_id == "case_path"
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_validation_plan_bundle(audit_path, output_path)


def test_writer_refuses_to_replace_its_input(tmp_path):
    audit_path = tmp_path / "audit.json"
    audit_path.write_text(json.dumps(_audit(_case())), encoding="utf-8")

    with pytest.raises(ValueError, match="must differ"):
        write_validation_plan_bundle(
            audit_path,
            audit_path,
            overwrite=True,
        )


def test_load_rejects_tampered_bundle(tmp_path):
    audit_path = tmp_path / "audit.json"
    output_path = tmp_path / "plans.json"
    audit_path.write_text(json.dumps(_audit(_case())), encoding="utf-8")
    write_validation_plan_bundle(audit_path, output_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    payload["plans"][0]["objective"] = "tampered"
    output_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="digest mismatch"):
        load_validation_plan_bundle(output_path)


def test_load_rejects_resigned_noncanonical_result_contract(tmp_path):
    audit_path = tmp_path / "audit.json"
    output_path = tmp_path / "plans.json"
    audit_path.write_text(json.dumps(_audit(_case())), encoding="utf-8")
    write_validation_plan_bundle(audit_path, output_path)
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    payload["plans"][0]["result_contract"]["subject_kind"] = (
        "validation_plan"
    )
    unsigned = dict(payload)
    unsigned.pop("deterministic_digest", None)
    payload["deterministic_digest"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    output_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="non-canonical plan"):
        load_validation_plan_bundle(output_path)


def test_builder_does_not_open_network_or_spawn_processes(monkeypatch):
    def reject_side_effect(*_args, **_kwargs):
        raise AssertionError("validation-plan generation attempted a side effect")

    monkeypatch.setattr(socket.socket, "connect", reject_side_effect)
    monkeypatch.setattr(subprocess, "Popen", reject_side_effect)

    bundle = build_validation_plan_bundle(_audit(_case()))

    assert bundle["execution_boundary"]["executes_target"] is False
    assert bundle["execution_boundary"]["network_required"] is False


def test_public_json_schema_tracks_generated_contract():
    root = Path(__file__).resolve().parents[1]
    schema_path = (
        root
        / "schemas"
        / "belief.validation-plan-bundle.v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    bundle = build_validation_plan_bundle(_audit(_case()))

    assert schema["properties"]["schema_version"]["const"] == bundle[
        "schema_version"
    ]
    plan_schema = schema["$defs"]["validationPlan"]
    assert set(plan_schema["required"]).issubset(bundle["plans"][0])
    assert plan_schema["properties"]["schema_version"]["const"] == (
        VALIDATION_PLAN_SCHEMA_VERSION
    )
    assert schema["$defs"]["executionBoundary"]["properties"][
        "executes_target"
    ]["const"] is False


def test_script_builds_bundle_without_executing_target(tmp_path):
    audit_path = tmp_path / "audit.json"
    output_path = tmp_path / "plans.json"
    audit_path.write_text(json.dumps(_audit(_case())), encoding="utf-8")
    root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [
            sys.executable,
            str(root / "scripts" / "build_validation_plans.py"),
            "--audit",
            str(audit_path),
            "--output",
            str(output_path),
        ],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    bundle = json.loads(output_path.read_text(encoding="utf-8"))
    assert summary["plan_count"] == 1
    assert summary["executes_target"] is False
    assert bundle["execution_boundary"]["network_required"] is False


def test_published_json_schema_matches_runtime_contract():
    root = Path(__file__).resolve().parents[1]
    schema = json.loads(
        (root / "schemas" / "belief.validation-plan-bundle.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert schema["$schema"].endswith("draft/2020-12/schema")
    assert schema["properties"]["schema_version"]["const"] == (
        VALIDATION_PLAN_BUNDLE_SCHEMA_VERSION
    )
    plan_schema = schema["$defs"]["validationPlan"]
    assert plan_schema["properties"]["schema_version"]["const"] == (
        VALIDATION_PLAN_SCHEMA_VERSION
    )
    assert set(VALIDATION_STRATEGIES) == set(
        plan_schema["properties"]["strategy"]["enum"]
    )
    runtime_contract = build_validation_plan(_case()).to_dict()["result_contract"]
    contract_schema = schema["$defs"]["resultContract"]
    assert set(contract_schema["required"]) == set(runtime_contract)
    assert runtime_contract["subject_kind"] in (
        contract_schema["properties"]["subject_kind"]["enum"]
    )
    assert set(
        contract_schema["properties"]["allowed_outcomes"]["items"]["enum"]
    ) == set(runtime_contract["allowed_outcomes"])
