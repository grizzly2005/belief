"""End-to-end Flask/FastAPI validation through the existing runner."""

from __future__ import annotations

from dataclasses import replace

import pytest

from belief.validation.execution_models import (
    ValidationContractError,
)
from belief.validation.models import ValidationResult
from belief.validation.plans import build_validation_plan
from belief.validation.runner import run_validation_plan
from belief.validation.worker import (
    IsolatedWebValidationExecutor,
    build_isolated_web_context,
    run_isolated_web_validation_plan,
    run_worker_request,
)
from belief.validation.worker.contracts import WorkerRequest
from belief.validation.worker.registry import get_fixture_spec
from belief.validation.web import optional_framework_available


pytestmark = pytest.mark.security

_FIXTURES = (
    ("fx_01d7c2_v1", "flask", "bypassed"),
    ("fx_18a4e9_v1", "flask", "enforced"),
    ("fx_2f6b10_v1", "flask", "bypassed"),
    ("fx_3c8d57_v1", "flask", "enforced"),
    ("fx_47e1a3_v1", "fastapi", "bypassed"),
    ("fx_5b9c20_v1", "fastapi", "enforced"),
    ("fx_6d04f8_v1", "fastapi", "bypassed"),
    ("fx_7a2e61_v1", "fastapi", "enforced"),
)


def _plan(case_type: str, *, identifier: str = ""):
    return build_validation_plan({
        "case_id": identifier or f"isolated_{case_type}",
        "case_type": case_type,
        "status": "needs_review",
        "review_priority": "high",
        "file": "registered_fixture.py",
        "line": 10,
        "rule_id": "BELIEF_ISOLATED_WEB_FIXTURE",
        "cwe": (
            "CWE-22"
            if case_type == "path_traversal_possible"
            else "CWE-639"
        ),
        "source": "controlled_test_client_input",
        "sink": "registered_web_fixture",
        "missing_guarantees": [
            "runtime_guard_enforcement_not_observed",
        ],
        "route_context": {
            "framework": "registered_web_fixture",
            "route": "/local-test-client",
        },
        "structured_dataflow": {
            "schema_version": "belief.dataflow_evidence.v1",
            "source": {
                "symbol": "controlled_test_client_input",
                "line": 9,
            },
            "sink": {
                "symbol": "registered_web_fixture",
                "line": 10,
            },
            "ordered_nodes": [
                {
                    "symbol": "controlled_test_client_input",
                    "line": 9,
                },
                {
                    "symbol": "registered_web_fixture",
                    "line": 10,
                },
            ],
            "guard_applicability": {"applicable": False},
        },
    })


def _fixture_framework(fixture_id: str) -> str:
    spec = get_fixture_spec(fixture_id)
    assert spec is not None
    return spec.framework


def _case_type(fixture_id: str) -> str:
    spec = get_fixture_spec(fixture_id)
    assert spec is not None
    return spec.case_type


def _execution(result: ValidationResult) -> dict:
    return result.metadata["execution"]


@pytest.mark.parametrize(
    ("fixture_id", "framework", "expected_outcome"),
    _FIXTURES,
)
def test_registered_web_fixture_returns_existing_result_contract(
    fixture_id,
    framework,
    expected_outcome,
):
    if not optional_framework_available(framework):
        pytest.skip(f"optional dependency unavailable: {framework}")
    plan = _plan(
        _case_type(fixture_id),
        identifier=f"case_{fixture_id}",
    )

    result = run_isolated_web_validation_plan(
        plan,
        fixture_id=fixture_id,
        source_revision="fixture-source-v1",
    )

    assert isinstance(result, ValidationResult)
    assert result.outcome == expected_outcome
    assert result.metadata["baseline_functional"] is True
    assert result.metadata["validation_plan_id"] == plan.plan_id
    assert result.metadata["source_revision"] == "fixture-source-v1"
    assert result.metadata["proof_collected"]
    execution = _execution(result)
    assert execution["schema_version"] == (
        "belief.validation_execution_summary.v2"
    )
    assert execution["fixture_id"] == fixture_id
    assert execution["executed"] is True
    assert execution["baseline_passed"] is True
    assert execution["oracle_evaluated_count"] >= 5
    assert execution["observations"]


@pytest.mark.parametrize(
    "fixture_id",
    (
        "fx_01d7c2_v1",
        "fx_47e1a3_v1",
    ),
)
def test_path_worker_covers_all_required_oracles(fixture_id):
    framework = _fixture_framework(fixture_id)
    if not optional_framework_available(framework):
        pytest.skip(f"optional dependency unavailable: {framework}")
    result = run_isolated_web_validation_plan(
        _plan(
            "path_traversal_possible",
            identifier=f"oracles_{fixture_id}",
        ),
        fixture_id=fixture_id,
        source_revision="fixture-source-v1",
    )
    observations = {
        item["scenario"]: item
        for item in _execution(result)["observations"]
    }

    assert {
        "legitimate_path",
        "parent_segment",
        "absolute_path",
        "normalized_equivalent",
        "symlink_boundary",
        "filesystem_final_state",
    } <= set(observations)
    assert observations["legitimate_path"]["oracle_passed"] is True
    for scenario in (
        "parent_segment",
        "absolute_path",
        "normalized_equivalent",
    ):
        assert observations[scenario]["oracle_evaluated"] is True
        assert observations[scenario]["oracle_passed"] is False
        assert observations[scenario]["actual"]["sentinel_reached"] is True
    symlink = observations["symlink_boundary"]
    assert (
        symlink["oracle_evaluated"] is True
        or "symlink_unavailable" in symlink["limitations"]
    )
    assert observations["filesystem_final_state"]["oracle_passed"] is True


@pytest.mark.parametrize(
    "fixture_id",
    (
        "fx_2f6b10_v1",
        "fx_6d04f8_v1",
    ),
)
def test_idor_worker_distinguishes_authentication_owner_and_tenant(
    fixture_id,
):
    framework = _fixture_framework(fixture_id)
    if not optional_framework_available(framework):
        pytest.skip(f"optional dependency unavailable: {framework}")
    result = run_isolated_web_validation_plan(
        _plan(
            "idor_bola_possible",
            identifier=f"oracles_{fixture_id}",
        ),
        fixture_id=fixture_id,
        source_revision="fixture-source-v1",
    )
    observations = {
        item["scenario"]: item
        for item in _execution(result)["observations"]
    }

    assert observations["read_owned_resource"]["oracle_passed"] is True
    assert observations["update_owned_resource"]["oracle_passed"] is True
    for scenario in (
        "read_foreign_resource",
        "update_foreign_resource",
        "read_cross_tenant_resource",
        "update_cross_tenant_resource",
    ):
        assert observations[scenario]["actual"]["authenticated"] is True
        assert observations[scenario]["oracle_passed"] is False
    assert observations["resource_b_final_state"]["oracle_passed"] is False
    assert observations["resource_c_final_state"]["oracle_passed"] is False
    assert observations["read_foreign_resource"]["actual"][
        "resource_owner"
    ] == "user_b"
    assert observations["read_cross_tenant_resource"]["actual"][
        "resource_tenant"
    ] == "tenant_b"


def test_semantic_result_is_deterministic_across_spawned_runs():
    if not optional_framework_available("flask"):
        pytest.skip("optional dependency unavailable: flask")
    plan = _plan(
        "idor_bola_possible",
        identifier="deterministic_flask_idor",
    )
    first = run_isolated_web_validation_plan(
        plan,
        fixture_id="fx_3c8d57_v1",
        source_revision="fixture-source-v1",
    )
    second = run_isolated_web_validation_plan(
        plan,
        fixture_id="fx_3c8d57_v1",
        source_revision="fixture-source-v1",
    )

    assert first.to_dict() == second.to_dict()
    assert _execution(first)["summary_id"] == _execution(second)["summary_id"]


def test_raw_worker_response_attests_guards_without_claiming_os_sandbox():
    if not optional_framework_available("flask"):
        pytest.skip("optional dependency unavailable: flask")
    response = run_worker_request(WorkerRequest(
        fixture_id="fx_18a4e9_v1",
        validation_plan_id="vp_0123456789abcdef",
        validation_plan_digest="a" * 64,
        source_revision="fixture-source-v1",
        correlation_id="corr_attestation",
    ))

    assert response.worker_status == "completed"
    attestation = response.attestation
    assert attestation.environment_policy_installed is True
    assert attestation.filesystem_policy_installed is True
    assert attestation.network_policy_installed is True
    assert attestation.process_policy_installed is True
    assert attestation.timeout_enforced is True
    assert attestation.cleanup_completed is True
    assert attestation.framework == "flask"
    assert attestation.fixture_id == response.fixture_id
    assert len(attestation.fixture_registry_digest) == 64
    assert len(attestation.fixture_source_digest) == 64
    assert attestation.io_policy_violations == ()


def test_fixture_case_type_mismatch_is_inconclusive():
    plan = _plan("path_traversal_possible", identifier="mismatch")
    result = run_isolated_web_validation_plan(
        plan,
        fixture_id="fx_3c8d57_v1",
        source_revision="fixture-source-v1",
    )

    assert result.outcome == "inconclusive"
    assert _execution(result)["supported"] is False
    assert "fixture_case_type_mismatch" in _execution(result)["limitations"]


def test_unknown_fixture_is_inconclusive_through_existing_runner():
    plan = _plan("path_traversal_possible", identifier="unknown")
    result = run_isolated_web_validation_plan(
        plan,
        fixture_id="unknown_fixture_v1",
        source_revision="fixture-source-v1",
    )

    assert result.outcome == "inconclusive"
    assert _execution(result)["executed"] is False
    assert _execution(result)["baseline_passed"] is None
    assert "worker_error:unknown_fixture" in _execution(result)["limitations"]


def test_runner_rejects_an_incorrect_plan_digest_before_spawn():
    plan = _plan("path_traversal_possible", identifier="wrong_digest")
    context = build_isolated_web_context(
        plan,
        fixture_id="fx_18a4e9_v1",
        source_revision="fixture-source-v1",
    )
    tampered = replace(context, expected_plan_digest="f" * 64)

    with pytest.raises(
        ValidationContractError,
        match="expected_plan_digest",
    ):
        run_validation_plan(
            plan,
            context=tampered,
            executor_registry={
                plan.case_type: IsolatedWebValidationExecutor()
            },
        )


def test_existing_direct_executors_keep_their_original_semantics():
    path_plan = _plan(
        "path_traversal_possible",
        identifier="direct_path_non_regression",
    )
    path_context = build_isolated_web_context(
        path_plan,
        fixture_id="fx_18a4e9_v1",
        source_revision="fixture-source-v1",
    )
    assert path_context.adapter == "isolated_web_worker_v2"

    from belief.validation.execution_models import (
        ValidationExecutionContext,
    )

    direct_context = ValidationExecutionContext.for_plan(
        path_plan,
        fixture_id="direct_path_fixture",
        adapter="path_resolve_enforced",
        source_revision="direct-fixture-v1",
    )
    direct = run_validation_plan(path_plan, context=direct_context)

    assert direct.outcome == "enforced"
    assert direct.method.endswith("/path_resolve_enforced")
