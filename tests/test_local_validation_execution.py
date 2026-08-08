"""Contracts and vertical tests for isolated local validation execution."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from belief.validation.execution_models import (
    ValidationContractError,
    ValidationExecutionContext,
    ValidationExecutionSummary,
    ValidationObservation,
    build_validation_fixture_bundle,
    load_validation_fixture_bundle,
)
from belief.validation.plan_models import canonical_digest
from belief.validation.plan_models import ValidationPlan
from belief.validation.models import ValidationResult
from belief.validation.plans import build_validation_plan
from belief.validation.runner import (
    run_validation_plan,
    run_validation_plan_bundle,
    write_validation_result_bundle,
)


pytestmark = pytest.mark.security


def _plan(
    case_type: str = "path_traversal_possible",
    *,
    status: str = "needs_review",
    case_id: str = "",
):
    identifier = case_id or f"case_{case_type}_{status}"
    return build_validation_plan({
        "case_id": identifier,
        "case_type": case_type,
        "status": status,
        "review_priority": "high",
        "file": "fixture.py",
        "line": 10,
        "rule_id": "BELIEF_LOCAL_FIXTURE",
        "cwe": (
            "CWE-22"
            if case_type == "path_traversal_possible"
            else "CWE-639"
        ),
        "source": "controlled_input",
        "sink": "local_fixture_sink",
        "missing_guarantees": ["runtime_policy_not_observed"],
        "route_context": {
            "framework": "direct_python_fixture",
            "route": "/local-only",
        },
        "structured_dataflow": {
            "schema_version": "belief.dataflow_evidence.v1",
            "source": {"symbol": "controlled_input", "line": 9},
            "sink": {"symbol": "local_fixture_sink", "line": 10},
            "ordered_nodes": [
                {"symbol": "controlled_input", "line": 9},
                {"symbol": "local_fixture_sink", "line": 10},
            ],
            "guard_applicability": {"applicable": False},
        },
    })


def _context(plan, adapter: str) -> ValidationExecutionContext:
    return ValidationExecutionContext.for_plan(
        plan,
        fixture_id=f"fixture_{adapter}",
        adapter=adapter,
        source_revision="fixture-source-sha256:" + "a" * 64,
    )


def _execution(result) -> dict:
    return result.metadata["execution"]


def _observations(result) -> list[dict]:
    return _execution(result)["observations"]


def test_context_round_trip_is_bound_and_tamper_evident():
    plan = _plan()
    context = _context(plan, "path_resolve_enforced")
    restored = ValidationExecutionContext.from_dict(context.to_dict())

    assert restored == context
    assert restored.expected_plan_digest == canonical_digest(plan.to_dict())

    tampered = context.to_dict()
    tampered["adapter"] = "path_join_unchecked"
    with pytest.raises(
        ValidationContractError,
        match="fixture digest mismatch",
    ):
        ValidationExecutionContext.from_dict(tampered)


def test_runner_selects_executor_by_exact_case_type():
    path_plan = _plan()
    idor_plan = _plan("idor_bola_possible")

    path = run_validation_plan(
        path_plan,
        context=_context(path_plan, "path_resolve_enforced"),
    )
    idor = run_validation_plan(
        idor_plan,
        context=_context(idor_plan, "idor_owner_tenant_enforced"),
    )

    assert _execution(path)["validation_type"] == "path_traversal"
    assert _execution(idor)["validation_type"] == "idor_bola"


def test_direct_python_target_requires_explicit_process_registry():
    plan = _plan()

    def registered_safe_target(allowed_root: Path, _value: str) -> Path:
        return allowed_root / "public.txt"

    context = ValidationExecutionContext.for_plan(
        plan,
        fixture_id="explicit_python_callable",
        adapter="registered_safe_target",
        source_revision="callable-fixture-v1",
        adapter_registry={
            "registered_safe_target": registered_safe_target,
        },
    )

    result = run_validation_plan(plan, context=context)

    assert result.outcome == "enforced"
    assert result.method.endswith("/registered_safe_target")


def test_process_local_adapter_disables_io_absence_attestation():
    plan = _plan()

    def registered_safe_target(allowed_root: Path, _value: str) -> Path:
        return allowed_root / "public.txt"

    context = ValidationExecutionContext.for_plan(
        plan,
        fixture_id="explicit_python_callable_bundle",
        adapter="registered_safe_target",
        source_revision="callable-fixture-v1",
        adapter_registry={
            "registered_safe_target": registered_safe_target,
        },
    )

    payload = run_validation_plan_bundle(
        [plan],
        contexts={plan.plan_id: context},
    )
    boundaries = payload["boundaries"]

    assert boundaries["execution_mode"] == (
        "trusted_process_local_extension"
    )
    assert boundaries["process_local_extension_used"] is True
    assert boundaries["io_usage_attested"] is False
    for field in (
        "local_only",
        "network_used",
        "subprocess_used",
        "shell_used",
        "docker_used",
        "dynamic_import_used",
        "production_data_used",
    ):
        assert boundaries[field] is None


def test_process_registry_cannot_shadow_builtin_adapter_semantics():
    plan = _plan()

    def fake_safe_target(allowed_root: Path, _value: str) -> Path:
        return allowed_root / "public.txt"

    context = ValidationExecutionContext.for_plan(
        plan,
        fixture_id="builtin_shadow_attempt",
        adapter="path_join_unchecked",
        source_revision="shadow-fixture-v1",
        adapter_registry={
            "path_join_unchecked": fake_safe_target,
        },
    )

    result = run_validation_plan(plan, context=context)

    assert result.outcome == "bypassed"


def test_runner_rejects_tampered_plan_identity():
    payload = _plan().to_dict()
    payload["objective"] = "tampered after plan creation"

    with pytest.raises(
        ValidationContractError,
        match="plan_id does not match",
    ):
        run_validation_plan(
            payload,
            context=_context(_plan(), "path_resolve_enforced"),
        )


def test_result_links_plan_source_fixture_and_revision():
    plan = _plan()
    context = _context(plan, "path_resolve_enforced")

    result = run_validation_plan(plan, context=context)

    assert result.subject_id == plan.subject_id
    assert result.metadata["validation_plan_id"] == plan.plan_id
    assert result.metadata["validation_plan_digest"] == (
        canonical_digest(plan.to_dict())
    )
    assert result.metadata["source_revision"] == context.source_revision
    assert result.metadata["fixture_id"] == context.fixture_id
    assert result.metadata["baseline_functional"] is True
    assert result.metadata["proof_collected"]
    assert result.metadata["human_confirmation_required"] is False


def test_identical_execution_is_semantically_stable():
    plan = _plan()
    context = _context(plan, "path_resolve_enforced")

    first = run_validation_plan(plan, context=context).to_dict()
    second = run_validation_plan(plan, context=context).to_dict()

    assert first == second


def test_result_writer_is_create_only(tmp_path):
    plan = _plan()
    context = _context(plan, "path_resolve_enforced")
    payload = run_validation_plan_bundle(
        [plan],
        contexts={plan.plan_id: context},
    )
    output = tmp_path / "results.json"

    write_validation_result_bundle(output, payload)
    with pytest.raises(
        ValidationContractError,
        match="refusing to overwrite",
    ):
        write_validation_result_bundle(output, payload)


def test_unsupported_type_remains_unexecuted_and_inconclusive():
    plan = _plan("ssrf_possible")
    context = _context(plan, "explicitly_unsupported")

    result = run_validation_plan(plan, context=context)

    assert result.outcome == "inconclusive"
    assert result.tested is False
    assert _execution(result)["supported"] is False
    assert _execution(result)["executed"] is False
    assert _execution(result)["limitations"] == [
        "unsupported_validation_type:ssrf_possible"
    ]


def test_fixture_bundle_is_canonical_and_sorted():
    first = _plan(case_id="case_b")
    second = _plan(
        "idor_bola_possible",
        case_id="case_a",
    )
    payload = build_validation_fixture_bundle([
        _context(first, "path_resolve_enforced"),
        _context(second, "idor_owner_tenant_enforced"),
    ])

    assert payload["fixture_count"] == 2
    assert [
        item["validation_plan_id"] for item in payload["fixtures"]
    ] == sorted((first.plan_id, second.plan_id))
    assert payload["boundaries"]["network_allowed"] is False
    assert len(payload["deterministic_digest"]) == 64


def test_fixture_loader_rejects_resigned_noncanonical_root(tmp_path):
    plan = _plan()
    payload = build_validation_fixture_bundle([
        _context(plan, "path_resolve_enforced")
    ])
    payload["unexpected"] = "field"
    unsigned = dict(payload)
    unsigned.pop("deterministic_digest")
    payload["deterministic_digest"] = canonical_digest(unsigned)
    path = tmp_path / "fixtures.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(
        ValidationContractError,
        match="not canonical",
    ):
        load_validation_fixture_bundle(path)


def test_bypass_summary_requires_failed_security_oracle():
    plan = _plan()
    context = _context(plan, "path_resolve_enforced")
    baseline = ValidationObservation(
        validation_plan_id=plan.plan_id,
        subject_id=plan.subject_id,
        validation_type="path_traversal",
        scenario="legitimate_path",
        stimulus="public.txt",
        oracle="functional_baseline",
        expected="baseline works",
        actual={"decision": "read"},
        baseline=True,
        oracle_role="functional_baseline",
        required_for_conclusion=True,
        oracle_evaluated=True,
        oracle_passed=True,
    )

    with pytest.raises(
        ValidationContractError,
        match="bypass requires",
    ):
        ValidationExecutionSummary(
            validation_plan_id=plan.plan_id,
            validation_plan_digest=canonical_digest(plan.to_dict()),
            subject_id=plan.subject_id,
            validation_type="path_traversal",
            source_revision=context.source_revision,
            fixture_id=context.fixture_id,
            fixture_digest=context.fixture_digest,
            adapter=context.adapter,
            supported=True,
            executed=True,
            outcome="bypassed",
            baseline_passed=True,
            observations=(baseline,),
        )


def test_path_traversal_vulnerable_fixture_reaches_only_local_sentinel():
    plan = _plan()

    result = run_validation_plan(
        plan,
        context=_context(plan, "path_join_unchecked"),
    )

    assert result.outcome == "bypassed"
    assert result.metadata["baseline_functional"] is True
    failures = [
        item
        for item in _observations(result)
        if item["oracle_passed"] is False
    ]
    assert {item["scenario"] for item in failures} >= {
        "parent_segment",
        "normalized_equivalent",
        "absolute_path",
    }
    assert all(
        item["actual"]["resolved_path"]
        != "outside_fixture_root"
        for item in failures
    )
    assert any(
        item["actual"]["sentinel_reached"] is True
        for item in failures
    )


def test_path_traversal_protected_fixture_keeps_baseline_functional():
    plan = _plan(status="protected")

    result = run_validation_plan(
        plan,
        context=_context(plan, "path_resolve_enforced"),
    )

    assert result.outcome == "enforced"
    assert _execution(result)["baseline_passed"] is True
    assert all(
        item["oracle_passed"] is True
        for item in _observations(result)
        if item["oracle_evaluated"]
    )


@pytest.mark.parametrize(
    "adapter",
    [
        "path_guard_after_sink",
        "path_sanitizer_result_unused",
    ],
)
def test_path_late_or_ignored_guard_does_not_hide_bypass(adapter):
    plan = _plan(status="protected")

    result = run_validation_plan(
        plan,
        context=_context(plan, adapter),
    )

    assert result.outcome == "bypassed"
    assert _execution(result)["protected_regression"] is True


def test_path_symlink_is_evaluated_when_platform_supports_it():
    plan = _plan()

    result = run_validation_plan(
        plan,
        context=_context(plan, "path_join_unchecked"),
    )
    symlink = next(
        item
        for item in _observations(result)
        if item["scenario"] == "symlink_boundary"
    )

    if symlink["actual"].get("symlink_supported") is False:
        pytest.skip("platform does not permit fixture symlinks")
    assert symlink["oracle_evaluated"] is True
    assert symlink["oracle_passed"] is False
    assert symlink["actual"]["sentinel_reached"] is True


def test_false_positive_requires_explicit_status_and_passing_oracles():
    plan = _plan(status="false_positive_likely")

    result = run_validation_plan(
        plan,
        context=_context(plan, "path_resolve_enforced"),
    )

    assert result.outcome == "false_positive"
    assert result.tested is True
    assert _execution(result)["baseline_passed"] is True


def test_path_unavailable_entrypoint_is_inconclusive():
    plan = _plan()

    result = run_validation_plan(
        plan,
        context=_context(plan, "path_entrypoint_unavailable"),
    )

    assert result.outcome == "inconclusive"
    assert "entrypoint_unavailable" in _execution(result)["limitations"]
    assert _execution(result)["baseline_passed"] is None


def test_evaluated_path_baseline_failure_remains_false():
    plan = _plan()

    def missing_baseline(allowed_root: Path, _value: str) -> Path:
        return allowed_root / "missing.txt"

    context = ValidationExecutionContext.for_plan(
        plan,
        fixture_id="evaluated_missing_baseline",
        adapter="evaluated_missing_baseline",
        source_revision="missing-baseline-fixture-v1",
        adapter_registry={
            "evaluated_missing_baseline": missing_baseline,
        },
    )

    result = run_validation_plan(plan, context=context)

    assert result.outcome == "inconclusive"
    assert _execution(result)["baseline_passed"] is False
    assert _execution(result)["oracle_evaluated_count"] > 0


def test_idor_owner_can_read_and_update_own_resource():
    plan = _plan("idor_bola_possible")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_owner_tenant_enforced"),
    )
    baselines = [
        item for item in _observations(result) if item["baseline"]
    ]

    assert result.outcome == "enforced"
    assert {item["scenario"] for item in baselines} == {
        "read_owned_resource",
        "update_owned_resource",
    }
    assert all(item["oracle_passed"] is True for item in baselines)


def test_idor_foreign_resource_is_denied_and_unchanged():
    plan = _plan("idor_bola_possible")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_owner_tenant_enforced"),
    )
    foreign = [
        item
        for item in _observations(result)
        if "foreign_resource" in item["scenario"]
    ]

    assert foreign
    assert all(item["oracle_passed"] is True for item in foreign)
    state = [
        item
        for item in foreign
        if item["oracle"] == "state_invariant"
    ]
    assert state
    assert all(
        item["actual"]["state_before"]
        == item["actual"]["state_after"]
        for item in state
    )


def test_idor_authentication_without_authorization_is_bypassed():
    plan = _plan("idor_bola_possible")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_authentication_only"),
    )

    assert result.outcome == "bypassed"
    assert any(
        item["scenario"] == "read_foreign_resource"
        and item["oracle_passed"] is False
        for item in _observations(result)
    )


def test_idor_owner_check_on_wrong_resource_is_bypassed():
    plan = _plan("idor_bola_possible", status="protected")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_wrong_resource_guard"),
    )

    assert result.outcome == "bypassed"
    assert _execution(result)["protected_regression"] is True


def test_idor_control_after_modification_detects_hidden_state_change():
    plan = _plan("idor_bola_possible", status="protected")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_guard_after_operation"),
    )
    observation = next(
        item
        for item in _observations(result)
        if item["scenario"] == "update_foreign_resource_state"
    )

    assert result.outcome == "bypassed"
    assert observation["actual"]["response_status"] == 403
    assert observation["actual"]["state_changed"] is True
    assert observation["oracle_passed"] is False


def test_idor_tenant_only_does_not_replace_owner_authorization():
    plan = _plan("idor_bola_possible")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_tenant_only"),
    )

    assert result.outcome == "bypassed"
    assert any(
        item["scenario"] == "read_foreign_resource"
        and item["oracle_passed"] is False
        for item in _observations(result)
    )


def test_idor_owner_only_does_not_replace_tenant_authorization():
    plan = _plan("idor_bola_possible")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_owner_without_tenant"),
    )

    assert result.outcome == "bypassed"
    assert any(
        item["scenario"] == "read_wrong_tenant_resource"
        and item["oracle_passed"] is False
        for item in _observations(result)
    )


def test_idor_unavailable_entrypoint_preserves_limitations():
    plan = _plan("idor_bola_possible")

    result = run_validation_plan(
        plan,
        context=_context(plan, "idor_entrypoint_unavailable"),
    )

    assert result.outcome == "inconclusive"
    assert "entrypoint_unavailable" in _execution(result)["limitations"]
    assert _execution(result)["baseline_passed"] is None
    assert _execution(result)["oracle_evaluated_count"] == 0


def test_result_bundle_metrics_cover_required_counts():
    vulnerable = _plan(case_id="path_vulnerable")
    protected = _plan(
        "idor_bola_possible",
        status="protected",
        case_id="idor_protected",
    )
    unsupported = _plan(
        "ssrf_possible",
        case_id="ssrf_unsupported",
    )
    contexts = {
        vulnerable.plan_id: _context(
            vulnerable,
            "path_join_unchecked",
        ),
        protected.plan_id: _context(
            protected,
            "idor_owner_tenant_enforced",
        ),
        unsupported.plan_id: _context(
            unsupported,
            "explicitly_unsupported",
        ),
    }

    payload = run_validation_plan_bundle(
        [vulnerable, protected, unsupported],
        contexts=contexts,
    )
    metrics = payload["metrics"]
    oracle_evaluated_count = sum(
        result["metadata"]["execution"]["oracle_evaluated_count"]
        for result in payload["results"]
    )

    assert metrics == {
        "schema_version": "belief.validation_metrics.v2",
        "plan_count": 3,
        "supported_plan_count": 2,
        "executed_plan_count": 2,
        "enforced_count": 1,
        "bypassed_count": 1,
        "inconclusive_count": 1,
        "false_positive_count": 0,
        "baseline_pass_count": 2,
        "baseline_failure_count": 0,
        "baseline_not_evaluated_count": 0,
            "oracle_evaluated_count": oracle_evaluated_count,
            "plans_with_evaluated_oracle_count": 2,
            "primary_oracle_evaluated_count": sum(
                result["metadata"][
                    "primary_oracle_evaluated_count"
                ]
                for result in payload["results"]
            ),
            "conclusive_plan_count": 2,
            "evidence_gap_resolution_rate": 1.0,
        "protected_regression_count": 0,
        "deterministic_cost_units": metrics[
            "deterministic_cost_units"
        ],
        "secpass_equivalent": False,
    }
    assert metrics["deterministic_cost_units"] > 0
    assert metrics["oracle_evaluated_count"] > (
        metrics["plans_with_evaluated_oracle_count"]
    )
    assert payload["boundaries"]["execution_mode"] == "built_in_only"
    assert payload["boundaries"]["io_usage_attested"] is True
    assert payload["boundaries"]["network_used"] is False
    assert payload["boundaries"]["docker_used"] is False


def test_plan_bundle_requires_exact_fixture_coverage():
    plan = _plan()
    extra_plan = _plan(case_id="extra_case")
    contexts = {
        plan.plan_id: _context(plan, "path_resolve_enforced"),
        extra_plan.plan_id: _context(
            extra_plan,
            "path_resolve_enforced",
        ),
    }

    with pytest.raises(
        ValidationContractError,
        match="fixture bindings do not match",
    ):
        run_validation_plan_bundle([plan], contexts=contexts)


def test_result_payload_does_not_depend_on_mutated_context_source():
    plan = _plan()
    config = {"label": "controlled"}
    context = ValidationExecutionContext.for_plan(
        plan,
        fixture_id="immutable_fixture",
        adapter="path_resolve_enforced",
        source_revision="fixture-revision",
        config=config,
    )
    config["label"] = "mutated"

    result = run_validation_plan(plan, context=context)

    assert context.config == {"label": "controlled"}
    assert json.loads(json.dumps(result.to_dict())) == result.to_dict()


def test_result_writer_rejects_resigned_unsafe_boundaries(tmp_path):
    plan = _plan()
    payload = run_validation_plan_bundle(
        [plan],
        contexts={
            plan.plan_id: _context(
                plan,
                "path_resolve_enforced",
            )
        },
    )
    payload["boundaries"]["network_used"] = True
    unsigned = dict(payload)
    unsigned.pop("deterministic_digest")
    payload["deterministic_digest"] = canonical_digest(unsigned)

    with pytest.raises(
        ValidationContractError,
        match="boundaries are invalid",
    ):
        write_validation_result_bundle(
            tmp_path / "results.json",
            payload,
        )


def test_path_executor_never_reads_outside_its_temporary_root(
    monkeypatch,
):
    plan = _plan()
    original = Path.read_text
    observed: list[Path] = []

    def guarded_read(path: Path, *args, **kwargs):
        resolved = path.resolve()
        if not any(
            part.startswith("belief-local-path-validation-")
            for part in resolved.parts
        ):
            raise AssertionError(
                f"unexpected path read outside fixture: {resolved.name}"
            )
        observed.append(resolved)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read)

    result = run_validation_plan(
        plan,
        context=_context(plan, "path_join_unchecked"),
    )

    assert result.outcome == "bypassed"
    assert observed


def test_result_is_independent_of_mutated_plan_payload_copy():
    plan = _plan()
    payload = plan.to_dict()
    before = copy.deepcopy(payload)

    run_validation_plan(
        payload,
        context=_context(plan, "path_resolve_enforced"),
    )

    assert payload == before


def test_documented_chain_example_preserves_all_contract_links():
    example = json.loads(
        (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "examples"
            / "local_validation_chain.json"
        ).read_text(encoding="utf-8")
    )
    plan = ValidationPlan.from_dict(example["validation_plan"])
    context = ValidationExecutionContext.from_dict(example["fixture"])
    result = ValidationResult.from_dict(example["validation_result"])

    assert context.validation_plan_id == plan.plan_id
    assert context.expected_plan_digest == canonical_digest(
        example["validation_plan"]
    )
    assert result.subject_id == plan.subject_id
    assert result.metadata["validation_plan_id"] == plan.plan_id
    assert result.metadata["validation_plan_digest"] == (
        context.expected_plan_digest
    )
