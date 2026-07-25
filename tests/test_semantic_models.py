"""Contracts for composable semantic value objects."""

from __future__ import annotations

import pytest

from belief.semantic.models import (
    FUNCTION_SUMMARY_SCHEMA_VERSION,
    AnalysisGap,
    FlowState,
    FunctionEffect,
    FunctionSummary,
    GuardEffect,
    ResourceIdentity,
    RootCauseIdentity,
    SecurityTransition,
    SummaryKind,
)


pytestmark = pytest.mark.security


def test_resource_and_root_cause_identity_are_location_independent():
    resource = ResourceIdentity(
        kind="parameter",
        symbol="target",
        path=("host",),
        context="redirect",
    )
    first = RootCauseIdentity(
        category="unsafe_redirect",
        source_kind="request_parameter",
        sink_kind="redirect",
        resource=resource,
        security_property="same_origin",
    )
    second = RootCauseIdentity(
        category="unsafe_redirect",
        source_kind="request_parameter",
        sink_kind="redirect",
        resource=resource,
        security_property="same_origin",
    )

    assert resource.canonical == "parameter:target.host@redirect"
    assert first.digest == second.digest
    assert "line" not in first.to_dict()


def test_root_cause_identity_survives_helper_and_parameter_rename():
    before_resource = ResourceIdentity(
        kind="parameter",
        symbol="target",
        context="input:0",
    )
    after_resource = ResourceIdentity(
        kind="parameter",
        symbol="destination",
        context="input:0",
    )
    other_resource = ResourceIdentity(
        kind="parameter",
        symbol="destination",
        context="input:1",
    )

    before = RootCauseIdentity(
        category="unsafe_redirect",
        source_kind="request_parameter",
        sink_kind="redirect",
        resource=before_resource,
        security_property="same_origin",
        context="handler",
    )
    moved = RootCauseIdentity(
        category="unsafe_redirect",
        source_kind="request_parameter",
        sink_kind="redirect",
        resource=after_resource,
        security_property="same_origin",
        context="redirect_helper",
    )
    wrong_resource = RootCauseIdentity(
        category="unsafe_redirect",
        source_kind="request_parameter",
        sink_kind="redirect",
        resource=other_resource,
        security_property="same_origin",
        context="redirect_helper",
    )

    assert before_resource.semantic_key == after_resource.semantic_key
    assert before.digest == moved.digest
    assert before.digest != wrong_resource.digest


def test_security_transition_requires_the_same_resource_and_property():
    value = ResourceIdentity(kind="parameter", symbol="value")
    other = ResourceIdentity(kind="parameter", symbol="other")
    unsafe = FlowState(
        property="bounded",
        value="unknown",
        resource=value,
    )
    safe = FlowState(
        property="bounded",
        value="bounded",
        resource=value,
    )

    transition = SecurityTransition(
        transition_id="bound-before-sink",
        kind="abortive_bound",
        resource=value,
        before=unsafe,
        after=safe,
        line=4,
        control_path=("if len(value) > limit", "raise"),
    )

    assert transition.to_dict()["after"]["value"] == "bounded"
    with pytest.raises(ValueError, match="after-state resource mismatch"):
        SecurityTransition(
            transition_id="wrong-resource",
            kind="abortive_bound",
            resource=value,
            before=unsafe,
            after=FlowState(
                property="bounded",
                value="bounded",
                resource=other,
            ),
        )


def test_guard_effect_preserves_branch_and_result_use():
    resource = ResourceIdentity(kind="parameter", symbol="url")
    effect = GuardEffect(
        guard_id="same-origin",
        effect="authorize",
        resource=resource,
        state_property="origin",
        state_value="same_origin",
        branch="true",
        abortive=False,
        dominates_sink=True,
        result_used=True,
        line=8,
    )

    payload = effect.to_dict()

    assert payload["dominates_sink"] is True
    assert payload["result_used"] is True


def test_function_summary_is_versioned_sorted_and_deterministic():
    resource = ResourceIdentity(kind="parameter", symbol="value")
    effects = tuple(
        sorted(
            {
                FunctionEffect(
                    kind=SummaryKind.RETURN_FROM_PARAMETER,
                    value="value",
                    parameter_index=0,
                    resource=resource,
                    line=2,
                ),
                FunctionEffect(
                    kind=SummaryKind.IDENTITY,
                    value="value",
                    parameter_index=0,
                    resource=resource,
                    line=2,
                    result_used=False,
                ),
            },
            key=lambda effect: effect.sort_key,
        )
    )
    gap = AnalysisGap(
        code="example_gap",
        stage="summary",
        reason="bounded example",
        file="module.py",
        function="identity",
        line=2,
        limit_name="max_call_depth",
        limit_value=4,
        observed_value=5,
    )
    first = FunctionSummary(
        file="module.py",
        qualified_name="identity",
        parameters=("value",),
        effects=effects,
        gaps=(gap,),
        complete=False,
    )
    second = FunctionSummary(
        file="module.py",
        qualified_name="identity",
        parameters=("value",),
        effects=effects,
        gaps=(gap,),
        complete=False,
    )

    assert first.schema_version == FUNCTION_SUMMARY_SCHEMA_VERSION
    assert first.deterministic_digest == second.deterministic_digest
    assert first.to_dict()["gaps"][0]["line"] == 2
    assert first.to_dict()["effects"][0]["result_used"] is False


def test_function_summary_rejects_unsorted_effects():
    high = FunctionEffect(kind=SummaryKind.UNKNOWN, value="unknown")
    low = FunctionEffect(kind=SummaryKind.CONSTANT, value="1")

    with pytest.raises(ValueError, match="deterministically sorted"):
        FunctionSummary(
            file="module.py",
            qualified_name="function",
            parameters=(),
            effects=(high, low),
        )
