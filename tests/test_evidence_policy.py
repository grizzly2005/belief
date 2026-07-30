"""Truth table for the single local-evidence conclusion policy."""

from __future__ import annotations

import pytest

from belief.validation.evidence_policy import (
    FUNCTIONAL_BASELINE,
    OPTIONAL,
    PRIMARY_SECURITY,
    SECONDARY_SECURITY,
    EvidencePolicyError,
    evaluate_evidence,
)


pytestmark = pytest.mark.security


def _observation(
    role: str,
    *,
    evaluated: bool = True,
    passed: bool | None = True,
    required: bool = True,
    scenario: str | None = None,
):
    return {
        "oracle_role": role,
        "required_for_conclusion": required,
        "oracle_evaluated": evaluated,
        "oracle_passed": passed,
        "baseline": role == FUNCTIONAL_BASELINE,
        "oracle": role,
        "scenario": scenario or role,
    }


BASELINE_PASS = _observation(FUNCTIONAL_BASELINE)
PRIMARY_PASS = _observation(PRIMARY_SECURITY)


@pytest.mark.parametrize(
    (
        "observations",
        "completed",
        "safe_outcome",
        "outcome",
        "baseline",
    ),
    (
        ((BASELINE_PASS, PRIMARY_PASS), True, "enforced", "enforced", True),
        (
            (BASELINE_PASS, PRIMARY_PASS),
            True,
            "false_positive",
            "false_positive",
            True,
        ),
        (
            (
                BASELINE_PASS,
                _observation(PRIMARY_SECURITY, passed=False),
            ),
            True,
            "enforced",
            "bypassed",
            True,
        ),
        (
            (BASELINE_PASS, PRIMARY_PASS),
            False,
            "enforced",
            "inconclusive",
            True,
        ),
        ((PRIMARY_PASS,), True, "enforced", "inconclusive", None),
        (
            (
                _observation(FUNCTIONAL_BASELINE, passed=False),
                PRIMARY_PASS,
            ),
            True,
            "enforced",
            "inconclusive",
            False,
        ),
        (
            (
                _observation(
                    FUNCTIONAL_BASELINE,
                    evaluated=False,
                    passed=None,
                ),
                PRIMARY_PASS,
            ),
            True,
            "enforced",
            "inconclusive",
            None,
        ),
        (
            (
                BASELINE_PASS,
                _observation(SECONDARY_SECURITY),
            ),
            True,
            "enforced",
            "inconclusive",
            True,
        ),
        (
            (
                BASELINE_PASS,
                _observation(
                    PRIMARY_SECURITY,
                    evaluated=False,
                    passed=None,
                ),
            ),
            True,
            "enforced",
            "inconclusive",
            True,
        ),
        (
            (
                BASELINE_PASS,
                PRIMARY_PASS,
                _observation(
                    SECONDARY_SECURITY,
                    evaluated=False,
                    passed=None,
                ),
            ),
            True,
            "enforced",
            "inconclusive",
            True,
        ),
        (
            (
                BASELINE_PASS,
                PRIMARY_PASS,
                _observation(
                    OPTIONAL,
                    evaluated=False,
                    passed=None,
                    required=False,
                ),
            ),
            True,
            "enforced",
            "enforced",
            True,
        ),
        (
            (
                BASELINE_PASS,
                PRIMARY_PASS,
                _observation(
                    OPTIONAL,
                    passed=False,
                    required=False,
                ),
            ),
            True,
            "enforced",
            "bypassed",
            True,
        ),
        (
            (
                BASELINE_PASS,
                PRIMARY_PASS,
                _observation(SECONDARY_SECURITY, passed=False),
            ),
            True,
            "enforced",
            "bypassed",
            True,
        ),
        (
            (
                BASELINE_PASS,
                _observation(PRIMARY_SECURITY, passed=False),
                _observation(
                    SECONDARY_SECURITY,
                    evaluated=False,
                    passed=None,
                ),
            ),
            True,
            "enforced",
            "bypassed",
            True,
        ),
    ),
)
def test_evidence_policy_truth_table(
    observations,
    completed,
    safe_outcome,
    outcome,
    baseline,
):
    decision = evaluate_evidence(
        observations,
        completed=completed,
        safe_outcome=safe_outcome,
    )

    assert decision.outcome == outcome
    assert decision.baseline_passed is baseline
    assert decision.conclusive is (outcome != "inconclusive")


def test_optional_absence_is_a_limitation_not_an_abstention():
    decision = evaluate_evidence(
        (
            BASELINE_PASS,
            PRIMARY_PASS,
            _observation(
                OPTIONAL,
                evaluated=False,
                passed=None,
                required=False,
                scenario="symlink_boundary",
            ),
        ),
        completed=True,
    )

    assert decision.outcome == "enforced"
    assert decision.optional_unevaluated_oracles == (
        "optional:symlink_boundary",
    )
    assert decision.limitations == (
        "optional_oracle_unevaluated:optional:symlink_boundary",
    )


@pytest.mark.parametrize(
    "observation",
    (
        {
            **PRIMARY_PASS,
            "oracle_role": "unknown",
        },
        {
            **PRIMARY_PASS,
            "baseline": True,
        },
        {
            **BASELINE_PASS,
            "required_for_conclusion": False,
        },
        {
            **PRIMARY_PASS,
            "oracle_evaluated": False,
            "oracle_passed": True,
        },
    ),
)
def test_policy_rejects_contradictory_observations(observation):
    with pytest.raises(EvidencePolicyError):
        evaluate_evidence((observation,), completed=True)
