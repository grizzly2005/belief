"""Belief -> BooleanConstraint adapter coverage."""

from __future__ import annotations

import pytest

from belief.belief_logic_adapter import (
    belief_boolean_conflict,
    belief_to_boolean_constraint,
    beliefs_to_boolean_constraints,
    check_belief_boolean_contradictions,
)
from belief.logic_ir import Z3_AVAILABLE
from belief.models import Belief, Finding, JustificationCategory, Predicate, Scope


def _require_z3():
    pytest.importorskip("z3", reason="z3-solver not installed")


def _belief(belief_id: str, expression: str) -> Belief:
    return Belief(
        id=belief_id,
        predicate=Predicate(expression=expression),
        scope=Scope(file_path="logic.py", function_name="f"),
        justification=JustificationCategory.C5_NO_JUSTIFICATION,
    )


def test_positive_expression_becomes_true_constraint():
    constraint = belief_to_boolean_constraint(_belief("b_positive", "feature.enabled"))

    assert constraint is not None
    assert constraint.expected is True
    assert constraint.belief_id == "b_positive"
    assert constraint.label == "feature.enabled"


def test_not_expression_becomes_false_constraint():
    constraint = belief_to_boolean_constraint(_belief("b_not", "not feature.enabled"))

    assert constraint is not None
    assert constraint.expected is False
    assert constraint.belief_id == "b_not"


def test_bang_expression_becomes_false_constraint():
    constraint = belief_to_boolean_constraint(_belief("b_bang", "!feature.enabled"))

    assert constraint is not None
    assert constraint.expected is False


def test_equals_true_expression_becomes_true_constraint():
    constraint = belief_to_boolean_constraint(_belief("b_true", "feature.enabled == true"))

    assert constraint is not None
    assert constraint.expected is True


def test_equals_false_expression_becomes_false_constraint():
    constraint = belief_to_boolean_constraint(_belief("b_false", "feature.enabled == false"))

    assert constraint is not None
    assert constraint.expected is False


def test_ambiguous_expression_returns_none():
    assert belief_to_boolean_constraint(_belief("b_ambiguous", "feature.enabled != maybe")) is None
    assert belief_to_boolean_constraint(_belief("b_call", "feature.enabled()")) is None
    assert belief_to_boolean_constraint(_belief("b_compound", "feature.enabled and auth.ok")) is None


def test_positive_and_negative_share_same_atom_key():
    positive = belief_to_boolean_constraint(_belief("b_positive", "feature.enabled"))
    negative = belief_to_boolean_constraint(_belief("b_negative", "not feature.enabled"))

    assert positive is not None
    assert negative is not None
    assert positive.atom.key == negative.atom.key
    assert positive.belief_id != negative.belief_id


def test_bulk_conversion_ignores_ambiguous_beliefs():
    constraints = beliefs_to_boolean_constraints([
        _belief("b_positive", "auth.token_verified"),
        _belief("b_ambiguous", "auth.token_verified != maybe"),
        _belief("b_false", "user.is_admin == false"),
    ])

    assert [constraint.belief_id for constraint in constraints] == ["b_positive", "b_false"]


def test_two_boolean_beliefs_contradict_with_unsat_core():
    _require_z3()
    assert Z3_AVAILABLE is True
    beliefs = [
        _belief("belief_true", "feature.enabled"),
        _belief("belief_false", "feature.enabled == false"),
    ]

    proof = check_belief_boolean_contradictions(beliefs)

    assert proof is not None
    assert proof.status == "unsat"
    assert proof.unsat_core == ("belief_false", "belief_true")
    assert proof.to_dict()["unsat_core"] == ["belief_false", "belief_true"]


def test_compatible_boolean_beliefs_are_sat():
    _require_z3()
    beliefs = [
        _belief("belief_true_a", "feature.enabled"),
        _belief("belief_true_b", "feature.enabled == true"),
    ]

    proof = check_belief_boolean_contradictions(beliefs)

    assert proof is not None
    assert proof.status == "sat"
    assert proof.unsat_core == ()


def test_optional_conflict_conversion_from_unsat_proof():
    _require_z3()
    beliefs = [
        _belief("belief_true", "feature.enabled"),
        _belief("belief_false", "not feature.enabled"),
    ]

    conflict = belief_boolean_conflict(beliefs)

    assert conflict is not None
    assert conflict.verified_by == "z3_logic_ir"
    assert "UNSAT core: belief_false, belief_true" in conflict.description


def test_no_automatic_finding_created():
    beliefs = [
        _belief("belief_true", "feature.enabled"),
        _belief("belief_false", "not feature.enabled"),
    ]

    proof = check_belief_boolean_contradictions(beliefs)

    assert not hasattr(proof, "to_finding")
    assert "z3_expr" not in Belief.__dataclass_fields__
    assert isinstance(Finding(rule_id="CONTROL"), Finding)
