"""Minimal boolean Logic IR -> Z3 UNSAT-core coverage."""

from __future__ import annotations

import pytest

from belief.logic_ir import (
    BooleanAtom,
    BooleanConstraint,
    LogicCheckResult,
    LogicConflictProof,
    boolean_constraint_from_belief,
    check_boolean_constraints,
    prove_boolean_constraints,
    stable_atom_key,
)
from belief.models import Belief, Finding, JustificationCategory, Predicate, Scope


def _require_z3():
    pytest.importorskip("z3", reason="z3-solver not installed")


def _belief(belief_id: str, expression: str = "feature.enabled") -> Belief:
    return Belief(
        id=belief_id,
        predicate=Predicate(expression=expression),
        scope=Scope(file_path="logic.py", function_name="f"),
        justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
    )


def test_no_z3_expr_added_to_belief_model():
    assert "z3_expr" not in Belief.__dataclass_fields__


def test_atom_key_is_stable():
    assert stable_atom_key("Feature.Enabled") == stable_atom_key(" feature.enabled ")
    assert stable_atom_key("Feature.Enabled").startswith("atom:")


def test_result_and_proof_are_serializable_without_finding_conversion():
    atom = BooleanAtom(key=stable_atom_key("feature.enabled"), source_id="b1")
    constraints = (
        BooleanConstraint.atom_is_true(atom, belief_id="b1"),
        BooleanConstraint.atom_is_false(atom, belief_id="b2"),
    )
    result = LogicCheckResult(status="unknown", reason="simulated")
    proof = LogicConflictProof.from_result(result, constraints)

    assert result.to_dict() == {
        "status": "unknown",
        "unsat_core": [],
        "model": {},
        "reason": "simulated",
        "backend": "z3_logic_ir",
    }
    assert proof.to_dict()["status"] == "unknown"
    assert not hasattr(proof, "to_finding")
    assert isinstance(Finding(rule_id="CONTROL"), Finding)


def test_compatible_constraints_are_sat():
    _require_z3()
    atom = BooleanAtom(key=stable_atom_key("feature.enabled"), source_id="b1")
    constraints = (
        BooleanConstraint.atom_is_true(atom, belief_id="b1"),
        BooleanConstraint.atom_is_true(atom, belief_id="b2"),
    )

    result = check_boolean_constraints(constraints)

    assert result.status == "sat"
    assert result.unsat_core == ()
    assert result.model == {atom.key: "True"}


def test_true_and_false_same_atom_are_unsat_with_core():
    _require_z3()
    atom = BooleanAtom(key=stable_atom_key("feature.enabled"), source_id="b1")
    constraints = (
        BooleanConstraint.atom_is_true(atom, belief_id="b_true"),
        BooleanConstraint.atom_is_false(atom, belief_id="b_false"),
    )

    result = check_boolean_constraints(constraints)

    assert result.status == "unsat"
    assert result.unsat_core == ("b_false", "b_true")


def test_unsat_core_order_is_deterministic():
    _require_z3()
    atom = BooleanAtom(key=stable_atom_key("feature.enabled"), source_id="b1")
    first = (
        BooleanConstraint.atom_is_false(atom, belief_id="b_false"),
        BooleanConstraint.atom_is_true(atom, belief_id="b_true"),
    )
    second = tuple(reversed(first))

    assert check_boolean_constraints(first).unsat_core == check_boolean_constraints(second).unsat_core


def test_boolean_constraints_can_be_built_from_beliefs():
    _require_z3()
    b_true = _belief("belief_true")
    b_false = _belief("belief_false")
    constraints = (
        boolean_constraint_from_belief(b_true, expected=True, predicate_key="feature.enabled"),
        boolean_constraint_from_belief(b_false, expected=False, predicate_key="feature.enabled"),
    )

    result = check_boolean_constraints(constraints)

    assert result.status == "unsat"
    assert result.unsat_core == ("belief_false", "belief_true")


def test_unsat_proof_converts_to_existing_conflict_model():
    _require_z3()
    b_true = _belief("belief_true")
    b_false = _belief("belief_false")
    constraints = (
        boolean_constraint_from_belief(b_true, expected=True, predicate_key="feature.enabled"),
        boolean_constraint_from_belief(b_false, expected=False, predicate_key="feature.enabled"),
    )

    proof = prove_boolean_constraints(constraints)
    conflict = proof.to_conflict({b_true.id: b_true, b_false.id: b_false})

    assert proof.is_conflict
    assert proof.to_dict()["unsat_core"] == ["belief_false", "belief_true"]
    assert conflict is not None
    assert conflict.verified_by == "z3_logic_ir"
    assert "UNSAT core: belief_false, belief_true" in conflict.description
    assert conflict.to_dict()["verified_by"] == "z3_logic_ir"
