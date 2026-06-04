"""Tiny Belief -> BooleanConstraint adapter for BELIEF v4.

Only unambiguous boolean atom shapes are supported. Ambiguous expressions
return None so the deeper verifier can decide what to do.
"""

from __future__ import annotations

import re
from typing import Iterable

from .logic_ir import (
    BooleanAtom,
    BooleanConstraint,
    LogicConflictProof,
    check_boolean_constraints,
    stable_atom_key,
)
from .models import Belief, Conflict, ConflictSeverity

_ATOM_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
_EQ_BOOL_PATTERN = re.compile(
    rf"^\s*({_ATOM_PATTERN.pattern})\s*==\s*(true|false)\s*$",
    re.IGNORECASE,
)


def belief_to_boolean_constraint(belief: Belief) -> BooleanConstraint | None:
    """Convert one clearly-boolean belief into a BooleanConstraint."""
    expression = str(getattr(belief.predicate, "expression", "") or "").strip()
    parsed = _parse_boolean_expression(expression)
    if parsed is None:
        return None

    atom_name, expected = parsed
    return BooleanConstraint(
        atom=BooleanAtom(key=stable_atom_key(atom_name), source_id=belief.id),
        expected=expected,
        belief_id=belief.id,
        label=expression,
    )


def beliefs_to_boolean_constraints(beliefs: Iterable[Belief]) -> list[BooleanConstraint]:
    """Convert all supported beliefs; unsupported expressions are ignored."""
    constraints: list[BooleanConstraint] = []
    for belief in beliefs:
        constraint = belief_to_boolean_constraint(belief)
        if constraint is not None:
            constraints.append(constraint)
    return constraints


def check_belief_boolean_contradictions(
    beliefs: Iterable[Belief],
    *,
    timeout_ms: int = 5000,
) -> LogicConflictProof | None:
    """Check supported boolean beliefs and return a proof when any were usable."""
    constraints = beliefs_to_boolean_constraints(beliefs)
    if not constraints:
        return None
    result = check_boolean_constraints(constraints, timeout_ms=timeout_ms)
    return LogicConflictProof.from_result(result, constraints)


def belief_boolean_conflict(
    beliefs: Iterable[Belief],
    *,
    timeout_ms: int = 5000,
    severity: ConflictSeverity = ConflictSeverity.MEDIUM,
) -> Conflict | None:
    """Optionally convert a boolean UNSAT proof into the existing Conflict model."""
    belief_list = list(beliefs)
    proof = check_belief_boolean_contradictions(belief_list, timeout_ms=timeout_ms)
    if proof is None:
        return None
    return proof.to_conflict(
        {belief.id: belief for belief in belief_list},
        severity=severity,
    )


def _parse_boolean_expression(expression: str) -> tuple[str, bool] | None:
    if not expression:
        return None

    match = _EQ_BOOL_PATTERN.fullmatch(expression)
    if match:
        return _normalize_atom(match.group(1)), match.group(2).lower() == "true"

    lowered = expression.lower()
    if lowered.startswith("not "):
        atom = expression[4:].strip()
        if _is_supported_atom(atom):
            return _normalize_atom(atom), False
        return None

    if expression.startswith("!"):
        atom = expression[1:].strip()
        if _is_supported_atom(atom):
            return _normalize_atom(atom), False
        return None

    if _is_supported_atom(expression):
        return _normalize_atom(expression), True

    return None


def _is_supported_atom(value: str) -> bool:
    return bool(_ATOM_PATTERN.fullmatch(value.strip()))


def _normalize_atom(value: str) -> str:
    return value.strip().lower()


__all__ = [
    "belief_to_boolean_constraint",
    "beliefs_to_boolean_constraints",
    "check_belief_boolean_contradictions",
    "belief_boolean_conflict",
]
