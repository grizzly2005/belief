"""Minimal boolean Logic IR and Z3 backend for BELIEF v4.

This module is deliberately small: it proves the path
Belief -> Logic IR -> Z3 -> UNSAT core without adding Z3 expressions to the
Belief model and without replacing z3_verifier.py.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from .models import Belief, Conflict, ConflictSeverity

try:
    import z3  # type: ignore
    Z3_AVAILABLE = True
except ImportError:
    z3 = None  # type: ignore
    Z3_AVAILABLE = False


@dataclass(frozen=True, order=True)
class BooleanAtom:
    """A stable boolean atom detached from any Z3 object."""

    key: str
    source_id: str = ""

    @classmethod
    def from_belief(
        cls,
        belief: Belief,
        *,
        predicate_key: str | None = None,
    ) -> "BooleanAtom":
        key = stable_atom_key(
            predicate_key
            or belief.canonical_key
            or belief.predicate.expression
            or belief.id
        )
        return cls(key=key, source_id=belief.id)

    def to_dict(self) -> dict[str, str]:
        return {
            "key": self.key,
            "source_id": self.source_id,
        }


@dataclass(frozen=True)
class BooleanConstraint:
    """A belief-backed assertion that an atom is true or false."""

    atom: BooleanAtom
    expected: bool
    belief_id: str
    label: str = ""

    @classmethod
    def atom_is_true(
        cls,
        atom: BooleanAtom,
        *,
        belief_id: str | None = None,
        label: str = "",
    ) -> "BooleanConstraint":
        return cls(
            atom=atom,
            expected=True,
            belief_id=belief_id or atom.source_id or atom.key,
            label=label,
        )

    @classmethod
    def atom_is_false(
        cls,
        atom: BooleanAtom,
        *,
        belief_id: str | None = None,
        label: str = "",
    ) -> "BooleanConstraint":
        return cls(
            atom=atom,
            expected=False,
            belief_id=belief_id or atom.source_id or atom.key,
            label=label,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "atom": self.atom.to_dict(),
            "expected": self.expected,
            "belief_id": self.belief_id,
            "label": self.label,
        }


@dataclass(frozen=True)
class LogicCheckResult:
    """Result of checking boolean constraints."""

    status: str
    unsat_core: tuple[str, ...] = ()
    model: dict[str, str] = field(default_factory=dict)
    reason: str = ""
    backend: str = "z3_logic_ir"

    @property
    def is_unsat(self) -> bool:
        return self.status == "unsat"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "unsat_core": list(self.unsat_core),
            "model": dict(sorted(self.model.items())),
            "reason": self.reason,
            "backend": self.backend,
        }


@dataclass(frozen=True)
class LogicConflictProof:
    """Serializable proof object for a boolean-IR conflict."""

    status: str
    unsat_core: tuple[str, ...]
    constraints: tuple[dict[str, Any], ...]
    backend: str = "z3_logic_ir"
    reason: str = ""

    @classmethod
    def from_result(
        cls,
        result: LogicCheckResult,
        constraints: Iterable[BooleanConstraint],
    ) -> "LogicConflictProof":
        return cls(
            status=result.status,
            unsat_core=tuple(result.unsat_core),
            constraints=tuple(c.to_dict() for c in normalize_constraints(constraints)),
            backend=result.backend,
            reason=result.reason,
        )

    @property
    def is_conflict(self) -> bool:
        return self.status == "unsat" and len(self.unsat_core) >= 2

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "unsat_core": list(self.unsat_core),
            "constraints": list(self.constraints),
            "backend": self.backend,
            "reason": self.reason,
        }

    def to_conflict(
        self,
        beliefs_by_id: Mapping[str, Belief],
        *,
        severity: ConflictSeverity = ConflictSeverity.MEDIUM,
    ) -> Conflict | None:
        """Convert a two-belief UNSAT proof to the existing Conflict model."""
        if not self.is_conflict:
            return None

        involved = [belief_id for belief_id in self.unsat_core if belief_id in beliefs_by_id]
        if len(involved) < 2:
            return None

        belief_a = beliefs_by_id[involved[0]]
        belief_b = beliefs_by_id[involved[1]]
        return Conflict(
            belief_a=belief_a,
            belief_b=belief_b,
            severity=severity,
            description=(
                "Boolean Logic IR contradiction confirmed by Z3. "
                f"UNSAT core: {', '.join(self.unsat_core)}."
            ),
            verified_by=self.backend,
        )


def stable_atom_key(value: str) -> str:
    """Create a deterministic boolean atom key from a belief/predicate key."""
    text = str(value or "").strip()
    if not text:
        text = "anonymous"
    normalized = re.sub(r"\s+", " ", text).lower()
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:16]
    return f"atom:{digest}"


def boolean_constraint_from_belief(
    belief: Belief,
    *,
    expected: bool,
    predicate_key: str | None = None,
    label: str = "",
) -> BooleanConstraint:
    atom = BooleanAtom.from_belief(belief, predicate_key=predicate_key)
    if expected:
        return BooleanConstraint.atom_is_true(atom, belief_id=belief.id, label=label)
    return BooleanConstraint.atom_is_false(atom, belief_id=belief.id, label=label)


def normalize_constraints(
    constraints: Iterable[BooleanConstraint],
) -> tuple[BooleanConstraint, ...]:
    return tuple(sorted(
        constraints,
        key=lambda c: (c.belief_id, c.atom.key, c.expected, c.label),
    ))


def check_boolean_constraints(
    constraints: Iterable[BooleanConstraint],
    *,
    timeout_ms: int = 5000,
) -> LogicCheckResult:
    """Check boolean constraints with Z3 and return SAT/UNSAT/UNKNOWN."""
    normalized = normalize_constraints(constraints)
    if not Z3_AVAILABLE:
        return LogicCheckResult(
            status="unavailable",
            reason="z3-solver not installed",
        )

    solver = z3.Solver()
    solver.set("timeout", int(timeout_ms))

    atom_symbols: dict[str, str] = {}
    track_to_belief: dict[str, str] = {}
    for constraint in normalized:
        atom_symbol = _z3_symbol("atom", constraint.atom.key)
        track_symbol = _z3_symbol(
            "track",
            json.dumps(constraint.to_dict(), sort_keys=True, separators=(",", ":")),
        )
        atom_symbols[constraint.atom.key] = atom_symbol
        track_to_belief[track_symbol] = constraint.belief_id
        z3_atom = z3.Bool(atom_symbol)
        z3_constraint = z3_atom if constraint.expected else z3.Not(z3_atom)
        solver.assert_and_track(z3_constraint, z3.Bool(track_symbol))

    try:
        outcome = solver.check()
    except Exception as exc:
        return LogicCheckResult(status="error", reason=str(exc))

    if outcome == z3.unsat:
        core_symbols = {str(item) for item in solver.unsat_core()}
        core = tuple(
            constraint.belief_id
            for constraint in normalized
            if _z3_symbol(
                "track",
                json.dumps(constraint.to_dict(), sort_keys=True, separators=(",", ":")),
            ) in core_symbols
        )
        return LogicCheckResult(status="unsat", unsat_core=core)

    if outcome == z3.sat:
        model = solver.model()
        model_values = {
            atom_key: str(model.eval(z3.Bool(symbol), model_completion=True))
            for atom_key, symbol in sorted(atom_symbols.items())
        }
        return LogicCheckResult(status="sat", model=model_values)

    reason = ""
    try:
        reason = solver.reason_unknown()
    except Exception:
        reason = "unknown"
    return LogicCheckResult(status="unknown", reason=reason)


def prove_boolean_constraints(
    constraints: Iterable[BooleanConstraint],
    *,
    timeout_ms: int = 5000,
) -> LogicConflictProof:
    normalized = normalize_constraints(constraints)
    result = check_boolean_constraints(normalized, timeout_ms=timeout_ms)
    return LogicConflictProof.from_result(result, normalized)


def _z3_symbol(prefix: str, value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"{prefix}_{digest}"


__all__ = [
    "Z3_AVAILABLE",
    "BooleanAtom",
    "BooleanConstraint",
    "LogicCheckResult",
    "LogicConflictProof",
    "stable_atom_key",
    "boolean_constraint_from_belief",
    "normalize_constraints",
    "check_boolean_constraints",
    "prove_boolean_constraints",
]
