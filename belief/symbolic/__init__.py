"""
BELIEF — Symbolic Executor.

Uses Z3 to symbolically verify belief predicates by encoding function
behavior as constraints. When the standard predicate translator fails,
the symbolic executor tries deeper analysis.

Inspired by Z3's bounded model checking examples and angr's constraint
solving approach, adapted to work on belief predicates.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

try:
    import z3
    _Z3_AVAILABLE = True
except ImportError:
    _Z3_AVAILABLE = False

from ..models import Belief, Conflict, ConflictSeverity

logger = logging.getLogger("belief.symbolic")


@dataclass
class SymbolicResult:
    """Result of symbolic verification."""
    verified: bool = False
    verdict: str = "unknown"        # sat, unsat, timeout, error
    counterexample: dict = field(default_factory=dict)
    constraints_encoded: int = 0
    solve_time_ms: float = 0.0
    explanation: str = ""


class SymbolicExecutor:
    """
    Symbolically execute belief predicates using Z3.

    Given two beliefs that may conflict, encodes both as Z3 constraints
    and checks satisfiability. If both can be satisfied simultaneously,
    no conflict. If not, it's a real conflict with a counterexample.
    """

    def __init__(self, timeout_ms: int = 5000):
        self.timeout_ms = timeout_ms

    def verify_belief_pair(self, belief_a: Belief, belief_b: Belief) -> SymbolicResult:
        """Check if two beliefs can coexist (both satisfiable)."""
        if not _Z3_AVAILABLE:
            return SymbolicResult(verdict="unavailable", explanation="Z3 not installed")

        import time
        start = time.time()

        try:
            solver = z3.Solver()
            solver.set("timeout", self.timeout_ms)

            # Encode both predicates
            ca = self._encode_predicate(belief_a.predicate.expression)
            cb = self._encode_predicate(belief_b.predicate.expression)

            if ca is None or cb is None:
                return SymbolicResult(
                    verdict="unencodable",
                    explanation="Could not encode one or both predicates",
                )

            # Check if both can be true simultaneously
            solver.add(ca)
            solver.add(cb)

            result = solver.check()
            elapsed = (time.time() - start) * 1000

            if result == z3.sat:
                model = solver.model()
                counterexample = {}
                for decl in model.decls():
                    counterexample[str(decl)] = str(model[decl])
                return SymbolicResult(
                    verified=True,
                    verdict="sat",
                    counterexample=counterexample,
                    constraints_encoded=2,
                    solve_time_ms=elapsed,
                    explanation="Both beliefs can coexist — no conflict",
                )
            elif result == z3.unsat:
                return SymbolicResult(
                    verified=True,
                    verdict="unsat",
                    constraints_encoded=2,
                    solve_time_ms=elapsed,
                    explanation="Beliefs are contradictory — confirmed conflict",
                )
            else:
                return SymbolicResult(
                    verdict="timeout",
                    solve_time_ms=elapsed,
                    explanation="Z3 solver timed out",
                )

        except Exception as e:
            return SymbolicResult(verdict="error", explanation=str(e))

    def verify_conflict(self, conflict: Conflict) -> SymbolicResult:
        """Verify a detected conflict using symbolic execution."""
        return self.verify_belief_pair(conflict.belief_a, conflict.belief_b)

    def find_conflicts_symbolic(self, beliefs: list[Belief]) -> list[Conflict]:
        """Find conflicts among beliefs using Z3."""
        if not _Z3_AVAILABLE:
            return []

        conflicts = []
        for i in range(len(beliefs)):
            for j in range(i + 1, len(beliefs)):
                ba, bb = beliefs[i], beliefs[j]

                # Only check beliefs with overlapping scope
                if not ba.scope.overlaps(bb.scope):
                    continue

                # Only check beliefs with shared variables
                shared_vars = set(ba.predicate.variables) & set(bb.predicate.variables)
                if not shared_vars and not self._expressions_share_variables(
                    ba.predicate.expression, bb.predicate.expression
                ):
                    continue

                result = self.verify_belief_pair(ba, bb)
                if result.verdict == "unsat":
                    severity = self._compute_severity(ba, bb)
                    conflicts.append(Conflict(
                        belief_a=ba,
                        belief_b=bb,
                        severity=severity,
                        description=(
                            f"Symbolic verification confirms contradiction: "
                            f"'{ba.predicate.expression}' ∧ '{bb.predicate.expression}' is unsat"
                        ),
                        verified_by="symbolic_z3",
                    ))

        return conflicts

    def encode_and_check(self, expression: str) -> SymbolicResult:
        """Encode a single expression and check satisfiability."""
        if not _Z3_AVAILABLE:
            return SymbolicResult(verdict="unavailable")

        constraint = self._encode_predicate(expression)
        if constraint is None:
            return SymbolicResult(verdict="unencodable")

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)
        solver.add(constraint)

        result = solver.check()
        if result == z3.sat:
            model = solver.model()
            ce = {str(d): str(model[d]) for d in model.decls()}
            return SymbolicResult(verified=True, verdict="sat", counterexample=ce,
                                  constraints_encoded=1)
        elif result == z3.unsat:
            return SymbolicResult(verified=True, verdict="unsat", constraints_encoded=1,
                                  explanation="Expression is unsatisfiable")
        return SymbolicResult(verdict="timeout")

    # ── Predicate Encoding ──

    _VARS: dict[str, z3.ArithRef] = {}  # shared variable cache

    def _get_var(self, name: str):
        if name not in self._VARS:
            self._VARS[name] = z3.Int(name)
        return self._VARS[name]

    def _encode_predicate(self, expr: str):
        """Convert a predicate expression string to a Z3 constraint."""
        if not expr:
            return None

        expr = expr.strip()

        # Conjunction: x > 0 and y < 10
        m = re.match(
            r'(\w+)\s*(>=|<=|>|<|==|!=)\s*([-+]?\d+(?:\.\d+)?)\s+and\s+'
            r'(\w+)\s*(>=|<=|>|<|==|!=)\s*([-+]?\d+(?:\.\d+)?)',
            expr
        )
        if m:
            v1, op1, val1 = m.group(1), m.group(2), float(m.group(3))
            v2, op2, val2 = m.group(4), m.group(5), float(m.group(6))
            c1 = self._make_comparison(v1, op1, val1)
            c2 = self._make_comparison(v2, op2, val2)
            if c1 is not None and c2 is not None:
                return z3.And(c1, c2)

        # Simple comparison: x > 10
        m = re.match(r'(\w+)\s*(>=|<=|>|<|==|!=)\s*([-+]?\d+(?:\.\d+)?)', expr)
        if m:
            return self._make_comparison(m.group(1), m.group(2), float(m.group(3)))

        # Negation: not x > 10
        m = re.match(r'not\s+(\w+)\s*(>=|<=|>|<|==|!=)\s*([-+]?\d+(?:\.\d+)?)', expr)
        if m:
            inner = self._make_comparison(m.group(1), m.group(2), float(m.group(3)))
            return z3.Not(inner) if inner is not None else None

        # Boolean: x == True / x == False
        m = re.match(r'(\w+)\s*==\s*(True|False)', expr)
        if m:
            var = z3.Bool(m.group(1))
            return var if m.group(2) == "True" else z3.Not(var)

        # is not None / is None
        if "is not None" in expr:
            var_name = expr.split("is not None")[0].strip()
            return self._get_var(var_name) != 0
        if "is None" in expr:
            var_name = expr.split("is None")[0].strip()
            return self._get_var(var_name) == 0

        return None

    def _make_comparison(self, var_name: str, op: str, value: float):
        v = self._get_var(var_name)
        val = int(value) if value == int(value) else z3.RealVal(value)
        ops = {">=": v >= val, "<=": v <= val, ">": v > val,
               "<": v < val, "==": v == val, "!=": v != val}
        return ops.get(op)

    def _expressions_share_variables(self, expr_a: str, expr_b: str) -> bool:
        """Check if two expressions reference the same variables."""
        words_a = set(re.findall(r'\b[a-zA-Z_]\w*\b', expr_a))
        words_b = set(re.findall(r'\b[a-zA-Z_]\w*\b', expr_b))
        noise = {"is", "not", "None", "True", "False", "and", "or", "in"}
        return bool((words_a - noise) & (words_b - noise))

    def _compute_severity(self, ba: Belief, bb: Belief) -> ConflictSeverity:
        max_frag = max(ba.fragility, bb.fragility)
        if max_frag >= 0.8:
            return ConflictSeverity.CRITICAL
        elif max_frag >= 0.6:
            return ConflictSeverity.HIGH
        elif max_frag >= 0.4:
            return ConflictSeverity.MEDIUM
        return ConflictSeverity.LOW
