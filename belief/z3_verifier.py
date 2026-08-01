"""
BELIEF — Z3-based formal conflict detector (v2).

The Reasoning layer: translates belief predicates into Z3 constraints and
checks for contradictions, including transitive conflicts through the
dependency graph.

v2 changes:
- **Wider DSL coverage**: isinstance(x, T), len(x) anywhere (not only as
  operand), string-set comparisons, more chained-comparison shapes.
- **Translation diagnostics**: returns (constraint, error_msg) so callers
  can feed the error back to a repair loop.
- **Repair callback**: ConflictDetector accepts an optional `repair_fn`
  that is called when a 'fol' predicate fails translation. The callback
  returns a possibly-fixed Belief; if it now translates, we use it.
- **Heuristic fallback is more conservative**: only flags a conflict when
  there's strong textual signal (regex anti-patterns), not just any text
  similarity.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Callable, Optional

from .models import (
    Belief,
    Conflict,
    ConflictSeverity,
    Frontier,
    LogicType,
)
from .predicate_logic import PredicateLogicError

logger = logging.getLogger("belief.z3_verifier")

try:
    import z3  # type: ignore
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    logger.warning("z3-solver not installed. Using heuristic conflict detection only.")


# ─────────────────────────────────────────────
#  Translation result type
# ─────────────────────────────────────────────

@dataclass
class TranslationResult:
    """Result of translating a predicate to Z3."""
    constraint: Optional["z3.BoolRef"] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.constraint is not None


# ─────────────────────────────────────────────
#  Predicate → Z3 translator (extended)
# ─────────────────────────────────────────────

class PredicateTranslator:
    """Translate semi-formal predicate expressions into Z3 constraints.

    Coverage (v2):
      - Numeric comparisons: x <= y, len(s) < 1024
      - Equality / nullity: x == y, x != None
      - Booleans: flag == True, x is True
      - Set membership: x in {A, B, C}, x not in NAME, x in {"a", "b"}
      - Implications: A implies B, if A then B
      - Conjunction / disjunction
      - Chained comparisons: 0 < x < 100
      - String equality: x.encoding == 'utf-8'
      - isinstance(x, T): mapped to a boolean atom
      - Method-call atoms: x.is_safe(), x.has_attr() → boolean atom
      - len() anywhere as operand, with isolation
    """

    def __init__(self):
        self._vars: dict[str, "z3.ExprRef"] = {}

    # ── Public API ──

    def translate(self, expression: str) -> Optional["z3.BoolRef"]:
        """Translate to Z3, returning None on failure."""
        return self.translate_with_diagnostics(expression).constraint

    def translate_with_diagnostics(self, expression: str) -> TranslationResult:
        """Translate with error context — for repair-loop integration."""
        if not Z3_AVAILABLE:
            return TranslationResult(error="z3 not installed")

        expr = expression.strip()
        if not expr:
            return TranslationResult(error="empty expression")

        try:
            for handler in self._handlers():
                result = handler(expr)
                if result is not None:
                    return TranslationResult(constraint=result)
            return TranslationResult(
                error=f"no handler matched: '{expr[:80]}'"
            )
        except Exception as e:
            return TranslationResult(
                error=f"{type(e).__name__}: {str(e)[:120]}"
            )

    def _handlers(self):
        """Order matters: try complex/compound first, atoms last."""
        return [
            self._try_negation,
            self._try_implication,
            self._try_conjunction,
            self._try_disjunction,
            self._try_chained_comparison,
            self._try_isinstance,
            self._try_numeric_comparison,
            self._try_string_equality,
            self._try_equality,
            self._try_set_membership,
            self._try_boolean,
            self._try_method_call_atom,
        ]

    # ── Variable helpers ──

    def _get_int_var(self, name: str) -> "z3.ArithRef":
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        if clean not in self._vars:
            self._vars[clean] = z3.Int(clean)
        return self._vars[clean]

    def _get_bool_var(self, name: str) -> "z3.BoolRef":
        clean = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        key = f"bool_{clean}"
        if key not in self._vars:
            self._vars[key] = z3.Bool(clean)
        return self._vars[key]

    def _try_parse_operand(self, s: str) -> "z3.ArithRef":
        s = s.strip().strip("()")
        # Integer literal
        try:
            return z3.IntVal(int(s))
        except ValueError:
            pass
        try:
            return z3.IntVal(int(float(s)))
        except ValueError:
            pass
        # len(...) / sizeof(...) / size(...)
        m = re.match(r"(?:len|sizeof|size|count)\(\s*(.+?)\s*\)$", s)
        if m:
            return self._get_int_var(f"len_{m.group(1).strip()}")
        # type(x) — treat as int (we only check equality with type names)
        m = re.match(r"type\(\s*(.+?)\s*\)$", s)
        if m:
            return self._get_int_var(f"type_{m.group(1).strip()}")
        return self._get_int_var(s)

    # ── Pattern handlers ──

    def _try_negation(self, expr: str) -> Optional["z3.BoolRef"]:
        for prefix in ("not ", "NOT ", "!"):
            if expr.startswith(prefix):
                inner = self.translate(expr[len(prefix):].strip())
                if inner is not None:
                    return z3.Not(inner)
        return None

    def _try_implication(self, expr: str) -> Optional["z3.BoolRef"]:
        m = re.fullmatch(r"(.+?)\s+implies\s+(.+)", expr, re.IGNORECASE)
        if m:
            ante = self.translate(m.group(1).strip())
            cons = self.translate(m.group(2).strip())
            if ante is not None and cons is not None:
                return z3.Implies(ante, cons)

        m = re.fullmatch(r"if\s+(.+?)\s+then\s+(.+)", expr, re.IGNORECASE)
        if m:
            ante = self.translate(m.group(1).strip())
            cons = self.translate(m.group(2).strip())
            if ante is not None and cons is not None:
                return z3.Implies(ante, cons)

        return None

    def _try_conjunction(self, expr: str) -> Optional["z3.BoolRef"]:
        # Don't split inside parens or quoted strings
        parts = _smart_split(expr, [" and ", " AND ", " && "])
        if len(parts) < 2:
            return None
        translated = [self.translate(p.strip()) for p in parts]
        if all(t is not None for t in translated):
            return z3.And(translated)
        return None

    def _try_disjunction(self, expr: str) -> Optional["z3.BoolRef"]:
        parts = _smart_split(expr, [" or ", " OR ", " || "])
        if len(parts) < 2:
            return None
        translated = [self.translate(p.strip()) for p in parts]
        if all(t is not None for t in translated):
            return z3.Or(translated)
        return None

    def _try_chained_comparison(self, expr: str) -> Optional["z3.BoolRef"]:
        m = re.fullmatch(
            r"(.+?)\s*(<=?|>=?)\s*(.+?)\s*(<=?|>=?)\s*(.+)", expr
        )
        if not m:
            return None

        left = self._try_parse_operand(m.group(1))
        mid = self._try_parse_operand(m.group(3))
        right = self._try_parse_operand(m.group(5))
        ops = {
            "<": lambda a, b: a < b,
            "<=": lambda a, b: a <= b,
            ">": lambda a, b: a > b,
            ">=": lambda a, b: a >= b,
        }
        op1 = ops.get(m.group(2))
        op2 = ops.get(m.group(4))
        if op1 and op2:
            return z3.And(op1(left, mid), op2(mid, right))
        return None

    def _try_isinstance(self, expr: str) -> Optional["z3.BoolRef"]:
        """isinstance(x, T) → boolean atom 'x_isinstance_T'."""
        m = re.fullmatch(r"isinstance\(\s*(.+?)\s*,\s*(.+?)\s*\)", expr)
        if m:
            var = m.group(1).strip()
            typ = m.group(2).strip().strip("()")
            return self._get_bool_var(f"{var}_isinstance_{typ}")
        return None

    def _try_numeric_comparison(self, expr: str) -> Optional["z3.BoolRef"]:
        patterns = [
            (r"(.+?)\s*<=\s*(.+)", lambda a, b: a <= b),
            (r"(.+?)\s*>=\s*(.+)", lambda a, b: a >= b),
            (r"(.+?)\s*<\s*(.+)", lambda a, b: a < b),
            (r"(.+?)\s*>\s*(.+)", lambda a, b: a > b),
        ]
        for pattern, op in patterns:
            m = re.fullmatch(pattern, expr)
            if m:
                left = self._try_parse_operand(m.group(1))
                right = self._try_parse_operand(m.group(2))
                return op(left, right)
        return None

    def _try_string_equality(self, expr: str) -> Optional["z3.BoolRef"]:
        m = re.fullmatch(r"""(.+?)\s*==\s*['"](.+?)['"]""", expr)
        if m:
            var_name = m.group(1).strip()
            value = m.group(2).strip()
            return self._get_bool_var(f"{var_name}_eq_{value}")

        m = re.fullmatch(r"""(.+?)\s*!=\s*['"](.+?)['"]""", expr)
        if m:
            var_name = m.group(1).strip()
            value = m.group(2).strip()
            return z3.Not(self._get_bool_var(f"{var_name}_eq_{value}"))

        return None

    def _try_equality(self, expr: str) -> Optional["z3.BoolRef"]:
        # != None / is not None
        m = re.fullmatch(r"(.+?)\s*(?:!=|is\s+not)\s*(?:None|null|NULL)", expr)
        if m:
            return self._get_bool_var(f"{m.group(1).strip()}_is_not_none")

        # == None / is None
        m = re.fullmatch(r"(.+?)\s*(?:==|is)\s*(?:None|null|NULL)", expr)
        if m:
            return z3.Not(self._get_bool_var(f"{m.group(1).strip()}_is_not_none"))

        # ==
        m = re.fullmatch(r"(.+?)\s*==\s*(.+)", expr)
        if m:
            left = self._try_parse_operand(m.group(1))
            right = self._try_parse_operand(m.group(2))
            return left == right

        # !=
        m = re.fullmatch(r"(.+?)\s*!=\s*(.+)", expr)
        if m:
            left = self._try_parse_operand(m.group(1))
            right = self._try_parse_operand(m.group(2))
            return left != right

        return None

    def _try_set_membership(self, expr: str) -> Optional["z3.BoolRef"]:
        # x in {A, B, C}  (literal set)
        m = re.fullmatch(r"(.+?)\s+in\s+\{(.+?)\}", expr)
        if m:
            var_name = m.group(1).strip()
            members = [s.strip().strip("'\"") for s in m.group(2).split(",")]
            return self._get_bool_var(f"{var_name}_in_{'_'.join(sorted(members))[:40]}")

        # x not in {A, B, C}
        m = re.fullmatch(r"(.+?)\s+not\s+in\s+\{(.+?)\}", expr)
        if m:
            var_name = m.group(1).strip()
            members = [s.strip().strip("'\"") for s in m.group(2).split(",")]
            return z3.Not(self._get_bool_var(
                f"{var_name}_in_{'_'.join(sorted(members))[:40]}"
            ))

        # x in SETNAME (symbolic set)
        m = re.fullmatch(r"(.+?)\s+in\s+([A-Z_][A-Z_0-9]*)", expr)
        if m:
            return self._get_bool_var(
                f"{m.group(1).strip()}_in_{m.group(2).strip()}"
            )

        # x not in SETNAME
        m = re.fullmatch(r"(.+?)\s+not\s+in\s+([A-Z_][A-Z_0-9]*)", expr)
        if m:
            return z3.Not(self._get_bool_var(
                f"{m.group(1).strip()}_in_{m.group(2).strip()}"
            ))

        return None

    def _try_boolean(self, expr: str) -> Optional["z3.BoolRef"]:
        m = re.fullmatch(r"(.+?)\s*(?:==|is)\s*(?:True|true)", expr)
        if m:
            return self._get_bool_var(m.group(1).strip())

        m = re.fullmatch(r"(.+?)\s*(?:==|is)\s*(?:False|false)", expr)
        if m:
            return z3.Not(self._get_bool_var(m.group(1).strip()))

        # Bare boolean atom: e.g. just "is_admin" (no operator)
        if re.fullmatch(r"[a-zA-Z_][\w.]*", expr):
            return self._get_bool_var(expr)

        return None

    def _try_method_call_atom(self, expr: str) -> Optional["z3.BoolRef"]:
        """Treat method-call expressions as opaque boolean atoms.
        Examples: x.is_safe(), x.is_valid(), x.has_attr('foo'), is_admin(user).
        This lets us at least track conflicts between two beliefs that both
        reference the same call."""
        m = re.fullmatch(r"([a-zA-Z_][\w.]*)\(.*?\)", expr)
        if m:
            return self._get_bool_var(m.group(1).strip().replace(".", "_"))
        return None


# ─────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────

def _smart_split(text: str, separators: list[str]) -> list[str]:
    """Split text on the first found separator, but only at top level
    (not inside parens or quotes). Returns [text] if no split."""
    depth = 0
    in_str: str | None = None
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if in_str:
            if c == in_str and (i == 0 or text[i - 1] != "\\"):
                in_str = None
            i += 1
            continue
        if c in ("'", '"'):
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
            i += 1
            continue
        if c in ")]}":
            depth -= 1
            i += 1
            continue

        if depth == 0:
            for sep in separators:
                if text.startswith(sep, i):
                    # Found a split point — split ALL top-level occurrences
                    return _split_all_top_level(text, sep)
        i += 1
    return [text]


def _split_all_top_level(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    in_str: str | None = None
    last = 0
    i = 0
    n = len(text)
    sep_len = len(sep)
    while i < n:
        c = text[i]
        if in_str:
            if c == in_str and (i == 0 or text[i - 1] != "\\"):
                in_str = None
            i += 1
            continue
        if c in ("'", '"'):
            in_str = c
            i += 1
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        if depth == 0 and text[i:i + sep_len] == sep:
            parts.append(text[last:i])
            last = i + sep_len
            i += sep_len
            continue
        i += 1
    parts.append(text[last:])
    return parts


# ─────────────────────────────────────────────
#  Conflict Detector
# ─────────────────────────────────────────────

# Type alias for the repair callback
RepairFn = Callable[[Belief, str], Optional[Belief]]


class ConflictDetector:
    """Detect conflicts between beliefs using Z3 + heuristic fallback."""

    def __init__(
        self,
        timeout_ms: int = 30000,
        repair_fn: Optional[RepairFn] = None,
    ):
        self.timeout_ms = timeout_ms
        self.repair_fn = repair_fn  # called with (belief, error_str)

        # Stats — useful for measuring DSL hit rate
        self.stats = {
            "translated_ok": 0,
            "translated_after_repair": 0,
            "translation_failed": 0,
            "z3_conflicts": 0,
            "heuristic_conflicts": 0,
            "predicate_negation_abstained": 0,
        }

    # ── Public API ──

    def detect_pairwise(
        self,
        beliefs_a: list[Belief],
        beliefs_b: list[Belief],
        frontier: Optional[Frontier] = None,
    ) -> list[Conflict]:
        """Check all pairs from two components for contradictions."""
        conflicts: list[Conflict] = []
        for ba in beliefs_a:
            if ba.logic_type != LogicType.FOL:
                continue
            for bb in beliefs_b:
                if bb.logic_type != LogicType.FOL:
                    continue
                if not self._share_variables(ba, bb):
                    continue
                conflict = self._check_conflict(ba, bb, frontier)
                if conflict:
                    conflicts.append(conflict)
        return conflicts

    def detect_transitive(
        self,
        all_beliefs: list[Belief],
        call_graph: dict[str, set[str]],
        frontiers: list[Frontier],
    ) -> list[Conflict]:
        """A→B→C: A and C contradict transitively even if A↔B and B↔C don't."""
        conflicts: list[Conflict] = []
        beliefs_by_scope: dict[str, list[Belief]] = {}
        for b in all_beliefs:
            beliefs_by_scope.setdefault(b.scope.qualified_name, []).append(b)

        visited: set[str] = set()
        for start, callees in call_graph.items():
            for mid in callees:
                for end in call_graph.get(mid, set()):
                    if start == end:
                        continue
                    path_key = f"{start}->{mid}->{end}"
                    if path_key in visited:
                        continue
                    visited.add(path_key)

                    start_beliefs = beliefs_by_scope.get(start, [])
                    end_beliefs = beliefs_by_scope.get(end, [])
                    if not start_beliefs or not end_beliefs:
                        continue

                    for ba in start_beliefs:
                        for bb in end_beliefs:
                            if not self._share_variables(ba, bb):
                                continue
                            conflict = self._check_conflict(ba, bb, None)
                            if conflict:
                                conflict.is_transitive = True
                                conflict.transitive_path = [start, mid, end]
                                conflicts.append(conflict)

        return conflicts

    # ── Internal ──

    def _share_variables(self, a: Belief, b: Belief) -> bool:
        """Quick filter: do the two beliefs reference at least one common variable?"""
        if not a.predicate.variables or not b.predicate.variables:
            a_words = set(re.findall(r"\b[a-z_][a-z0-9_]*\b",
                                    a.predicate.expression.lower()))
            b_words = set(re.findall(r"\b[a-z_][a-z0-9_]*\b",
                                    b.predicate.expression.lower()))
            noise = {
                "is", "not", "in", "true", "false", "none", "null",
                "and", "or", "the", "len", "type", "isinstance",
            }
            return bool((a_words - noise) & (b_words - noise))

        a_vars = {v.lower().split(".")[0] for v in a.predicate.variables}
        b_vars = {v.lower().split(".")[0] for v in b.predicate.variables}
        return bool(a_vars & b_vars)

    def _translate_or_repair(
        self, belief: Belief, code_context: str = ""
    ) -> tuple[Optional["z3.BoolRef"], Belief]:
        """Translate `belief.predicate.expression` to Z3. If it fails AND
        a repair callback is set, try once. Returns (constraint, possibly-
        updated belief)."""
        translator = PredicateTranslator()
        result = translator.translate_with_diagnostics(belief.predicate.expression)
        if result.ok:
            self.stats["translated_ok"] += 1
            return result.constraint, belief

        if self.repair_fn is not None and result.error:
            try:
                repaired = self.repair_fn(belief, result.error)
            except Exception as e:
                logger.debug(f"Repair callback raised: {e}")
                repaired = None

            if repaired is not None and repaired.logic_type == LogicType.FOL:
                result2 = translator.translate_with_diagnostics(
                    repaired.predicate.expression
                )
                if result2.ok:
                    self.stats["translated_after_repair"] += 1
                    return result2.constraint, repaired

        self.stats["translation_failed"] += 1
        return None, belief

    def _check_conflict(
        self,
        a: Belief,
        b: Belief,
        frontier: Optional[Frontier],
    ) -> Optional[Conflict]:
        if Z3_AVAILABLE:
            result = self._check_z3(a, b)
            if result is not None:
                return result
        return self._check_heuristic(a, b, frontier)

    def _check_z3(self, a: Belief, b: Belief) -> Optional[Conflict]:
        z3_a, a = self._translate_or_repair(a)
        z3_b, b = self._translate_or_repair(b)
        if z3_a is None or z3_b is None:
            return None

        solver = z3.Solver()
        solver.set("timeout", self.timeout_ms)

        # Direct contradiction: A ∧ B unsat
        solver.push()
        solver.add(z3_a)
        solver.add(z3_b)
        both_sat = solver.check()
        solver.pop()

        if both_sat == z3.unsat:
            self.stats["z3_conflicts"] += 1
            return Conflict(
                belief_a=a,
                belief_b=b,
                severity=self._calculate_severity(a, b),
                description=(
                    f"Formal contradiction: '{a.predicate.expression}' "
                    f"and '{b.predicate.expression}' cannot both be true."
                ),
                verified_by="z3",
            )

        # Possible-world: ¬A ∧ B sat → if A is fragile this is exploitable
        solver.push()
        solver.add(z3.Not(z3_a))
        solver.add(z3_b)
        neg_a_sat = solver.check()

        possible_world_str = None
        if neg_a_sat == z3.sat:
            try:
                possible_world_str = str(solver.model())
            except z3.Z3Exception:
                possible_world_str = None
        solver.pop()

        if neg_a_sat == z3.sat and a.justification.robustness_score < 0.5:
            self.stats["z3_conflicts"] += 1
            return Conflict(
                belief_a=a,
                belief_b=b,
                severity=self._calculate_severity(a, b),
                description=(
                    f"Belief '{a.predicate.expression}' ({a.justification.value}) "
                    f"can be violated while '{b.predicate.expression}' holds. "
                    f"If an attacker violates A's assumption, B's behavior is undefined."
                ),
                possible_world=possible_world_str,
                verified_by="z3",
            )

        return None

    def _check_heuristic(
        self,
        a: Belief,
        b: Belief,
        frontier: Optional[Frontier],
    ) -> Optional[Conflict]:
        """Conservative heuristic: only fire on strong textual signals."""

        # Direct negation match
        try:
            neg_a = a.predicate.negation()
        except PredicateLogicError:
            neg_a = None
            self.stats["predicate_negation_abstained"] += 1
        if (
            neg_a is not None
            and self._expressions_match(neg_a, b.predicate.expression)
        ):
            self.stats["heuristic_conflicts"] += 1
            return Conflict(
                belief_a=a,
                belief_b=b,
                severity=self._calculate_severity(a, b),
                description=(
                    f"Heuristic contradiction: negation of '{a.predicate.expression}' "
                    f"matches '{b.predicate.expression}'."
                ),
                verified_by="heuristic_negation",
            )

        # Strong trust-asymmetry signal — only when frontier is provided
        if frontier and frontier.trust_asymmetry > 0.7:
            if (a.justification.robustness_score <= 0.3 and
                    b.justification.robustness_score <= 0.3):
                self.stats["heuristic_conflicts"] += 1
                return Conflict(
                    belief_a=a,
                    belief_b=b,
                    severity=ConflictSeverity.MEDIUM,
                    description=(
                        f"Both sides of a high-trust-asymmetry frontier "
                        f"({frontier.trust_asymmetry:.2f}) have weak justifications. "
                        f"A: {a.predicate.expression} ({a.justification.value}), "
                        f"B: {b.predicate.expression} ({b.justification.value})."
                    ),
                    verified_by="heuristic_trust",
                )

        return None

    def _expressions_match(self, expr_a: str, expr_b: str) -> bool:
        a = re.sub(r"\s+", " ", expr_a.lower().strip())
        b = re.sub(r"\s+", " ", expr_b.lower().strip())
        return a == b

    def _calculate_severity(self, a: Belief, b: Belief) -> ConflictSeverity:
        max_fragility = max(a.fragility, b.fragility)
        min_robustness = min(
            a.justification.robustness_score,
            b.justification.robustness_score,
        )
        score = max_fragility * 0.5 + (1 - min_robustness) * 0.5

        if score > 0.8:
            return ConflictSeverity.CRITICAL
        if score > 0.6:
            return ConflictSeverity.HIGH
        if score > 0.4:
            return ConflictSeverity.MEDIUM
        if score > 0.2:
            return ConflictSeverity.LOW
        return ConflictSeverity.INFO

    def report_stats(self) -> dict:
        """Useful for measuring 'translated_ok / total' rate over time."""
        total = (self.stats["translated_ok"]
                 + self.stats["translated_after_repair"]
                 + self.stats["translation_failed"])
        rate = (self.stats["translated_ok"] + self.stats["translated_after_repair"]) / total if total else 0
        return {**self.stats, "translation_success_rate": round(rate, 3)}
