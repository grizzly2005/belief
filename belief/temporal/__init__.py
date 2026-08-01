"""
BELIEF — Temporal Logic Checker.

Checks LTL-like temporal properties on belief sequences:
- Always: a property must hold at every point
- Eventually: a property must hold at some point
- Until: property A holds until property B becomes true
- Never: a property must never hold

Applied to beliefs about resource management, lock ordering,
state machine transitions, and temporal drift.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass

from ..models import (
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)

logger = logging.getLogger("belief.temporal")


@dataclass
class TemporalProperty:
    """A temporal property to check."""
    name: str
    kind: str           # always, eventually, never, until
    predicate: str      # what must hold
    description: str = ""


@dataclass
class TemporalViolation:
    """A violation of a temporal property."""
    property_name: str
    kind: str
    line: int
    description: str
    severity: str = "medium"


class TemporalChecker:
    """
    Check temporal properties on Python source code.

    Analyzes control flow to verify that temporal beliefs hold:
    - Resources acquired are always released
    - Locks are not held indefinitely
    - State transitions follow expected patterns
    """

    # Built-in temporal properties
    BUILTIN_PROPERTIES = [
        TemporalProperty(
            "resource_release", "always",
            "resource.acquired implies eventually resource.released",
            "Every acquired resource must eventually be released",
        ),
        TemporalProperty(
            "lock_release", "always",
            "lock.acquired implies eventually lock.released",
            "Every lock must be released after acquisition",
        ),
        TemporalProperty(
            "error_handling", "always",
            "external_call implies eventually error_check",
            "External calls should have error handling",
        ),
        TemporalProperty(
            "close_after_open", "always",
            "file.open implies eventually file.close",
            "Opened files must be closed",
        ),
    ]

    def __init__(self, properties: list[TemporalProperty] | None = None):
        self.properties = properties or self.BUILTIN_PROPERTIES

    def check(self, source_code: str, file_path: str = "",
              module: str = "") -> list[Belief]:
        """Check temporal properties and return beliefs."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        beliefs = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func_beliefs = self._check_function(node, file_path, module)
                beliefs.extend(func_beliefs)

        return beliefs

    def _check_function(self, func: ast.FunctionDef, fp: str, mod: str) -> list[Belief]:
        beliefs = []
        scope = Scope(file_path=fp, function_name=func.name, module=mod,
                       line_start=func.lineno, line_end=func.end_lineno)

        # Extract calls and operations in order
        operations = self._extract_operations(func)

        # Check resource acquire/release pattern
        beliefs.extend(self._check_resource_pattern(operations, scope))

        # Check lock pattern
        beliefs.extend(self._check_lock_pattern(operations, scope))

        # Check file open/close pattern
        beliefs.extend(self._check_file_pattern(operations, scope))

        # Check error handling for external calls
        beliefs.extend(self._check_error_handling_pattern(func, scope))

        return beliefs

    def _extract_operations(self, func: ast.FunctionDef) -> list[tuple[str, int]]:
        """Extract ordered operations from function body."""
        ops = []
        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                name = self._get_call_name(node)
                if name:
                    ops.append((name.lower(), getattr(node, 'lineno', 0)))
            if isinstance(node, ast.With) or isinstance(node, ast.AsyncWith):
                ops.append(("context_manager", getattr(node, 'lineno', 0)))
        return sorted(ops, key=lambda x: x[1])

    def _check_resource_pattern(self, operations: list[tuple[str, int]],
                                 scope: Scope) -> list[Belief]:
        """Check acquire/release patterns."""
        beliefs = []
        acquire_patterns = {"acquire", "lock", "connect", "open", "begin", "start"}
        release_patterns = {"release", "unlock", "close", "disconnect", "end", "stop", "commit", "rollback"}

        acquired = []
        for op_name, line in operations:
            for ap in acquire_patterns:
                if ap in op_name:
                    acquired.append((op_name, line))
                    break
            for rp in release_patterns:
                if rp in op_name:
                    if acquired:
                        acquired.pop()
                    break

        # Unreleased resources
        for op_name, line in acquired:
            beliefs.append(Belief(
                predicate=Predicate(
                    expression=f"resource({op_name}).eventually_released == True",
                    variables=(op_name,),
                    anchor_lines=(line,),
                    natural_language=(
                        f"Resource acquired via '{op_name}' at line {line} "
                        f"may not be released — no matching release found."
                    ),
                ),
                scope=scope,
                justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                epistemic_status=EpistemicStatus.HOPE,
                logic_type=LogicType.TEMPORAL,
                confidence_score=0.82,
            ))
        return beliefs

    def _check_lock_pattern(self, operations: list[tuple[str, int]],
                             scope: Scope) -> list[Belief]:
        """Check lock acquire/release ordering."""
        beliefs = []
        locks_held = []

        for op_name, line in operations:
            if "lock" in op_name and any(a in op_name for a in ["acquire", "lock("]):
                locks_held.append((op_name, line))
            elif "lock" in op_name and any(r in op_name for r in ["release", "unlock"]):
                if locks_held:
                    locks_held.pop()
            elif op_name == "context_manager":
                pass  # context managers handle cleanup

        for op_name, line in locks_held:
            beliefs.append(Belief(
                predicate=Predicate(
                    expression=f"lock({op_name}).released == True",
                    variables=(),
                    anchor_lines=(line,),
                    natural_language=f"Lock acquired at line {line} may not be released in all paths.",
                ),
                scope=scope,
                justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                epistemic_status=EpistemicStatus.HOPE,
                logic_type=LogicType.TEMPORAL,
                confidence_score=0.80,
            ))
        return beliefs

    def _check_file_pattern(self, operations: list[tuple[str, int]],
                             scope: Scope) -> list[Belief]:
        """Check file open/close patterns."""
        beliefs = []
        opens = []

        for op_name, line in operations:
            if "open" in op_name and "close" not in op_name:
                opens.append((op_name, line))
            elif "close" in op_name:
                if opens:
                    opens.pop()

        for op_name, line in opens:
            beliefs.append(Belief(
                predicate=Predicate(
                    expression=f"file({op_name}).closed == True",
                    variables=(),
                    anchor_lines=(line,),
                    natural_language=f"File opened at line {line} may not be closed — use 'with' statement.",
                ),
                scope=scope,
                justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                epistemic_status=EpistemicStatus.HOPE,
                logic_type=LogicType.TEMPORAL,
                confidence_score=0.85,
            ))
        return beliefs

    def _check_error_handling_pattern(self, func: ast.FunctionDef,
                                       scope: Scope) -> list[Belief]:
        """Check that external calls have error handling."""
        beliefs = []
        external_patterns = {"request", "fetch", "connect", "query", "execute",
                              "send", "recv", "urlopen", "http"}

        for node in ast.walk(func):
            if isinstance(node, ast.Call):
                name = self._get_call_name(node)
                if not name:
                    continue
                if any(ep in name.lower() for ep in external_patterns):
                    # Check if inside try/except
                    if not self._is_inside_try(func, node.lineno):
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"{name}().error_handled == True",
                                variables=(name,),
                                anchor_lines=(node.lineno,),
                                natural_language=(
                                    f"External call '{name}' at line {node.lineno} "
                                    f"has no error handling — assumes it always succeeds."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.HOPE,
                            logic_type=LogicType.TEMPORAL,
                            confidence_score=0.88,
                        ))
        return beliefs

    def _is_inside_try(self, func: ast.FunctionDef, target_line: int) -> bool:
        for node in ast.walk(func):
            if isinstance(node, ast.Try):
                if hasattr(node, 'lineno') and hasattr(node, 'end_lineno'):
                    if node.lineno <= target_line <= (node.end_lineno or target_line + 1):
                        return True
        return False

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            base = self._get_call_name_inner(node.func.value)
            if base:
                return f"{base}.{node.func.attr}"
            return node.func.attr
        return None

    def _get_call_name_inner(self, node) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_call_name_inner(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None
