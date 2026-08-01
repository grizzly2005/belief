"""
BELIEF — Structural belief extractor (no LLM required).

Extracts implicit beliefs directly from code patterns using Python AST.
This is a backup/supplement to LLM extraction: it catches common belief
patterns that are mechanically detectable from code structure.

Examples:
- Function parameter with no type hint → belief about type (C5)
- No null check before dereference → belief that value is not None (C5)
- No bounds check before indexing → belief about size (C5)
- No try/except around I/O → belief that I/O succeeds (C5 or hope)
- No return value check → belief that call succeeds (C5)
"""

from __future__ import annotations

import ast
import logging
from typing import Optional

from .models import (
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)

logger = logging.getLogger("belief.structural")


class StructuralExtractor:
    """
    Extract implicit beliefs from code structure without LLM.

    This is the "rule-based backup" that catches the most common belief
    patterns mechanically. It doesn't replace LLM extraction — it
    supplements it with high-confidence, deterministic findings.
    """

    def extract(
        self,
        source_code: str,
        file_path: str,
        module: str = "",
        function_name: str | None = None,
        class_name: str | None = None,
    ) -> list[Belief]:
        """Extract structural beliefs from Python source code."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        beliefs = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                fn_beliefs = self._analyze_function(
                    node, source_code, file_path, module
                )
                beliefs.extend(fn_beliefs)

        return beliefs

    def _analyze_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        source: str,
        file_path: str,
        module: str,
    ) -> list[Belief]:
        beliefs = []
        scope = Scope(
            file_path=file_path,
            function_name=node.name,
            module=module,
            line_start=node.lineno,
            line_end=node.end_lineno,
        )

        # 1. Untyped parameters → belief about type
        beliefs.extend(self._check_untyped_params(node, scope))

        # 2. Unchecked subscript access → belief about size/existence
        beliefs.extend(self._check_unchecked_indexing(node, scope, source))

        # 3. Attribute access without None check → belief not None
        beliefs.extend(self._check_unchecked_attr_access(node, scope, source))

        # 4. No try/except around external calls → belief about success
        beliefs.extend(self._check_unguarded_external_calls(node, scope, source))

        # 5. Division without zero check → belief about non-zero
        beliefs.extend(self._check_unchecked_division(node, scope, source))

        # 6. String formatting with external data → belief about format
        beliefs.extend(self._check_unvalidated_formatting(node, scope, source))

        # 7. Mutable default arguments → belief callers don't mutate shared state
        beliefs.extend(self._check_mutable_defaults(node, scope))

        # 8. Bare except / swallowed exceptions → belief errors are unimportant
        beliefs.extend(self._check_swallowed_exceptions(node, scope))

        # 9. Hardcoded strings that look like secrets → belief about config safety
        beliefs.extend(self._check_hardcoded_secrets(node, scope, source))

        # 10. Path operations without sanitization → belief about path safety
        beliefs.extend(self._check_unsafe_path_ops(node, scope))

        # 11. Unchecked cast / type coercion → belief about actual type
        beliefs.extend(self._check_unchecked_coercion(node, scope))

        # 12. No timeout on network/IO operations → belief about responsiveness
        beliefs.extend(self._check_missing_timeout(node, scope))

        # 13. Global/shared state mutation → belief about exclusive access
        beliefs.extend(self._check_shared_state_mutation(node, scope))

        # 14. Comparison with floating point equality → belief about precision
        beliefs.extend(self._check_float_equality(node, scope))

        return beliefs

    def _check_untyped_params(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        for arg in node.args.args:
            if arg.arg == "self" or arg.arg == "cls":
                continue
            if arg.annotation is None:
                beliefs.append(Belief(
                    predicate=Predicate(
                        expression=f"type({arg.arg}) == <expected>",
                        variables=(arg.arg,),
                        anchor_lines=(node.lineno,),
                        natural_language=(
                            f"Parameter '{arg.arg}' has no type annotation. "
                            f"The developer implicitly assumes callers pass the correct type."
                        ),
                    ),
                    scope=scope,
                    justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                    epistemic_status=EpistemicStatus.BELIEF,
                    logic_type=LogicType.FOL,
                    confidence_score=0.95,  # high confidence: structural fact
                ))
        return beliefs

    def _check_unchecked_indexing(
        self, node: ast.FunctionDef, scope: Scope, source: str
    ) -> list[Belief]:
        beliefs = []

        for child in ast.walk(node):
            if isinstance(child, ast.Subscript):
                # Check if there's a len() check or try/except above
                if not self._has_guard_before(node, child.lineno, ["len(", "if ", "try:"]):
                    var_name = self._get_name(child.value)
                    if var_name:
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"len({var_name}) > index",
                                variables=(var_name,),
                                anchor_lines=(child.lineno,),
                                natural_language=(
                                    f"Subscript access on '{var_name}' at line {child.lineno} "
                                    f"without bounds check."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.BELIEF,
                            logic_type=LogicType.FOL,
                            confidence_score=0.85,
                        ))
        return beliefs

    def _check_unchecked_attr_access(
        self, node: ast.FunctionDef, scope: Scope, source: str
    ) -> list[Belief]:
        beliefs = []
        seen_vars = set()

        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                var_name = self._get_name(child.value)
                if var_name and var_name not in seen_vars:
                    # Check if there's a None check before this access
                    if not self._has_guard_before(
                        node, child.lineno,
                        [f"{var_name} is not None", f"{var_name} is None",
                         f"if {var_name}", f"{var_name} !="]
                    ):
                        seen_vars.add(var_name)
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"{var_name} is not None",
                                variables=(var_name,),
                                anchor_lines=(child.lineno,),
                                natural_language=(
                                    f"Attribute access on '{var_name}' at line {child.lineno} "
                                    f"without None check."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.BELIEF,
                            logic_type=LogicType.FOL,
                            confidence_score=0.80,
                        ))
        return beliefs

    def _check_unguarded_external_calls(
        self, node: ast.FunctionDef, scope: Scope, source: str
    ) -> list[Belief]:
        beliefs = []
        external_patterns = {
            "open", "read", "write", "connect", "send", "recv",
            "get", "post", "put", "delete", "execute", "run",
            "loads", "load", "dumps", "dump",
        }

        # Check if the function body has a try/except
        has_try = any(isinstance(c, ast.Try) for c in ast.walk(node))

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name and any(p in call_name.lower() for p in external_patterns):
                    if not has_try:
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"{call_name}() succeeds",
                                variables=(call_name,),
                                anchor_lines=(child.lineno,),
                                natural_language=(
                                    f"External call '{call_name}()' at line {child.lineno} "
                                    f"has no error handling (no try/except in function)."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.HOPE,
                            logic_type=LogicType.PROBABILISTIC,
                            confidence_score=0.90,
                        ))
        return beliefs

    def _check_unchecked_division(
        self, node: ast.FunctionDef, scope: Scope, source: str
    ) -> list[Belief]:
        beliefs = []
        for child in ast.walk(node):
            if isinstance(child, (ast.Div, ast.FloorDiv)):
                # Find the parent BinOp
                pass  # Handled via BinOp below
            if isinstance(child, ast.BinOp) and isinstance(child.op, (ast.Div, ast.FloorDiv)):
                divisor_name = self._get_name(child.right)
                if divisor_name and not self._has_guard_before(
                    node, child.lineno, [f"{divisor_name} != 0", f"{divisor_name} > 0"]
                ):
                    beliefs.append(Belief(
                        predicate=Predicate(
                            expression=f"{divisor_name} != 0",
                            variables=(divisor_name,),
                            anchor_lines=(child.lineno,),
                            natural_language=(
                                f"Division by '{divisor_name}' at line {child.lineno} "
                                f"without zero check."
                            ),
                        ),
                        scope=scope,
                        justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                        epistemic_status=EpistemicStatus.BELIEF,
                        logic_type=LogicType.FOL,
                        confidence_score=0.92,
                    ))
        return beliefs

    def _check_unvalidated_formatting(
        self, node: ast.FunctionDef, scope: Scope, source: str
    ) -> list[Belief]:
        beliefs = []
        for child in ast.walk(node):
            # f-string or .format() with external variable
            if isinstance(child, ast.JoinedStr):
                for value in child.values:
                    if isinstance(value, ast.FormattedValue):
                        var_name = self._get_name(value.value)
                        if var_name:
                            beliefs.append(Belief(
                                predicate=Predicate(
                                    expression=f"{var_name}.is_safe_for_formatting == True",
                                    variables=(var_name,),
                                    anchor_lines=(child.lineno,),
                                    natural_language=(
                                        f"Variable '{var_name}' used in f-string at line "
                                        f"{child.lineno} without sanitization."
                                    ),
                                ),
                                scope=scope,
                                justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                                epistemic_status=EpistemicStatus.BELIEF,
                                logic_type=LogicType.INFORMATION_FLOW,
                                confidence_score=0.75,
                            ))
        return beliefs

    def _check_mutable_defaults(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        all_defaults = node.args.defaults + [
            d for d in node.args.kw_defaults if d is not None
        ]
        for default in all_defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                beliefs.append(Belief(
                    predicate=Predicate(
                        expression="mutable_default is not shared across calls",
                        variables=(),
                        anchor_lines=(node.lineno,),
                        natural_language=(
                            f"Function '{node.name}' has a mutable default argument. "
                            f"Developer assumes callers don't mutate the shared default."
                        ),
                    ),
                    scope=scope,
                    justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                    epistemic_status=EpistemicStatus.BELIEF,
                    logic_type=LogicType.BEHAVIORAL,
                    confidence_score=0.95,
                ))
                break  # one finding per function is enough
        return beliefs

    def _check_swallowed_exceptions(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        for child in ast.walk(node):
            if isinstance(child, ast.ExceptHandler):
                # Bare except or except that does nothing useful
                if child.type is None:
                    beliefs.append(Belief(
                        predicate=Predicate(
                            expression="caught_exception.severity == LOW",
                            variables=(),
                            anchor_lines=(child.lineno,),
                            natural_language=(
                                f"Bare except at line {child.lineno} catches ALL exceptions. "
                                f"Developer believes no critical error can occur here."
                            ),
                        ),
                        scope=scope,
                        justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                        epistemic_status=EpistemicStatus.HOPE,
                        logic_type=LogicType.BEHAVIORAL,
                        confidence_score=0.90,
                    ))
                # Check if exception variable is unused (swallowed)
                elif child.name:
                    # Walk the handler body looking for Name nodes using the variable
                    var_used = False
                    for body_node in ast.walk(ast.Module(body=child.body, type_ignores=[])):
                        if isinstance(body_node, ast.Name) and body_node.id == child.name:
                            var_used = True
                            break
                    if not var_used:
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"exception_{child.name}.details_unimportant == True",
                                variables=(),
                                anchor_lines=(child.lineno,),
                                natural_language=(
                                    f"Exception caught as '{child.name}' at line {child.lineno} "
                                    f"but variable is never used — error details are silently discarded."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.HOPE,
                            logic_type=LogicType.BEHAVIORAL,
                            confidence_score=0.85,
                        ))
        return beliefs

    def _check_hardcoded_secrets(
        self, node: ast.FunctionDef, scope: Scope, source: str
    ) -> list[Belief]:
        import re as _re
        beliefs = []
        secret_patterns = [
            (_re.compile(r"""(?:password|passwd|secret|token|api_key|apikey)\s*=\s*['"][^'"]{4,}['"]""", _re.IGNORECASE), "credential"),
            (_re.compile(r"""['"](?:sk-|pk-|ghp_|gho_|aws_)[a-zA-Z0-9]{10,}['"]"""), "API key"),
        ]
        lines = source.split("\n")
        func_lines = lines[node.lineno - 1: (node.end_lineno or node.lineno)]
        func_src = "\n".join(func_lines)

        for pattern, kind in secret_patterns:
            match = pattern.search(func_src)
            if match:
                beliefs.append(Belief(
                    predicate=Predicate(
                        expression=f"hardcoded_{kind}.is_safe_in_source == True",
                        variables=(),
                        anchor_lines=(node.lineno,),
                        natural_language=(
                            f"Possible hardcoded {kind} found in '{node.name}'. "
                            f"Developer believes source code is not exposed."
                        ),
                    ),
                    scope=scope,
                    justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                    epistemic_status=EpistemicStatus.BELIEF,
                    logic_type=LogicType.INFORMATION_FLOW,
                    confidence_score=0.80,
                ))
                break
        return beliefs

    def _check_unsafe_path_ops(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Emit path-safety beliefs only for locally traceable external input."""
        beliefs = []
        tainted_vars = self._external_path_variables(node)
        path_sinks = {
            "open",
            "builtins.open",
            "io.open",
            "os.open",
            "path",
            "pathlib.path",
            "os.path.join",
        }
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            call_name = (self._get_call_name(child) or "").lower()
            if call_name not in path_sinks:
                continue
            source_arg = next(
                (arg for arg in child.args if self._is_external_path_expr(arg, tainted_vars)),
                None,
            )
            if source_arg is None:
                continue
            source_name = self._get_name(source_arg) or "external path input"
            beliefs.append(Belief(
                predicate=Predicate(
                    expression=f"{source_name} not in PATH_TRAVERSAL_PATTERNS",
                    variables=(source_name,),
                    anchor_lines=(child.lineno,),
                    natural_language=(
                        f"Externally controlled path used in path operation at line "
                        f"{child.lineno} without a path traversal check."
                    ),
                ),
                scope=scope,
                justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                epistemic_status=EpistemicStatus.BELIEF,
                logic_type=LogicType.INFORMATION_FLOW,
                confidence_score=0.78,
            ))
        return beliefs

    def _external_path_variables(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        """Follow direct aliases of external path input within one function."""
        parameters = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg:
            parameters.append(node.args.vararg)
        if node.args.kwarg:
            parameters.append(node.args.kwarg)
        tainted = {
            arg.arg for arg in parameters
            if self._is_likely_external_path_name(arg.arg)
        }
        for statement in ast.walk(node):
            if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
                continue
            value = statement.value
            if value is None:
                continue
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            for target in targets:
                target_name = self._get_name(target)
                if not target_name:
                    continue
                if self._is_external_path_expr(value, tainted):
                    tainted.add(target_name)
                else:
                    tainted.discard(target_name)
        return tainted

    @staticmethod
    def _is_likely_external_path_name(name: str) -> bool:
        normalized = name.lower().replace("-", "_")
        if normalized in {
            "user_input",
            "userinput",
            "uploaded_file",
            "upload_filename",
            "request_path",
            "request_file",
            "untrusted_path",
            "untrusted_file",
            "client_path",
            "client_file",
        }:
            return True
        if normalized.endswith("_input"):
            return True
        return (
            normalized.startswith(("user_", "request_", "untrusted_", "client_"))
            and normalized.endswith(("path", "file", "filename"))
        )

    def _is_external_path_expr(self, node: ast.AST, tainted_vars: set[str]) -> bool:
        if isinstance(node, ast.Name):
            return node.id in tainted_vars or self._is_likely_external_path_name(node.id)
        dotted_name = self._get_name(node)
        if dotted_name:
            lowered = dotted_name.lower()
            if lowered == "sys.argv" or lowered.startswith(("sys.argv.", "os.environ", "request.", "req.")):
                return True
        if isinstance(node, ast.Call):
            call_name = (self._get_call_name(node) or "").lower()
            if (
                call_name in {"input", "getenv", "os.getenv"}
                or call_name.endswith(".input")
                or call_name.startswith(("request.", "req.", "os.environ."))
            ):
                return True
        return any(self._is_external_path_expr(child, tainted_vars) for child in ast.iter_child_nodes(node))

    def _check_unchecked_coercion(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        coercion_funcs = {"int", "float", "str", "bool", "list", "dict", "tuple", "set"}
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                if child.func.id in coercion_funcs and child.args:
                    arg_name = self._get_name(child.args[0])
                    if arg_name and not self._has_guard_before(
                        node, child.lineno, ["isinstance", "try:"]
                    ):
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"type({arg_name}) is convertible to {child.func.id}",
                                variables=(arg_name,),
                                anchor_lines=(child.lineno,),
                                natural_language=(
                                    f"Type coercion {child.func.id}({arg_name}) at line "
                                    f"{child.lineno} without type check — may raise ValueError/TypeError."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.BELIEF,
                            logic_type=LogicType.FOL,
                            confidence_score=0.82,
                        ))
        return beliefs

    def _check_missing_timeout(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        timeout_needed = {"get", "post", "put", "delete", "request", "urlopen",
                          "connect", "recv", "send", "read"}
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name and any(t in call_name.lower() for t in timeout_needed):
                    # Check if timeout is in keyword args
                    has_timeout = any(
                        kw.arg == "timeout" for kw in child.keywords
                    )
                    if not has_timeout:
                        beliefs.append(Belief(
                            predicate=Predicate(
                                expression=f"{call_name}() responds within reasonable time",
                                variables=(call_name,),
                                anchor_lines=(child.lineno,),
                                natural_language=(
                                    f"Call to '{call_name}()' at line {child.lineno} "
                                    f"has no timeout — developer assumes it responds promptly."
                                ),
                            ),
                            scope=scope,
                            justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                            epistemic_status=EpistemicStatus.HOPE,
                            logic_type=LogicType.TEMPORAL,
                            confidence_score=0.88,
                        ))
        return beliefs

    def _check_shared_state_mutation(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        for child in ast.walk(node):
            if isinstance(child, ast.Global) or isinstance(child, ast.Nonlocal):
                for name in child.names:
                    beliefs.append(Belief(
                        predicate=Predicate(
                            expression=f"concurrent_access({name}) == False",
                            variables=(name,),
                            anchor_lines=(child.lineno,),
                            natural_language=(
                                f"Function '{node.name}' mutates {'global' if isinstance(child, ast.Global) else 'nonlocal'} "
                                f"variable '{name}' — assumes no concurrent access."
                            ),
                        ),
                        scope=scope,
                        justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                        epistemic_status=EpistemicStatus.BELIEF,
                        logic_type=LogicType.TEMPORAL,
                        confidence_score=0.85,
                    ))
        return beliefs

    def _check_float_equality(
        self, node: ast.FunctionDef, scope: Scope
    ) -> list[Belief]:
        beliefs = []
        for child in ast.walk(node):
            if isinstance(child, ast.Compare):
                for op in child.ops:
                    if isinstance(op, (ast.Eq, ast.NotEq)):
                        # Check if any comparator involves float
                        all_nodes = [child.left] + child.comparators
                        for n in all_nodes:
                            if isinstance(n, ast.Constant) and isinstance(n.value, float):
                                beliefs.append(Belief(
                                    predicate=Predicate(
                                        expression="float_comparison.precision_is_exact == True",
                                        variables=(),
                                        anchor_lines=(child.lineno,),
                                        natural_language=(
                                            f"Floating-point equality comparison at line "
                                            f"{child.lineno} — developer assumes exact precision."
                                        ),
                                    ),
                                    scope=scope,
                                    justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                                    epistemic_status=EpistemicStatus.BELIEF,
                                    logic_type=LogicType.FOL,
                                    confidence_score=0.93,
                                ))
                                break
        return beliefs

    # ── Helpers ──

    def _get_name(self, node: ast.AST) -> Optional[str]:
        """Extract a readable name from an AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        if isinstance(node, ast.Subscript):
            return self._get_name(node.value)
        return None

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        return self._get_name(node.func)

    def _has_guard_before(
        self,
        func_node: ast.FunctionDef,
        target_line: int,
        patterns: list[str],
    ) -> bool:
        """Check if any guard pattern appears before target_line in the function."""
        # Walk the AST looking for guard patterns before the target line
        for child in ast.walk(func_node):
            if not hasattr(child, "lineno"):
                continue
            if child.lineno >= target_line:
                continue

            # Check for assert statements
            if isinstance(child, ast.Assert):
                return True

            # Check for if statements that test relevant conditions
            if isinstance(child, ast.If):
                test_str = ast.dump(child.test).lower()
                for pattern in patterns:
                    if pattern.lower().replace(" ", "") in test_str.replace(" ", ""):
                        return True

            # Check for try/except
            if isinstance(child, ast.Try):
                return True

        return False
