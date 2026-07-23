"""
BELIEF — Security-specific structural patterns.

Extends the base StructuralExtractor with security-focused patterns
inspired by Semgrep's security ruleset. Each pattern generates beliefs
about security assumptions in the code.
"""

from __future__ import annotations

import ast
import re
import logging

from .models import (
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)

logger = logging.getLogger("belief.structural.security")

_UNKNOWN = object()


class SecurityPatternExtractor:
    """
    Extracts security-specific beliefs from Python source code.
    Each pattern corresponds to a class of vulnerability and generates
    beliefs about what the developer assumes regarding security.
    """

    def extract(self, source_code: str, file_path: str = "",
                module: str = "") -> list[Belief]:
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        beliefs = []
        module_scope = Scope(
            file_path=file_path, module=module,
            line_start=1, line_end=len(source_code.splitlines()),
        )
        beliefs.extend(self._check_module_dynamic_code_execution(tree, module_scope))

        class_names: dict[int, str] = {}
        for class_node in ast.walk(tree):
            if not isinstance(class_node, ast.ClassDef):
                continue
            for child in class_node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    class_names[id(child)] = class_node.name

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                scope = Scope(
                    file_path=file_path, function_name=node.name,
                    class_name=class_names.get(id(node)),
                    module=module, line_start=node.lineno,
                    line_end=node.end_lineno,
                )
                beliefs.extend(self._check_sql_injection(node, scope, source_code))
                beliefs.extend(self._check_command_injection(node, scope, source_code))
                beliefs.extend(self._check_dynamic_code_execution(node, scope))
                beliefs.extend(self._check_deserialization(node, scope))
                beliefs.extend(self._check_weak_crypto(node, scope))
                beliefs.extend(self._check_ssrf(node, scope))
                beliefs.extend(self._check_path_traversal(node, scope))
                beliefs.extend(self._check_xss(node, scope, source_code))
                beliefs.extend(self._check_hardcoded_credentials(node, scope, source_code))
                beliefs.extend(self._check_insecure_random(node, scope))
                beliefs.extend(self._check_tls_verify_disabled(node, scope))
                beliefs.extend(self._check_debug_enabled(node, scope, source_code))
                beliefs.extend(self._check_cors_wildcard(node, scope, source_code))
                beliefs.extend(self._check_jwt_none_alg(node, scope, source_code))

        return beliefs

    def _check_sql_injection(self, node: ast.FunctionDef, scope: Scope,
                             source: str) -> list[Belief]:
        """Detect string formatting in SQL queries (CWE-89)."""
        beliefs = []
        self._get_func_source(node, source)

        # f-string or .format() in execute() calls
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and any(x in name.lower() for x in ["execute", "raw", "query"]):
                    for arg in child.args:
                        if isinstance(arg, ast.JoinedStr):  # f-string
                            beliefs.append(self._make_belief(
                                "sql_query.is_parameterized == True",
                                f"SQL query built with f-string at line {child.lineno} — "
                                f"vulnerable to SQL injection (CWE-89).",
                                scope, child.lineno, "critical", "CWE-89",
                            ))
                        elif isinstance(arg, ast.BinOp) and isinstance(arg.op, (ast.Add, ast.Mod)):
                            beliefs.append(self._make_belief(
                                "sql_query.is_parameterized == True",
                                f"SQL query built with string concatenation/formatting at line {child.lineno} — "
                                f"vulnerable to SQL injection (CWE-89).",
                                scope, child.lineno, "critical", "CWE-89",
                            ))
        return beliefs

    def _check_command_injection(self, node: ast.FunctionDef, scope: Scope,
                                 source: str) -> list[Belief]:
        """Detect user-controlled shell command execution (CWE-78)."""
        beliefs = []
        tainted_vars, constant_vars = self._simple_assignment_facts(node)
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if not name:
                    continue

                # os.system
                if "os.system" in name or "os.popen" in name:
                    if not child.args or not self._command_arg_is_user_controlled(
                        child.args[0], tainted_vars, constant_vars,
                    ):
                        continue
                    beliefs.append(self._make_belief(
                        "command.input.is_sanitized == True",
                        f"os.system/popen at line {child.lineno} — "
                        f"vulnerable to command injection (CWE-78).",
                        scope, child.lineno, "critical", "CWE-78",
                    ))

                # subprocess with shell=True
                if "subprocess" in name:
                    for kw in child.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            if child.args and not self._command_arg_is_user_controlled(
                                child.args[0], tainted_vars, constant_vars,
                            ):
                                continue
                            beliefs.append(self._make_belief(
                                "command.shell_disabled == True",
                                f"subprocess with shell=True at line {child.lineno} — "
                                f"vulnerable to command injection (CWE-78).",
                                scope, child.lineno, "high", "CWE-78",
                            ))
        return beliefs

    def _simple_assignment_facts(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[set[str], dict[str, object]]:
        tainted_vars = self._initial_user_controlled_vars(node)
        constant_vars: dict[str, object] = {}
        for stmt in ast.walk(node):
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            if value is None:
                continue
            for target in targets:
                target_name = self._get_name(target)
                if not target_name:
                    continue
                constant_value = self._literal_constant_value(value, constant_vars)
                if constant_value is not _UNKNOWN:
                    constant_vars[target_name] = constant_value
                    tainted_vars.discard(target_name)
                elif self._is_user_controlled_expr(value, tainted_vars, constant_vars):
                    constant_vars.pop(target_name, None)
                    tainted_vars.add(target_name)
                else:
                    constant_vars.pop(target_name, None)
                    tainted_vars.discard(target_name)
        return tainted_vars, constant_vars

    def _command_arg_is_user_controlled(
        self,
        node: ast.AST,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> bool:
        if self._literal_constant_value(node, constant_vars) is not _UNKNOWN:
            return False
        return self._is_user_controlled_expr(node, tainted_vars, constant_vars)

    def _check_module_dynamic_code_execution(
        self,
        tree: ast.Module,
        scope: Scope,
    ) -> list[Belief]:
        return self._scan_dynamic_code_statements(
            tree.body, scope, set(), {},
        )

    def _check_dynamic_code_execution(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect user-controlled Python eval/exec/compile usage (CWE-95)."""
        tainted_vars = self._initial_user_controlled_vars(node)
        constant_vars: dict[str, object] = {}
        return self._scan_dynamic_code_statements(
            node.body, scope, tainted_vars, constant_vars,
        )

    def _scan_dynamic_code_statements(
        self,
        statements: list[ast.stmt],
        scope: Scope,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> list[Belief]:
        beliefs: list[Belief] = []

        for stmt in statements:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue

            if isinstance(stmt, ast.Assign):
                beliefs.extend(self._scan_dynamic_code_calls(
                    stmt.value, scope, tainted_vars, constant_vars,
                ))
                for target in stmt.targets:
                    self._apply_dynamic_assignment(
                        target, stmt.value, tainted_vars, constant_vars,
                    )
                continue

            if isinstance(stmt, ast.AnnAssign):
                if stmt.value is not None:
                    beliefs.extend(self._scan_dynamic_code_calls(
                        stmt.value, scope, tainted_vars, constant_vars,
                    ))
                    self._apply_dynamic_assignment(
                        stmt.target, stmt.value, tainted_vars, constant_vars,
                    )
                continue

            if isinstance(stmt, ast.AugAssign):
                beliefs.extend(self._scan_dynamic_code_calls(
                    stmt.value, scope, tainted_vars, constant_vars,
                ))
                target_name = self._get_name(stmt.target)
                if target_name:
                    constant_vars.pop(target_name, None)
                    if (
                        target_name in tainted_vars
                        or self._is_user_controlled_expr(
                            stmt.value, tainted_vars, constant_vars,
                        )
                    ):
                        tainted_vars.add(target_name)
                    else:
                        tainted_vars.discard(target_name)
                continue

            if isinstance(stmt, ast.If):
                beliefs.extend(self._scan_dynamic_code_calls(
                    stmt.test, scope, tainted_vars, constant_vars,
                ))
                beliefs.extend(self._scan_dynamic_code_branch(
                    stmt.body, stmt.orelse, scope, tainted_vars, constant_vars,
                ))
                continue

            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                beliefs.extend(self._scan_dynamic_code_calls(
                    stmt.iter, scope, tainted_vars, constant_vars,
                ))
                target_name = self._get_name(stmt.target)
                if target_name:
                    tainted_vars.add(target_name)
                    constant_vars.pop(target_name, None)
                beliefs.extend(self._scan_dynamic_code_statements(
                    stmt.body + stmt.orelse, scope, tainted_vars, constant_vars,
                ))
                continue

            if isinstance(stmt, ast.While):
                beliefs.extend(self._scan_dynamic_code_calls(
                    stmt.test, scope, tainted_vars, constant_vars,
                ))
                beliefs.extend(self._scan_dynamic_code_statements(
                    stmt.body + stmt.orelse, scope, tainted_vars, constant_vars,
                ))
                continue

            if isinstance(stmt, (ast.With, ast.AsyncWith)):
                for item in stmt.items:
                    beliefs.extend(self._scan_dynamic_code_calls(
                        item.context_expr, scope, tainted_vars, constant_vars,
                    ))
                    if item.optional_vars:
                        target_name = self._get_name(item.optional_vars)
                        if target_name:
                            tainted_vars.discard(target_name)
                            constant_vars.pop(target_name, None)
                beliefs.extend(self._scan_dynamic_code_statements(
                    stmt.body, scope, tainted_vars, constant_vars,
                ))
                continue

            if isinstance(stmt, ast.Try):
                beliefs.extend(self._scan_dynamic_code_statements(
                    stmt.body, scope, tainted_vars, constant_vars,
                ))
                for handler in stmt.handlers:
                    beliefs.extend(self._scan_dynamic_code_statements(
                        handler.body, scope, tainted_vars, constant_vars,
                    ))
                beliefs.extend(self._scan_dynamic_code_statements(
                    stmt.orelse + stmt.finalbody, scope, tainted_vars, constant_vars,
                ))
                continue

            beliefs.extend(self._scan_dynamic_code_calls(
                stmt, scope, tainted_vars, constant_vars,
            ))

        return beliefs

    def _scan_dynamic_code_branch(
        self,
        body: list[ast.stmt],
        orelse: list[ast.stmt],
        scope: Scope,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> list[Belief]:
        body_tainted = set(tainted_vars)
        body_constants = dict(constant_vars)
        else_tainted = set(tainted_vars)
        else_constants = dict(constant_vars)

        beliefs = self._scan_dynamic_code_statements(
            body, scope, body_tainted, body_constants,
        )
        beliefs.extend(self._scan_dynamic_code_statements(
            orelse, scope, else_tainted, else_constants,
        ))

        tainted_vars.clear()
        tainted_vars.update(body_tainted | else_tainted)

        constant_vars.clear()
        for name, value in body_constants.items():
            if name in else_constants and else_constants[name] == value:
                constant_vars[name] = value

        return beliefs

    def _scan_dynamic_code_calls(
        self,
        node: ast.AST,
        scope: Scope,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> list[Belief]:
        beliefs: list[Belief] = []
        for child in ast.walk(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if not isinstance(child, ast.Call):
                continue
            belief = self._dynamic_code_belief_for_call(
                child, scope, tainted_vars, constant_vars,
            )
            if belief is not None:
                beliefs.append(belief)
        return beliefs

    def _dynamic_code_belief_for_call(
        self,
        call: ast.Call,
        scope: Scope,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> Belief | None:
        name = self._get_call_name(call)
        if not name:
            return None

        if self._is_eval_or_exec_call(name):
            if not call.args:
                return None
            source_arg = call.args[0]
            if self._literal_constant_value(source_arg, constant_vars) is not _UNKNOWN:
                return None
            if not self._is_user_controlled_expr(source_arg, tainted_vars, constant_vars):
                return None
            short_name = name.rsplit(".", 1)[-1]
            return self._make_belief(
                "dynamic_code.input.is_trusted == True",
                f"User-controlled data passed to {short_name}() at line {call.lineno} - "
                f"vulnerable to Python dynamic code execution (CWE-95).",
                scope, call.lineno, "critical", "CWE-95",
            )

        if self._is_compile_call(name):
            if len(call.args) < 3:
                return None
            mode = self._literal_constant_value(call.args[2], constant_vars)
            if mode not in {"exec", "eval"}:
                return None
            source_arg = call.args[0]
            if self._literal_constant_value(source_arg, constant_vars) is not _UNKNOWN:
                return None
            if not self._is_user_controlled_expr(source_arg, tainted_vars, constant_vars):
                return None
            return self._make_belief(
                "dynamic_code.source.is_trusted == True",
                f"User-controlled source passed to compile(..., mode='{mode}') "
                f"at line {call.lineno} - vulnerable to Python dynamic code execution (CWE-95).",
                scope, call.lineno, "critical", "CWE-95",
            )

        return None

    def _apply_dynamic_assignment(
        self,
        target: ast.AST,
        value: ast.AST,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> None:
        target_name = self._get_name(target)
        if not target_name:
            return

        constant_value = self._literal_constant_value(value, constant_vars)
        if constant_value is not _UNKNOWN:
            constant_vars[target_name] = constant_value
            tainted_vars.discard(target_name)
            return

        constant_vars.pop(target_name, None)
        if self._is_user_controlled_expr(value, tainted_vars, constant_vars):
            tainted_vars.add(target_name)
        else:
            tainted_vars.discard(target_name)

    def _initial_user_controlled_vars(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names = {arg.arg for arg in node.args.posonlyargs}
        names.update(arg.arg for arg in node.args.args)
        names.update(arg.arg for arg in node.args.kwonlyargs)
        if node.args.vararg:
            names.add(node.args.vararg.arg)
        if node.args.kwarg:
            names.add(node.args.kwarg.arg)
        return names

    def _is_eval_or_exec_call(self, name: str) -> bool:
        return name in {
            "eval",
            "exec",
            "builtins.eval",
            "builtins.exec",
            "__builtins__.eval",
            "__builtins__.exec",
        }

    def _is_compile_call(self, name: str) -> bool:
        return name in {
            "compile",
            "builtins.compile",
            "__builtins__.compile",
        }

    def _literal_constant_value(
        self,
        node: ast.AST,
        constant_vars: dict[str, object],
    ) -> object:
        if isinstance(node, ast.Name) and node.id in constant_vars:
            return constant_vars[node.id]
        try:
            return ast.literal_eval(node)
        except (ValueError, SyntaxError, TypeError, MemoryError, RecursionError):
            return _UNKNOWN

    def _is_user_controlled_expr(
        self,
        node: ast.AST,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> bool:
        if self._literal_constant_value(node, constant_vars) is not _UNKNOWN:
            return False

        if isinstance(node, ast.Name):
            name = node.id.lower()
            return (
                node.id in tainted_vars
                or name in {
                    "user_input", "userinput", "request", "req", "payload",
                    "body", "data", "query", "params", "headers", "input",
                    "expr", "expression", "code", "source",
                }
                or name.endswith("_input")
            )

        dotted_name = self._get_name(node)
        if dotted_name and self._is_user_controlled_name(dotted_name):
            return True

        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node) or ""
            if self._is_user_input_source_call(call_name):
                return True

        return any(
            self._is_user_controlled_expr(child, tainted_vars, constant_vars)
            for child in ast.iter_child_nodes(node)
        )

    def _is_user_controlled_name(self, name: str) -> bool:
        lowered = name.lower()
        return (
            lowered == "sys.argv"
            or lowered.startswith("sys.argv")
            or lowered == "os.environ"
            or lowered.startswith("os.environ")
            or lowered.startswith("request.")
            or lowered.startswith("req.")
        )

    def _is_user_input_source_call(self, name: str) -> bool:
        lowered = name.lower()
        return (
            lowered == "input"
            or lowered.endswith(".input")
            or lowered in {"getenv", "os.getenv"}
            or lowered.startswith("request.")
            or lowered.startswith("req.")
            or lowered.startswith("os.environ.")
        )

    def _check_deserialization(self, node: ast.FunctionDef, scope: Scope) -> list[Belief]:
        """Detect unsafe deserialization (CWE-502)."""
        beliefs = []
        dangerous_calls = {
            "pickle.loads": ("critical", "pickle deserialization"),
            "pickle.load": ("critical", "pickle deserialization"),
            "yaml.load": ("high", "YAML deserialization without SafeLoader"),
            "yaml.unsafe_load": ("critical", "unsafe YAML deserialization"),
            "marshal.loads": ("critical", "marshal deserialization"),
            "shelve.open": ("high", "shelve (uses pickle internally)"),
            "jsonpickle.decode": ("high", "jsonpickle deserialization"),
        }

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if not name:
                    continue

                for dangerous, (severity, desc) in dangerous_calls.items():
                    if dangerous in name:
                        # Check for SafeLoader in yaml.load
                        if "yaml.load" == dangerous:
                            has_safe = any(
                                kw.arg == "Loader" and "Safe" in str(ast.dump(kw.value))
                                for kw in child.keywords
                            )
                            if has_safe:
                                continue

                        beliefs.append(self._make_belief(
                            "deserialized_data.is_trusted == True",
                            f"Unsafe {desc} at line {child.lineno} — "
                            f"attacker-controlled data can execute arbitrary code (CWE-502).",
                            scope, child.lineno, severity, "CWE-502",
                        ))
        return beliefs

    def _check_weak_crypto(self, node: ast.FunctionDef, scope: Scope) -> list[Belief]:
        """Detect weak cryptographic algorithms (CWE-327)."""
        beliefs = []
        # Map of weak algo name to full patterns that indicate actual crypto usage
        weak_patterns = {
            "md5": ["hashlib.md5", "md5(", "MD5.new", "md5_hash", "md5sum"],
            "sha1": ["hashlib.sha1", "sha1(", "SHA1.new", "sha1_hash"],
            "des": ["DES.new", "DES3.new", "des_encrypt", "pyDes", "Crypto.DES"],
            "rc4": ["ARC4", "RC4", "rc4_encrypt"],
            "rc2": ["RC2", "rc2_encrypt"],
            "blowfish": ["Blowfish", "blowfish_encrypt"],
        }

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if not name:
                    continue
                name_lower = name.lower()
                for algo, patterns in weak_patterns.items():
                    if any(p.lower() in name_lower for p in patterns):
                        beliefs.append(self._make_belief(
                            "crypto.algorithm.is_strong == True",
                            f"Weak cryptographic algorithm '{name}' at line {child.lineno} (CWE-327).",
                            scope, child.lineno, "medium", "CWE-327",
                        ))
                        break

            # String constants referencing weak algos (exact match only)
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                val = child.value.lower().strip()
                if val in {"md5", "sha1", "des", "rc4", "rc2", "blowfish", "3des", "des3"}:
                    beliefs.append(self._make_belief(
                        "crypto.algorithm.is_strong == True",
                        f"Weak algorithm '{child.value}' referenced at line {child.lineno} (CWE-327).",
                        scope, child.lineno, "medium", "CWE-327",
                    ))
        return beliefs

    def _check_ssrf(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect potential SSRF (CWE-918)."""
        beliefs = []
        tainted_vars, constant_vars = self._simple_assignment_facts(node)
        fixed_request_vars = self._fixed_request_destination_vars(node, constant_vars)
        http_funcs = {"requests.get", "requests.post", "requests.put",
                      "httpx.get", "httpx.post", "urllib.request.urlopen",
                      "urlopen", "fetch"}

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._get_call_name(child)
            if not name or not any(h in name for h in http_funcs) or not child.args:
                continue
            url_arg = child.args[0]
            if self._is_fixed_request_destination(url_arg, fixed_request_vars):
                continue
            if not self._is_user_controlled_expr(url_arg, tainted_vars, constant_vars):
                continue
            beliefs.append(self._make_belief(
                "url_param.is_validated == True",
                f"HTTP request with user-controlled URL at line {child.lineno} — "
                f"potential SSRF (CWE-918).",
                scope, child.lineno, "high", "CWE-918",
            ))
        return beliefs

    def _fixed_request_destination_vars(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        constant_vars: dict[str, object],
    ) -> set[str]:
        """Return request variables assigned exactly once to a literal destination.

        Treating a name as fixed after one literal assignment is unsound when it
        can be reassigned on another path.  This deliberately recognizes only
        a single local assignment, preferring a false positive to hiding a
        possible user-controlled destination.
        """
        assignments: dict[str, list[ast.AST]] = {}
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
                assignments.setdefault(target_name, []).append(value)
        return {
            name
            for name, values in assignments.items()
            if len(values) == 1 and self._is_fixed_url_request(values[0], constant_vars)
        }

    def _is_fixed_url_request(
        self,
        node: ast.AST,
        constant_vars: dict[str, object],
    ) -> bool:
        if not isinstance(node, ast.Call) or not node.args:
            return False
        call_name = self._get_call_name(node)
        if call_name not in {"urllib.request.Request", "Request"}:
            return False
        return isinstance(self._literal_constant_value(node.args[0], constant_vars), str)

    @staticmethod
    def _is_fixed_request_destination(node: ast.AST, fixed_request_vars: set[str]) -> bool:
        return isinstance(node, ast.Name) and node.id in fixed_request_vars

    def _check_path_traversal(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect path operations reached from likely external path input (CWE-22)."""
        beliefs = []
        tainted_vars, constant_vars = self._path_assignment_facts(node)
        path_sinks = {
            "open",
            "builtins.open",
            "io.open",
            "os.open",
            "Path",
            "pathlib.Path",
            "os.path.join",
        }
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._get_call_name(child)
            if name not in path_sinks:
                continue
            source_arg = next(
                (
                    arg for arg in child.args
                    if self._is_path_controlled_expr(arg, tainted_vars, constant_vars)
                ),
                None,
            )
            if source_arg is None:
                continue
            source_name = self._get_name(source_arg) or "external path input"
            beliefs.append(self._make_belief(
                f"{source_name} not in PATH_TRAVERSAL",
                f"File operation with externally controlled path at line {child.lineno} — "
                f"potential path traversal (CWE-22).",
                scope, child.lineno, "high", "CWE-22",
                variables=(source_name,),
            ))
        return beliefs

    def _path_assignment_facts(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[set[str], dict[str, object]]:
        """Track obvious external path data without tainting every function argument.

        General command analysis treats parameters as potentially untrusted.  That is
        useful for a shell sink, but overly broad for filesystem operations: internal
        helpers commonly receive ``output_dir`` or ``root``.  Path traversal keeps a
        smaller, explainable seed set and follows only simple local aliases.
        """
        tainted_vars = self._initial_path_controlled_vars(node)
        constant_vars: dict[str, object] = {}
        for stmt in ast.walk(node):
            if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
                continue
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value = stmt.value
            if value is None:
                continue
            for target in targets:
                target_name = self._get_name(target)
                if not target_name:
                    continue
                constant_value = self._literal_constant_value(value, constant_vars)
                if constant_value is not _UNKNOWN:
                    constant_vars[target_name] = constant_value
                    tainted_vars.discard(target_name)
                elif self._is_path_controlled_expr(value, tainted_vars, constant_vars):
                    constant_vars.pop(target_name, None)
                    tainted_vars.add(target_name)
                else:
                    constant_vars.pop(target_name, None)
                    tainted_vars.discard(target_name)
        return tainted_vars, constant_vars

    def _initial_path_controlled_vars(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> set[str]:
        names = {arg.arg for arg in node.args.posonlyargs}
        names.update(arg.arg for arg in node.args.args)
        names.update(arg.arg for arg in node.args.kwonlyargs)
        if node.args.vararg:
            names.add(node.args.vararg.arg)
        if node.args.kwarg:
            names.add(node.args.kwarg.arg)
        return {name for name in names if self._is_likely_external_path_name(name)}

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

    def _is_path_controlled_expr(
        self,
        node: ast.AST,
        tainted_vars: set[str],
        constant_vars: dict[str, object],
    ) -> bool:
        if self._literal_constant_value(node, constant_vars) is not _UNKNOWN:
            return False
        if isinstance(node, ast.Name):
            return node.id in tainted_vars or self._is_likely_external_path_name(node.id)
        dotted_name = self._get_name(node)
        if dotted_name and self._is_user_controlled_name(dotted_name):
            return True
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node) or ""
            if self._is_user_input_source_call(call_name):
                return True
        return any(
            self._is_path_controlled_expr(child, tainted_vars, constant_vars)
            for child in ast.iter_child_nodes(node)
        )

    def _check_xss(self, node: ast.FunctionDef, scope: Scope,
                   source: str) -> list[Belief]:
        """Detect potential XSS (CWE-79)."""
        beliefs = []
        xss_sinks = {"render_template_string", "Markup", "mark_safe",
                     "format_html", "innerHTML", "document.write"}

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and any(s in name for s in xss_sinks):
                    variables = tuple(dict.fromkeys(
                        candidate.id
                        for argument in [
                            *child.args,
                            *(keyword.value for keyword in child.keywords),
                        ]
                        for candidate in ast.walk(argument)
                        if isinstance(candidate, ast.Name)
                    ))
                    beliefs.append(self._make_belief(
                        "html_output.is_escaped == True",
                        f"Unescaped HTML output via '{name}' at line {child.lineno} (CWE-79).",
                        scope, child.lineno, "high", "CWE-79",
                        variables=variables,
                    ))
        return beliefs

    def _check_hardcoded_credentials(self, node: ast.FunctionDef, scope: Scope,
                                     source: str) -> list[Belief]:
        """Detect hardcoded passwords/keys (CWE-798)."""
        beliefs = []
        func_src = self._get_func_source(node, source)

        patterns = [
            re.compile(r"""(?:password|passwd|secret|token|api_key)\s*=\s*['"][^'"]{4,}['"]""", re.IGNORECASE),
            re.compile(r"""['"](?:sk-|pk-|ghp_|gho_|aws_|AKIA)[a-zA-Z0-9]{10,}['"]"""),
        ]

        for pattern in patterns:
            match = pattern.search(func_src)
            if match:
                beliefs.append(self._make_belief(
                    "credentials.stored_securely == True",
                    f"Hardcoded credential at line ~{node.lineno} (CWE-798).",
                    scope, node.lineno, "high", "CWE-798",
                ))
                break
        return beliefs

    def _check_insecure_random(self, node: ast.FunctionDef, scope: Scope) -> list[Belief]:
        """Detect insecure randomness for security contexts (CWE-330)."""
        beliefs = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and "random." in name and "secrets" not in name and "os.urandom" not in name:
                    # Check if function name suggests security context
                    fn_name = (node.name or "").lower()
                    security_ctx = any(x in fn_name for x in [
                        "token", "secret", "key", "password", "auth",
                        "hash", "salt", "nonce", "session", "csrf",
                    ])
                    if security_ctx:
                        beliefs.append(self._make_belief(
                            "random.is_cryptographic == True",
                            f"Non-cryptographic random in security context at line {child.lineno} (CWE-330).",
                            scope, child.lineno, "high", "CWE-330",
                        ))
        return beliefs

    def _check_tls_verify_disabled(self, node: ast.FunctionDef, scope: Scope) -> list[Belief]:
        """Detect disabled TLS certificate verification (CWE-295)."""
        beliefs = []
        http_calls = {
            "requests.get", "requests.post", "requests.put", "requests.delete",
            "requests.request", "requests.Session.get", "requests.Session.post",
            "httpx.get", "httpx.post", "httpx.put", "httpx.delete", "httpx.request",
        }
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._get_call_name(child)
            if not name or not any(pattern in name for pattern in http_calls):
                continue
            for kw in child.keywords:
                if (
                    kw.arg == "verify"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                ):
                    beliefs.append(self._make_belief(
                        "tls.certificate_verified == True",
                        f"TLS certificate verification disabled at line {child.lineno} (CWE-295).",
                        scope, child.lineno, "high", "CWE-295",
                    ))
                    break
        return beliefs

    def _check_debug_enabled(self, node: ast.FunctionDef, scope: Scope,
                             source: str) -> list[Belief]:
        """Detect debug mode left enabled (CWE-489)."""
        beliefs = []
        func_src = self._get_func_source(node, source)
        if re.search(r"debug\s*=\s*True", func_src, re.IGNORECASE):
            beliefs.append(self._make_belief(
                "app.debug == False",
                f"Debug mode enabled in function '{node.name}' (CWE-489).",
                scope, node.lineno, "medium", "CWE-489",
            ))
        return beliefs

    def _check_cors_wildcard(self, node: ast.FunctionDef, scope: Scope,
                             source: str) -> list[Belief]:
        """Detect CORS wildcard (CWE-942)."""
        beliefs = []
        func_src = self._get_func_source(node, source)
        if re.search(r"""['"]Access-Control-Allow-Origin['"]\s*[,:]\s*['"]?\*""", func_src):
            beliefs.append(self._make_belief(
                "cors.origin == 'restricted'",
                f"CORS wildcard (*) in function '{node.name}' (CWE-942).",
                scope, node.lineno, "medium", "CWE-942",
            ))
        return beliefs

    def _check_jwt_none_alg(self, node: ast.FunctionDef, scope: Scope,
                            source: str) -> list[Belief]:
        """Detect JWT without algorithm verification (CWE-347)."""
        beliefs = []
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if name and "jwt.decode" in name:
                    has_algorithms = any(kw.arg == "algorithms" for kw in child.keywords)
                    any(
                        kw.arg in ("verify", "options") for kw in child.keywords
                    )
                    if not has_algorithms:
                        beliefs.append(self._make_belief(
                            "jwt.algorithm.verified == True",
                            f"JWT decode without algorithms parameter at line {child.lineno} (CWE-347).",
                            scope, child.lineno, "high", "CWE-347",
                        ))
        return beliefs

    # ── Helpers ──

    def _make_belief(self, expr: str, desc: str, scope: Scope,
                     lineno: int, severity: str, cwe: str,
                     variables: tuple[str, ...] = ()) -> Belief:
        confidence = {"critical": 0.95, "high": 0.88, "medium": 0.78}.get(severity, 0.7)
        return Belief(
            predicate=Predicate(
                expression=expr, variables=variables,
                anchor_lines=(lineno,),
                natural_language=f"{desc}",
            ),
            scope=scope,
            justification=JustificationCategory.C5_NO_JUSTIFICATION,
            epistemic_status=EpistemicStatus.BELIEF,
            logic_type=LogicType.INFORMATION_FLOW,
            confidence_score=confidence,
            cwe=cwe,
            source_metadata={
                "source": "security_patterns",
                "rule_id": cwe,
                "severity": severity,
            },
        )

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            base = self._get_name(node.func.value)
            if base:
                return f"{base}.{node.func.attr}"
            return node.func.attr
        return None

    def _get_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return None

    def _get_func_source(self, node: ast.FunctionDef, full_source: str) -> str:
        lines = full_source.split("\n")
        start = node.lineno - 1
        end = node.end_lineno or (start + 1)
        return "\n".join(lines[start:end])
