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
SECURITY_ANALYSIS_PROFILES = ("default", "patch_review")

_PATCH_PATH_STRONG_SANITIZERS = {
    "basename",
    "cleanup_path",
    "secure_filename",
}
_PATCH_PATH_GUARD_CALLS = {
    "_is_valid_path",
    "clean_path",
    "is_path_child_of",
    "is_safe_path",
    "safe_join",
    "validate_path",
}
_PATCH_PATH_CANONICALIZERS = {
    "unquote",
    "unquote_plus",
}
_PATCH_PATH_CANONICALIZER_FUNCTIONS = {
    "abspath",
    "normpath",
    "realpath",
    "resolve",
}
_PATCH_PATH_SINK_SUFFIXES = {
    "exists",
    "fopen",
    "isdir",
    "isfile",
    "lstat",
    "open",
    "remove",
    "rmtree",
    "send_file",
    "send_from_directory",
    "serve_file",
    "stat",
    "staticdir",
    "staticfile",
    "unlink",
}
_PATCH_AUTHORIZATION_CALLS = {
    "authorize",
    "can_access",
    "check_authorization",
    "check_permission",
    "has_object_permission",
    "has_perm",
    "has_permission",
    "is_authorized",
    "user_allowed",
}
_PATCH_ACCESS_REJECTION_CALLS = {
    "abort",
    "deny",
    "forbidden",
    "handle_no_permission",
}
_PATCH_SQL_FRAGMENT_NAMES = {
    "alias",
    "aliases",
    "field",
    "fields",
    "kind",
    "lookup_name",
    "options",
    "ordering",
    "savepoint_name",
}
_PATCH_SQL_VALIDATORS = {
    "check_alias",
    "escape",
    "fullmatch",
    "isidentifier",
    "issubset",
    "match",
    "quote",
    "quote_name",
    "search",
    "validate_identifier",
    "validate_savepoint_name",
    "validate_sql_identifier",
}
_PATCH_XSS_SINKS = {
    "finish",
    "httpresponse",
    "markup",
    "mark_safe",
    "render_template_string",
    "write",
}
_PATCH_XSS_SANITIZERS = {
    "clean",
    "conditional_escape",
    "escape",
    "format_html",
    "html_escape",
    "sanitize",
    "sanitize_html",
}
_PATCH_SAFE_URL_SCHEMES = frozenset({"http", "https"})
_PATCH_URL_ATTRIBUTE_PREFIX = re.compile(
    r"(?:action|formaction|href|src)\s*=\s*([\"'])[^\"']*$",
    re.IGNORECASE,
)


class SecurityPatternExtractor:
    """
    Extracts security-specific beliefs from Python source code.
    Each pattern corresponds to a class of vulnerability and generates
    beliefs about what the developer assumes regarding security.
    """

    def __init__(self, analysis_profile: str = "default") -> None:
        normalized = str(analysis_profile or "default").strip().lower()
        if normalized not in SECURITY_ANALYSIS_PROFILES:
            accepted = ", ".join(SECURITY_ANALYSIS_PROFILES)
            raise ValueError(
                f"invalid security analysis profile: {analysis_profile}. "
                f"Accepted: {accepted}"
            )
        self.analysis_profile = normalized

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
        escaped_substitution_callbacks = (
            _escaped_regex_substitution_callbacks(tree)
            if self.analysis_profile == "patch_review"
            else {}
        )
        if self.analysis_profile == "patch_review":
            beliefs.extend(
                self._check_patch_boundary_view_access(tree, module_scope)
            )
            beliefs.extend(
                self._check_patch_proxy_route_authority(tree, module_scope)
            )
            beliefs.extend(
                self._check_patch_unsafe_xml_parsing(tree, module_scope)
            )
            beliefs.extend(
                self._check_patch_redirect_header_injection(tree, module_scope)
            )
            beliefs.extend(
                self._check_patch_boundary_option_injection(tree, module_scope)
            )

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
                if self.analysis_profile == "patch_review":
                    beliefs.extend(
                        self._check_patch_boundary_path_traversal(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_authorization_context(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_identifier_override(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_sql_fragments(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_interpreter_fragment(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_reflected_output(
                            node,
                            scope,
                            escaped_boundary_sources=(
                                escaped_substitution_callbacks.get(id(node), set())
                            ),
                        )
                    )
                    beliefs.extend(
                        self._check_patch_boundary_tls_context(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_crypto_size(node, scope)
                    )
                    beliefs.extend(
                        self._check_patch_boundary_signature_configuration(node, scope)
                    )
                else:
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
                        if (
                            self.analysis_profile == "patch_review"
                            and _sql_expression_has_validated_fragments(node, arg)
                        ):
                            continue
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
        boundary_parameters = (
            _function_parameter_names(node) - {"self", "cls"}
            if self.analysis_profile == "patch_review"
            else set()
        )
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
                    if _command_boundary_is_validated(
                        node,
                        boundary_parameters,
                    ):
                        continue
                    variables, metadata = _patch_command_evidence(
                        self.analysis_profile,
                        boundary_parameters,
                        name,
                        child.lineno,
                        scope.line_start,
                    )
                    beliefs.append(self._make_belief(
                        "command.input.is_sanitized == True",
                        f"os.system/popen at line {child.lineno} — "
                        f"vulnerable to command injection (CWE-78).",
                        scope, child.lineno, "critical", "CWE-78",
                        variables=variables,
                        metadata=metadata,
                    ))

                # subprocess with shell=True
                if "subprocess" in name:
                    for kw in child.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            if child.args and not self._command_arg_is_user_controlled(
                                child.args[0], tainted_vars, constant_vars,
                            ):
                                continue
                            if _command_boundary_is_validated(
                                node,
                                boundary_parameters,
                            ):
                                continue
                            variables, metadata = _patch_command_evidence(
                                self.analysis_profile,
                                boundary_parameters,
                                name,
                                child.lineno,
                                scope.line_start,
                            )
                            beliefs.append(self._make_belief(
                                "command.shell_disabled == True",
                                f"subprocess with shell=True at line {child.lineno} — "
                                f"vulnerable to command injection (CWE-78).",
                                scope, child.lineno, "high", "CWE-78",
                                variables=variables,
                                metadata=metadata,
                            ))
        return beliefs

    def _simple_assignment_facts(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> tuple[set[str], dict[str, object]]:
        tainted_vars = self._initial_user_controlled_vars(node)
        if self.analysis_profile == "patch_review":
            tainted_vars.update(
                _function_parameter_names(node) - {"self", "cls"}
            )
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

    def _check_patch_boundary_path_traversal(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Trace path-like boundary parameters during an explicit patch review.

        The default scanner deliberately avoids treating every ``path`` or
        ``name`` parameter as hostile. A changed function is a narrower trust
        boundary: patch review may conservatively follow path-like parameters,
        while still requiring a concrete filesystem use or returned path.
        """

        boundary_sources = {
            name
            for name in _function_parameter_names(node)
            if _is_patch_path_parameter(name)
        }
        if not boundary_sources:
            return []
        normalized_function = node.name.lower().lstrip("_")
        if normalized_function in {
            *_PATCH_PATH_STRONG_SANITIZERS,
            *_PATCH_PATH_GUARD_CALLS,
            *_PATCH_PATH_CANONICALIZER_FUNCTIONS,
        }:
            return []
        tainted = set(boundary_sources)

        guarded: set[str] = set()
        canonicalized: set[str] = set()
        containment_aliases: dict[str, set[str]] = {}
        lineage = {name: {name} for name in tainted}
        direct_statement_ids = {id(statement) for statement in node.body}
        validation_line = _incomplete_path_validation_line(node, tainted)
        beliefs: list[Belief] = []
        emitted: set[tuple[int, tuple[str, ...]]] = set()

        if validation_line is not None:
            beliefs.append(
                self._patch_path_belief(
                    scope,
                    line=validation_line,
                    sources=tainted,
                    sink="path validation",
                    reason=(
                        "Path validation inspects traversal syntax before URL "
                        "canonicalization"
                    ),
                )
            )
            emitted.add((validation_line, tuple(sorted(tainted))))

        for event in _ordered_function_events(node):
            if isinstance(event, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets, value = _assignment_parts(event)
                if not targets or value is None:
                    continue
                source_names = _referenced_names(value) & tainted
                call_name = _expression_call_name(value)
                short_call = call_name.rsplit(".", 1)[-1].lower()
                definitely_assigned = (
                    targets
                    if id(event) in direct_statement_ids
                    else targets - boundary_sources
                )

                if short_call in _PATCH_PATH_STRONG_SANITIZERS and source_names:
                    tainted.difference_update(definitely_assigned)
                    guarded.difference_update(definitely_assigned)
                    canonicalized.difference_update(definitely_assigned)
                    for target in definitely_assigned:
                        containment_aliases.pop(target, None)
                        lineage.pop(target, None)
                    continue

                if source_names:
                    origins = {
                        origin
                        for source_name in source_names
                        for origin in lineage.get(source_name, {source_name})
                    }
                    tainted.update(targets)
                    for target in targets:
                        lineage[target] = set(origins)
                    if source_names <= guarded:
                        guarded.update(targets)
                    else:
                        guarded.difference_update(targets)
                    if short_call in _PATCH_PATH_CANONICALIZERS:
                        canonicalized.update(targets)
                    elif source_names <= canonicalized:
                        canonicalized.update(targets)
                    else:
                        canonicalized.difference_update(targets)
                else:
                    tainted.difference_update(definitely_assigned)
                    guarded.difference_update(definitely_assigned)
                    canonicalized.difference_update(definitely_assigned)
                    for target in definitely_assigned:
                        lineage.pop(target, None)

                if short_call == "commonpath" and source_names:
                    for target in targets:
                        containment_aliases[target] = set(source_names)
                else:
                    for target in targets:
                        containment_aliases.pop(target, None)
                continue

            if isinstance(event, ast.If):
                newly_guarded = _rejected_path_guard_sources(
                    event,
                    tainted=tainted,
                    containment_aliases=containment_aliases,
                )
                guarded.update(newly_guarded)
                continue

            if isinstance(event, ast.Assert):
                guarded.update(
                    _asserted_path_guard_sources(
                        event.test,
                        tainted=tainted,
                        containment_aliases=containment_aliases,
                    )
                )
                continue

            if isinstance(event, ast.Call):
                call_name = (self._get_call_name(event) or "").lower()
                short_call = call_name.rsplit(".", 1)[-1]
                sources = _call_path_sources(event, tainted)

                if short_call == "commonprefix" and sources:
                    origins = _origin_path_sources(sources, lineage)
                    key = (event.lineno, tuple(sorted(origins)))
                    if key not in emitted:
                        emitted.add(key)
                        beliefs.append(
                            self._patch_path_belief(
                                scope,
                                line=event.lineno,
                                sources=origins,
                                sink=call_name or "commonprefix",
                                reason=(
                                    "commonprefix compares strings and does not "
                                    "prove path containment"
                                ),
                            )
                        )
                    continue

                if not _is_patch_path_sink(call_name) or not sources:
                    continue
                unguarded = sources - guarded
                if not unguarded:
                    continue
                origins = _origin_path_sources(unguarded, lineage)
                key = (event.lineno, tuple(sorted(origins)))
                if key in emitted:
                    continue
                emitted.add(key)
                beliefs.append(
                    self._patch_path_belief(
                        scope,
                        line=event.lineno,
                        sources=origins,
                        sink=call_name or "filesystem operation",
                        reason="Path-like boundary input reaches a filesystem operation",
                    )
                )
                continue

            if isinstance(event, ast.Return) and event.value is not None:
                if not _function_returns_path_value(node, event.value):
                    continue
                sources = _referenced_names(event.value) & tainted
                unguarded = sources - guarded
                if not unguarded:
                    continue
                origins = _origin_path_sources(unguarded, lineage)
                key = (event.lineno, tuple(sorted(origins)))
                if key in emitted:
                    continue
                emitted.add(key)
                beliefs.append(
                    self._patch_path_belief(
                        scope,
                        line=event.lineno,
                        sources=origins,
                        sink=f"return from {node.name}",
                        reason="Path-like boundary input is returned as an OS path",
                    )
                )

        return beliefs

    def _check_patch_boundary_authorization_context(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect wrappers that authorize a different resource than they invoke."""

        if node.args.kwarg is None:
            return []
        kwargs_name = node.args.kwarg.arg
        if not _forwards_keyword_arguments(node, kwargs_name):
            return []

        assignments = _named_assignments(node)
        for call in ast.walk(node):
            if not isinstance(call, ast.Call) or not _is_authorization_call(call):
                continue
            for resource_name in _authorization_resource_names(call):
                value = assignments.get(resource_name)
                if value is None or not _references_request_context(value):
                    continue
                if kwargs_name in _referenced_names(value):
                    continue
                return [
                    self._make_belief(
                        "authorization.resource_context_complete == true",
                        (
                            f"Authorization at line {call.lineno} derives "
                            f"'{resource_name}' from request state but omits forwarded "
                            "route arguments — potential authorization bypass "
                            "(CWE-863)."
                        ),
                        scope,
                        call.lineno,
                        "high",
                        "CWE-863",
                        variables=(resource_name, kwargs_name),
                        metadata={
                            "analysis_profile": "patch_review",
                            "dataflow": {
                                "source": kwargs_name,
                                "source_line": scope.line_start,
                                "sink": _ast_call_name(call) or "authorization check",
                                "sink_line": call.lineno,
                                "path": [kwargs_name, resource_name, "authorization"],
                                "missing_guarantees": [
                                    "authorized_resource == invoked_resource"
                                ],
                            },
                        },
                    )
                ]
        return []

    def _check_patch_boundary_identifier_override(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect external record identifiers persisted without a field guard."""

        if not _is_record_creation_function(node):
            return []
        boundary_sources = {
            name
            for name in _function_parameter_names(node) - {"self", "cls"}
            if _is_mapping_boundary_name(name)
        }
        if (
            not boundary_sources
            or not _documents_external_identifier(node)
        ):
            return []
        aliases = _flow_aliases(node, boundary_sources)
        sink = next(
            (
                candidate
                for candidate in _ordered_function_events(node)
                if isinstance(candidate, ast.Call)
                and _is_record_persistence_call(candidate)
                and bool(_referenced_names(candidate) & aliases)
            ),
            None,
        )
        if sink is None or _has_external_identifier_guard(
            node,
            aliases,
            before_line=sink.lineno,
        ):
            return []

        source = sorted(boundary_sources)[0]
        sink_name = _ast_call_name(sink) or "record persistence"
        return [
            self._make_belief(
                "record.external_identifier_is_authorized == true",
                (
                    f"Externally supplied record identifier from '{source}' "
                    f"reaches '{sink_name}' at line {sink.lineno} without a "
                    "field-specific privilege, uniqueness, or removal guard "
                    "(CWE-915)."
                ),
                scope,
                sink.lineno,
                "high",
                "CWE-915",
                variables=(source,),
                metadata={
                    "analysis_profile": "patch_review",
                    "dataflow": {
                        "source": source,
                        "source_line": node.lineno,
                        "sink": sink_name,
                        "sink_line": sink.lineno,
                        "path": [source, sink_name],
                        "missing_guarantees": [
                            "record.external_identifier_is_authorized == true"
                        ],
                    },
                },
            )
        ]

    def _check_patch_boundary_sql_fragments(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect unvalidated identifier-like inputs entering SQL builders."""

        context = " ".join(
            (
                scope.file_path,
                scope.class_name or "",
                node.name,
            )
        ).lower()
        if not any(
            token in context
            for token in (
                "database",
                "engine",
                "postgres",
                "query",
                "savepoint",
                "sql",
                "sqlite",
            )
        ):
            return []
        if any(token in node.name.lower() for token in ("check_", "validate_")):
            return []

        parameters = _function_parameter_names(node) - {"self", "cls"}
        fragments = parameters & _PATCH_SQL_FRAGMENT_NAMES
        if "name" in parameters and "savepoint" in context:
            fragments.add("name")
        if not fragments:
            return []

        aliases = _flow_aliases(node, fragments)
        if _sql_fragments_are_validated(node, aliases):
            return []

        source = sorted(fragments)[0]
        sink = (
            f"{scope.class_name}.{node.name}"
            if scope.class_name
            else node.name
        )
        return [
            self._make_belief(
                "sql.fragment_is_validated == true",
                (
                    f"Identifier-like SQL fragment '{source}' enters '{sink}' "
                    "without an allowlist, quoting operation, or full-match "
                    "validation (CWE-89)."
                ),
                scope,
                node.lineno,
                "high",
                "CWE-89",
                variables=tuple(sorted(fragments)),
                metadata={
                    "analysis_profile": "patch_review",
                    "dataflow": {
                        "source": source,
                        "source_line": node.lineno,
                        "sink": sink,
                        "sink_line": node.lineno,
                        "path": [source, sink],
                        "missing_guarantees": [
                            "sql.identifier_matches_allowlist == true"
                        ],
                    },
                },
            )
        ]

    def _check_patch_boundary_interpreter_fragment(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect boundary values embedded in CLI/interpreter script fragments."""

        context = f"{scope.file_path} {scope.class_name or ''} {node.name}".lower()
        if not any(
            token in context
            for token in ("cli", "command", "console", "hive", "script", "shell")
        ):
            return []
        boundary_parameters = _function_parameter_names(node) - {"self", "cls"}
        if not boundary_parameters or _command_boundary_is_validated(
            node,
            boundary_parameters,
        ):
            return []
        for candidate in ast.walk(node):
            if not isinstance(candidate, (ast.JoinedStr, ast.BinOp, ast.Call)):
                continue
            referenced = _referenced_names(candidate) & boundary_parameters
            if not referenced or not _contains_interpreter_delimiter(candidate):
                continue
            source = sorted(referenced)[0]
            return [
                self._make_belief(
                    "interpreter.fragment_is_validated == true",
                    (
                        f"Boundary value '{source}' is embedded in an "
                        f"interpreter/CLI fragment at line {candidate.lineno} "
                        "without abortive delimiter validation (CWE-78)."
                    ),
                    scope,
                    candidate.lineno,
                    "high",
                    "CWE-78",
                    variables=tuple(sorted(referenced)),
                    metadata={
                        "analysis_profile": "patch_review",
                        "dataflow": {
                            "source": source,
                            "source_line": node.lineno,
                            "sink": "interpreter command fragment",
                            "sink_line": candidate.lineno,
                            "path": [source, "interpreter command fragment"],
                            "missing_guarantees": [
                                "command.argument_is_validated == true"
                            ],
                        },
                    },
                )
            ]
        return []

    def _check_patch_boundary_reflected_output(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
        *,
        escaped_boundary_sources: set[str] | None = None,
    ) -> list[Belief]:
        """Trace boundary values into explicit HTML/HTTP output operations."""

        function_name = node.name.lower()
        if any(token in function_name for token in ("escape", "safe", "sanitiz")):
            return []
        escaped_boundary_sources = set(escaped_boundary_sources or ())
        boundary_sources = _function_parameter_names(node) - {"self", "cls"}
        if not boundary_sources:
            return []

        tainted = _flow_aliases(node, boundary_sources)
        lineage = {name: {name} for name in tainted}
        sanitized_containers: set[str] = set()
        direct_statement_ids = {id(statement) for statement in node.body}
        guarded_url_sources: set[str] = set()

        for event in _ordered_function_events(node):
            if isinstance(event, (ast.For, ast.AsyncFor)):
                source_names = _referenced_names(event.iter) & tainted
                if source_names:
                    origins = {
                        origin
                        for source_name in source_names
                        for origin in lineage.get(source_name, {source_name})
                    }
                    for target in _target_names(event.target):
                        tainted.add(target)
                        lineage[target] = set(origins)
                continue

            if isinstance(event, ast.AugAssign):
                targets = _target_names(event.target)
                source_names = _referenced_names(event.value) & tainted
                if source_names or _expression_is_xss_boundary_source(event.value):
                    origins = {
                        origin
                        for source_name in source_names
                        for origin in lineage.get(source_name, {source_name})
                    }
                    if not origins:
                        origins = {"request"}
                    tainted.update(targets)
                    for target in targets:
                        lineage[target] = set(origins)
                continue

            if isinstance(event, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets, value = _assignment_parts(event)
                if value is None:
                    continue
                _record_sanitized_container(
                    event,
                    value,
                    sanitized_containers,
                )
                source_names = _referenced_names(value) & tainted
                definitely_assigned = (
                    targets
                    if id(event) in direct_statement_ids
                    else targets - boundary_sources
                )
                if _expression_has_xss_sanitizer(value):
                    tainted.difference_update(definitely_assigned)
                    for target in definitely_assigned:
                        lineage.pop(target, None)
                elif source_names or _expression_is_xss_boundary_source(value):
                    origins = {
                        origin
                        for source_name in source_names
                        for origin in lineage.get(source_name, {source_name})
                    }
                    if not origins:
                        origins = {"request"}
                    tainted.update(targets)
                    for target in targets:
                        lineage[target] = set(origins)
                else:
                    tainted.difference_update(definitely_assigned)
                    for target in definitely_assigned:
                        lineage.pop(target, None)
                continue

            if not isinstance(event, ast.Call):
                if isinstance(event, ast.If):
                    guarded_url_sources.update(
                        _rejected_url_scheme_sources(
                            event,
                            node=node,
                            before_line=event.lineno,
                        )
                    )
                continue
            sink = _ast_call_name(event)
            short_sink = sink.rsplit(".", 1)[-1].lower()
            if short_sink in {"add", "append", "extend", "insert", "update"}:
                receiver = (
                    _ast_dotted_name(event.func.value)
                    if isinstance(event.func, ast.Attribute)
                    else ""
                )
                receiver_name = receiver.rsplit(".", 1)[-1]
                source_names = {
                    name
                    for value in [
                        *event.args,
                        *(keyword.value for keyword in event.keywords),
                    ]
                    for name in (_referenced_names(value) & tainted)
                }
                if receiver_name and source_names:
                    tainted.add(receiver_name)
                    lineage[receiver_name] = {
                        origin
                        for source_name in source_names
                        for origin in lineage.get(source_name, {source_name})
                    }
                continue
            if short_sink not in _PATCH_XSS_SINKS:
                continue
            if short_sink in {"write", "finish"} and not _is_http_output_context(
                scope
            ):
                continue
            values = [
                *event.args,
                *(keyword.value for keyword in event.keywords),
            ]
            if not values:
                continue
            if (
                short_sink in {"write", "finish"}
                and (
                    forwarded_response_aliases
                    := _forwarded_http_response_aliases(
                        node,
                        before_line=event.lineno,
                    )
                )
                and all(
                    _is_http_response_payload(
                        value,
                        forwarded_response_aliases,
                    )
                    for value in values
                )
            ):
                continue
            sources: set[str] = set()
            for value in values:
                if _expression_has_xss_sanitizer(value):
                    continue
                referenced = _referenced_names(value) & tainted
                referenced -= sanitized_containers
                url_attribute_sources = (
                    _url_attribute_interpolation_names(value)
                )
                for source_name in referenced:
                    origins = lineage.get(source_name, {source_name})
                    from_escaped_callback_input = bool(
                        origins
                        and origins.issubset(escaped_boundary_sources)
                    )
                    if not from_escaped_callback_input:
                        sources.add(source_name)
                        continue
                    if (
                        source_name in url_attribute_sources
                        and source_name not in guarded_url_sources
                    ):
                        sources.add(source_name)
            if not sources:
                continue
            origins = {
                origin
                for source_name in sources
                for origin in lineage.get(source_name, {source_name})
            }
            source = sorted(origins)[0]
            return [
                self._make_belief(
                    "html_output.is_escaped == true",
                    (
                        f"Boundary value '{source}' reaches HTML/HTTP output "
                        f"'{sink}' at line {event.lineno} without a recognized "
                        "escaping or sanitization step (CWE-79)."
                    ),
                    scope,
                    event.lineno,
                    "high",
                    "CWE-79",
                    variables=tuple(sorted(origins)),
                    metadata={
                        "analysis_profile": "patch_review",
                        "dataflow": {
                            "source": source,
                            "source_line": node.lineno,
                            "sink": sink,
                            "sink_line": event.lineno,
                            "path": [source, sink],
                            "missing_guarantees": [
                                "html_output.is_escaped == true"
                            ],
                        },
                    },
                )
            ]
        return []

    def _check_patch_boundary_tls_context(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect a client TLS context used without hostname verification."""

        context = f"{scope.file_path} {scope.class_name or ''} {node.name}".lower()
        if not any(token in context for token in ("connect", "proxy", "ssl", "tls")):
            return []
        tls_calls = [
            candidate
            for candidate in ast.walk(node)
            if isinstance(candidate, ast.Call)
            and _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
            in {
                "create_default_context",
                "create_urllib3_context",
                "ssl_wrap_socket",
                "wrap_socket",
            }
        ]
        if not tls_calls:
            return []
        context_referenced = any(
            any(
                name.lower() in {"context", "ssl_context", "tls_context"}
                for name in _referenced_names(call)
            )
            for call in tls_calls
        )
        if not context_referenced:
            return []
        if _enables_tls_hostname_check(node):
            return []
        sink = _ast_call_name(tls_calls[-1])
        return [
            self._make_belief(
                "tls.hostname_verified == true",
                (
                    f"TLS context reaches '{sink}' at line "
                    f"{tls_calls[-1].lineno} without enabling hostname "
                    "verification (CWE-295)."
                ),
                scope,
                tls_calls[-1].lineno,
                "high",
                "CWE-295",
                variables=("ssl_context",),
                metadata={
                    "analysis_profile": "patch_review",
                    "dataflow": {
                        "source": "ssl_context",
                        "source_line": node.lineno,
                        "sink": sink,
                        "sink_line": tls_calls[-1].lineno,
                        "path": ["ssl_context", sink],
                        "missing_guarantees": [
                            "tls.hostname_verified == true"
                        ],
                    },
                },
            )
        ]

    def _check_patch_boundary_crypto_size(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect cryptographic blocks processed without canonical length checks."""

        context = f"{scope.file_path} {scope.class_name or ''} {node.name}".lower()
        if not any(
            token in context
            for token in ("crypto", "decrypt", "pkcs", "rsa", "signature", "verify")
        ):
            return []
        parameters = _function_parameter_names(node) - {"self", "cls"}
        blocks = parameters & {
            "ciphertext",
            "crypto",
            "digest",
            "signature",
            "signedtext",
        }
        if not blocks or not _has_crypto_block_operation(node, blocks):
            return []
        if _has_abortive_length_guard(node, blocks):
            return []
        source = sorted(blocks)[0]
        return [
            self._make_belief(
                "crypto.block_length_is_canonical == true",
                (
                    f"Cryptographic block '{source}' is processed by "
                    f"'{node.name}' without an abortive length check (CWE-327)."
                ),
                scope,
                node.lineno,
                "high",
                "CWE-327",
                variables=tuple(sorted(blocks)),
                metadata={
                    "analysis_profile": "patch_review",
                    "dataflow": {
                        "source": source,
                        "source_line": node.lineno,
                        "sink": node.name,
                        "sink_line": node.lineno,
                        "path": [source, node.name],
                        "missing_guarantees": [
                            "crypto.block_length_is_canonical == true"
                        ],
                    },
                },
            )
        ]

    def _check_patch_boundary_signature_configuration(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        scope: Scope,
    ) -> list[Belief]:
        """Detect salt-like signer configuration passed as a positional key."""

        context = f"{scope.file_path} {scope.class_name or ''} {node.name}".lower()
        if not any(token in context for token in ("sign", "token", "verification")):
            return []
        for call in ast.walk(node):
            if not isinstance(call, ast.Call):
                continue
            short_name = _ast_call_name(call).rsplit(".", 1)[-1]
            if short_name not in {"Signer", "TimestampSigner"} or not call.args:
                continue
            if any(keyword.arg == "salt" for keyword in call.keywords):
                continue
            salt_names = {
                _ast_dotted_name(candidate).lower()
                for candidate in ast.walk(call.args[0])
                if _ast_dotted_name(candidate)
                and "salt" in _ast_dotted_name(candidate).lower()
            }
            if not salt_names:
                continue
            source = sorted(salt_names)[0]
            return [
                self._make_belief(
                    "signature.salt_is_bound_to_salt_parameter == true",
                    (
                        f"Salt-like value '{source}' is passed positionally to "
                        f"'{short_name}' at line {call.lineno}; it may bind as "
                        "key material instead of domain-separation salt (CWE-347)."
                    ),
                    scope,
                    call.lineno,
                    "high",
                    "CWE-347",
                    variables=(source,),
                    metadata={
                        "analysis_profile": "patch_review",
                        "dataflow": {
                            "source": source,
                            "source_line": node.lineno,
                            "sink": short_name,
                            "sink_line": call.lineno,
                            "path": [source, short_name],
                            "missing_guarantees": [
                                "signature.salt_parameter_is_explicit == true"
                            ],
                        },
                    },
                )
            ]
        return []

    def _check_patch_boundary_view_access(
        self,
        tree: ast.Module,
        module_scope: Scope,
    ) -> list[Belief]:
        """Detect route-selected object access without an object-level guard."""

        beliefs: list[Belief] = []
        for class_node in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, ast.ClassDef)
        ):
            if not _is_web_view_class(class_node):
                continue
            methods = [
                child
                for child in class_node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if any(_has_object_authorization_guard(method) for method in methods):
                continue
            for method in methods:
                lookup = _route_selected_object_lookup(method)
                if lookup is None:
                    continue
                scope = Scope(
                    file_path=module_scope.file_path,
                    function_name=method.name,
                    class_name=class_node.name,
                    module=module_scope.module,
                    line_start=method.lineno,
                    line_end=method.end_lineno,
                )
                sink = _ast_call_name(lookup) or "object lookup"
                beliefs.append(
                    self._make_belief(
                        "resource.object_authorized == true",
                        (
                            f"Route-selected object reaches '{sink}' at line "
                            f"{lookup.lineno} without an object-level ownership or "
                            "permission guard (CWE-863)."
                        ),
                        scope,
                        lookup.lineno,
                        "high",
                        "CWE-863",
                        variables=("route_selector", "authenticated_user"),
                        metadata={
                            "analysis_profile": "patch_review",
                            "dataflow": {
                                "source": "route_selector",
                                "source_line": method.lineno,
                                "sink": sink,
                                "sink_line": lookup.lineno,
                                "path": ["route_selector", sink],
                                "missing_guarantees": [
                                    (
                                        "resource.owner == authenticated_user OR "
                                        "user.has_object_permission"
                                    )
                                ],
                            },
                        },
                    )
                )
                break
        return beliefs

    def _check_patch_proxy_route_authority(
        self,
        tree: ast.Module,
        module_scope: Scope,
    ) -> list[Belief]:
        """Detect proxy route captures that do not isolate URL authorities."""

        if not _module_has_outbound_http_request(tree):
            return []

        beliefs: list[Belief] = []
        outbound_handler_names = _outbound_http_handler_names(tree)
        class_names: dict[int, str] = {}
        for class_node in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, ast.ClassDef)
        ):
            for child in class_node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    class_names[id(child)] = class_node.name

        for function in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            scope = Scope(
                file_path=module_scope.file_path,
                function_name=function.name,
                class_name=class_names.get(id(function)),
                module=module_scope.module,
                line_start=function.lineno,
                line_end=function.end_lineno,
            )
            for call in (
                candidate
                for candidate in ast.walk(function)
                if isinstance(candidate, ast.Call)
                and _is_route_registration_call(candidate)
            ):
                if not (
                    _node_has_outbound_http_request(function)
                    or _route_references_handler(
                        call,
                        outbound_handler_names,
                    )
                ):
                    continue
                for literal in (
                    candidate
                    for candidate in ast.walk(call)
                    if isinstance(candidate, ast.Constant)
                    and isinstance(candidate.value, str)
                ):
                    if not _proxy_route_has_ambiguous_authority(literal.value):
                        continue
                    beliefs.append(
                        self._make_belief(
                            "proxy.route_authority_isolated == true",
                            (
                                f"Proxy route at line {literal.lineno} captures a "
                                "host without excluding URL authority delimiters "
                                "before an outbound request (CWE-918)."
                            ),
                            scope,
                            literal.lineno,
                            "high",
                            "CWE-918",
                            variables=("route_host",),
                            metadata={
                                "analysis_profile": "patch_review",
                                "dataflow": {
                                    "source": "route_host_capture",
                                    "source_line": literal.lineno,
                                    "sink": "outbound HTTP request",
                                    "sink_line": literal.lineno,
                                    "path": [
                                        "route_host_capture",
                                        "outbound HTTP request",
                                    ],
                                    "missing_guarantees": [
                                        "proxy.route_authority_isolated == true"
                                    ],
                                },
                            },
                        )
                    )
        return beliefs

    def _check_patch_unsafe_xml_parsing(
        self,
        tree: ast.Module,
        module_scope: Scope,
    ) -> list[Belief]:
        """Detect boundary data parsed by an imported unsafe stdlib XML parser."""

        unsafe_calls = _unsafe_xml_parser_call_names(tree)
        if not unsafe_calls:
            return []

        beliefs: list[Belief] = []
        class_names = _function_class_names(tree)
        for function in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            boundary_sources = (
                _function_parameter_names(function) - {"self", "cls"}
            )
            if not boundary_sources:
                continue
            aliases = _flow_aliases(function, boundary_sources)
            scope = Scope(
                file_path=module_scope.file_path,
                function_name=function.name,
                class_name=class_names.get(id(function)),
                module=module_scope.module,
                line_start=function.lineno,
                line_end=function.end_lineno,
            )
            for call in (
                event
                for event in _ordered_function_events(function)
                if isinstance(event, ast.Call)
                and _ast_call_name(event) in unsafe_calls
            ):
                values = [
                    *call.args,
                    *(keyword.value for keyword in call.keywords),
                ]
                sources = {
                    source
                    for value in values
                    for source in (_referenced_names(value) & aliases)
                }
                if not sources or not _is_external_xml_boundary(
                    function,
                    sources=sources,
                    values=values,
                ):
                    continue
                source = sorted(sources)[0]
                sink = _ast_call_name(call)
                beliefs.append(
                    self._make_belief(
                        "xml.parser_rejects_unsafe_entities == true",
                        (
                            f"Boundary XML from '{source}' reaches stdlib parser "
                            f"'{sink}' at line {call.lineno} without a hardened "
                            "entity-expansion policy (CWE-611)."
                        ),
                        scope,
                        call.lineno,
                        "high",
                        "CWE-611",
                        variables=tuple(sorted(sources)),
                        metadata={
                            "analysis_profile": "patch_review",
                            "dataflow": {
                                "source": source,
                                "source_line": function.lineno,
                                "sink": sink,
                                "sink_line": call.lineno,
                                "path": [source, sink],
                                "missing_guarantees": [
                                    "xml.parser_rejects_unsafe_entities == true"
                                ],
                            },
                        },
                    )
                )
        return beliefs

    def _check_patch_redirect_header_injection(
        self,
        tree: ast.Module,
        module_scope: Scope,
    ) -> list[Belief]:
        """Detect boundary redirect targets without a proven CR/LF sanitizer."""

        sanitizers = _proven_crlf_sanitizer_names(tree)
        class_names = _function_class_names(tree)
        class_attributes: dict[str, set[str]] = {}
        for class_node in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, ast.ClassDef)
        ):
            initializer = next(
                (
                    child
                    for child in class_node.body
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and child.name == "__init__"
                ),
                None,
            )
            if initializer is None:
                continue
            class_attributes[class_node.name] = {
                attribute
                for attribute, (source, _) in (
                    _boundary_backed_instance_attributes(initializer).items()
                )
                if (
                    _is_redirect_boundary_name(source)
                    or _is_redirect_boundary_name(attribute)
                )
            }

        beliefs: list[Belief] = []
        for function in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, (ast.FunctionDef, ast.AsyncFunctionDef))
        ):
            class_name = class_names.get(id(function))
            tainted_attributes = class_attributes.get(class_name or "", set())
            boundary_sources = {
                name
                for name in _function_parameter_names(function) - {"self", "cls"}
                if _is_redirect_boundary_name(name)
            }
            if (
                not boundary_sources
                and not tainted_attributes
                and not _references_request_context(function)
            ):
                continue

            aliases = _redirect_taint_aliases(
                function,
                boundary_sources=boundary_sources,
                tainted_attributes=tainted_attributes,
                sanitizers=sanitizers,
            )
            scope = Scope(
                file_path=module_scope.file_path,
                function_name=function.name,
                class_name=class_name,
                module=module_scope.module,
                line_start=function.lineno,
                line_end=function.end_lineno,
            )
            for call in (
                event
                for event in _ordered_function_events(function)
                if isinstance(event, ast.Call)
                and _is_redirect_sink_call(event)
            ):
                for value in _redirect_call_values(call):
                    if _expression_is_crlf_sanitized(value, sanitizers):
                        continue
                    if not _expression_has_redirect_taint(
                        value,
                        aliases=aliases,
                        tainted_attributes=tainted_attributes,
                    ):
                        continue
                    sink = _ast_call_name(call)
                    source = _redirect_source_label(
                        value,
                        aliases=aliases,
                        tainted_attributes=tainted_attributes,
                    )
                    beliefs.append(
                        self._make_belief(
                            "http.redirect_target_excludes_crlf == true",
                            (
                                f"Boundary redirect target '{source}' reaches "
                                f"'{sink}' at line {call.lineno} without proven "
                                "CR/LF removal (CWE-93)."
                            ),
                            scope,
                            call.lineno,
                            "high",
                            "CWE-93",
                            variables=(source,),
                            metadata={
                                "analysis_profile": "patch_review",
                                "dataflow": {
                                    "source": source,
                                    "source_line": function.lineno,
                                    "sink": sink,
                                    "sink_line": call.lineno,
                                    "path": [source, sink],
                                    "missing_guarantees": [
                                        "http.redirect_target_excludes_crlf == true"
                                    ],
                                },
                            },
                        )
                    )
                    break
        return beliefs

    def _check_patch_boundary_option_injection(
        self,
        tree: ast.Module,
        module_scope: Scope,
    ) -> list[Belief]:
        """Detect boundary list items that become process options."""

        beliefs: list[Belief] = []
        for class_node in (
            candidate
            for candidate in ast.walk(tree)
            if isinstance(candidate, ast.ClassDef)
        ):
            methods = {
                child.name: child
                for child in class_node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            initializer = methods.get("__init__")
            if initializer is None or not _class_has_process_sink(class_node):
                continue
            attributes = _boundary_backed_instance_attributes(initializer)
            for attribute, (source, line) in sorted(attributes.items()):
                if _is_explicit_process_option_source(source, attribute):
                    continue
                if not _class_builds_process_args_from_attribute(
                    class_node,
                    attribute,
                ):
                    continue
                if _attribute_has_option_prefix_guard(
                    initializer,
                    methods,
                    attribute,
                ):
                    continue
                scope = Scope(
                    file_path=module_scope.file_path,
                    function_name=initializer.name,
                    class_name=class_node.name,
                    module=module_scope.module,
                    line_start=initializer.lineno,
                    line_end=initializer.end_lineno,
                )
                beliefs.append(
                    self._make_belief(
                        "command.argument_cannot_be_option == true",
                        (
                            f"Boundary collection '{source}' reaches a process "
                            "argument vector without an abortive leading-option "
                            f"check at line {line} (CWE-88)."
                        ),
                        scope,
                        line,
                        "high",
                        "CWE-88",
                        variables=(source, attribute),
                        metadata={
                            "analysis_profile": "patch_review",
                            "dataflow": {
                                "source": source,
                                "source_line": initializer.lineno,
                                "sink": "process argument vector",
                                "sink_line": line,
                                "path": [
                                    source,
                                    f"self.{attribute}",
                                    "process argument vector",
                                ],
                                "missing_guarantees": [
                                    "command.argument_cannot_be_option == true"
                                ],
                            },
                        },
                    )
                )
        return beliefs

    def _patch_path_belief(
        self,
        scope: Scope,
        *,
        line: int,
        sources: set[str],
        sink: str,
        reason: str,
    ) -> Belief:
        ordered_sources = tuple(sorted(sources))
        source = ordered_sources[0] if ordered_sources else "path input"
        return self._make_belief(
            "path.boundary_guarded == true",
            f"{reason} at line {line} — potential path traversal (CWE-22).",
            scope,
            line,
            "high",
            "CWE-22",
            variables=ordered_sources,
            metadata={
                "analysis_profile": "patch_review",
                "dataflow": {
                    "source": source,
                    "source_line": scope.line_start,
                    "sink": sink,
                    "sink_line": line,
                    "path": [source, sink],
                    "missing_guarantees": ["path.is_within_store == true"],
                },
            },
        )

    def _check_xss(self, node: ast.FunctionDef, scope: Scope,
                   source: str) -> list[Belief]:
        """Detect potential XSS (CWE-79)."""
        beliefs = []
        xss_sinks = {
            "render_template_string",
            "Markup",
            "mark_safe",
            "innerHTML",
            "document.write",
        }

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
                     variables: tuple[str, ...] = (),
                     metadata: dict | None = None) -> Belief:
        confidence = {"critical": 0.95, "high": 0.88, "medium": 0.78}.get(severity, 0.7)
        source_metadata = {
            "source": "security_patterns",
            "rule_id": cwe,
            "severity": severity,
        }
        if metadata:
            source_metadata.update(metadata)
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
            source_metadata=source_metadata,
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


def _function_parameter_names(
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


def _is_patch_path_parameter(name: str) -> bool:
    normalized = str(name or "").strip().lower().replace("-", "_")
    if not normalized or normalized in {"self", "cls"}:
        return False
    trusted_tokens = {
        "base",
        "basedir",
        "base_dir",
        "directory",
        "dir",
        "root",
        "rootdir",
        "root_dir",
        "root_path",
        "store",
        "storage",
    }
    if normalized in trusted_tokens:
        return False
    if normalized in {
        "file",
        "file_name",
        "filename",
        "filepath",
        "key",
        "name",
        "path",
        "request_path",
        "tok",
        "token",
        "untrusted_path",
        "user_path",
        "vpath",
    }:
        return True
    return normalized.endswith(("_file", "_filename", "_key", "_path"))


def _ordered_function_events(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    events: list[ast.AST] = []
    stack = list(reversed(node.body))
    while stack:
        current = stack.pop()
        if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        if isinstance(
            current,
            (
                ast.Assign,
                ast.AnnAssign,
                ast.NamedExpr,
                ast.AugAssign,
                ast.For,
                ast.AsyncFor,
                ast.If,
                ast.Assert,
                ast.Call,
                ast.Return,
            ),
        ):
            events.append(current)
        stack.extend(reversed(list(ast.iter_child_nodes(current))))

    priority = {
        ast.Assign: 0,
        ast.AnnAssign: 0,
        ast.NamedExpr: 0,
        ast.AugAssign: 0,
        ast.For: 1,
        ast.AsyncFor: 1,
        ast.If: 1,
        ast.Assert: 1,
        ast.Call: 2,
        ast.Return: 3,
    }
    return sorted(
        events,
        key=lambda item: (
            getattr(item, "lineno", 0),
            priority.get(type(item), 9),
            getattr(item, "col_offset", 0),
        ),
    )


def _assignment_parts(
    node: ast.Assign | ast.AnnAssign | ast.NamedExpr,
) -> tuple[set[str], ast.AST | None]:
    if isinstance(node, ast.Assign):
        targets = node.targets
        value = node.value
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
        value = node.value
    else:
        targets = [node.target]
        value = node.value
    return {
        name
        for target in targets
        for name in _target_names(target)
    }, value


def _target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {
            name
            for element in node.elts
            for name in _target_names(element)
        }
    return set()


def _referenced_names(node: ast.AST) -> set[str]:
    return {
        child.id
        for child in ast.walk(node)
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load)
    }


def _expression_call_name(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    return _ast_call_name(node)


def _ast_call_name(node: ast.Call) -> str:
    parts: list[str] = []
    current: ast.AST = node.func
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _call_path_sources(node: ast.Call, tainted: set[str]) -> set[str]:
    values: list[ast.AST] = [
        *node.args,
        *(keyword.value for keyword in node.keywords),
    ]
    if isinstance(node.func, ast.Attribute):
        values.append(node.func.value)
    return {
        name
        for value in values
        for name in (_referenced_names(value) & tainted)
    }


def _origin_path_sources(
    sources: set[str],
    lineage: dict[str, set[str]],
) -> set[str]:
    return {
        origin
        for source in sources
        for origin in lineage.get(source, {source})
    }


def _is_patch_path_sink(call_name: str) -> bool:
    normalized = str(call_name or "").strip().lower()
    if not normalized:
        return False
    short = normalized.rsplit(".", 1)[-1]
    return short in _PATCH_PATH_SINK_SUFFIXES


def _branch_terminates(body: list[ast.stmt]) -> bool:
    if not body:
        return False
    tail = body[-1]
    return isinstance(tail, (ast.Return, ast.Raise, ast.Continue, ast.Break))


def _rejected_path_guard_sources(
    node: ast.If,
    *,
    tainted: set[str],
    containment_aliases: dict[str, set[str]],
) -> set[str]:
    if not _branch_terminates(node.body):
        return set()
    test = node.test
    sources = _referenced_names(test) & tainted
    for alias in _referenced_names(test):
        sources.update(containment_aliases.get(alias, set()))

    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        if _contains_path_guard_call(test.operand) or _contains_normalized_startswith(
            test.operand
        ):
            return sources

    if isinstance(test, ast.Compare):
        if _comparison_rejects_containment(test, containment_aliases):
            return sources
    return set()


def _asserted_path_guard_sources(
    test: ast.AST,
    *,
    tainted: set[str],
    containment_aliases: dict[str, set[str]],
) -> set[str]:
    sources = _referenced_names(test) & tainted
    for alias in _referenced_names(test):
        sources.update(containment_aliases.get(alias, set()))
    if _contains_path_guard_call(test) or _contains_normalized_startswith(test):
        return sources
    if isinstance(test, ast.Compare) and _comparison_accepts_containment(
        test, containment_aliases
    ):
        return sources
    return set()


def _contains_path_guard_call(node: ast.AST) -> bool:
    return any(
        (_ast_call_name(child).rsplit(".", 1)[-1].lower() in _PATCH_PATH_GUARD_CALLS)
        for child in ast.walk(node)
        if isinstance(child, ast.Call)
    )


def _contains_normalized_startswith(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        if _ast_call_name(child).rsplit(".", 1)[-1].lower() != "startswith":
            continue
        receiver = child.func.value if isinstance(child.func, ast.Attribute) else None
        if receiver is None:
            continue
        names = {
            _ast_call_name(call).rsplit(".", 1)[-1].lower()
            for call in ast.walk(receiver)
            if isinstance(call, ast.Call)
        }
        if names & {"abspath", "normpath", "realpath", "resolve"}:
            return True
    return False


def _comparison_rejects_containment(
    node: ast.Compare,
    containment_aliases: dict[str, set[str]],
) -> bool:
    if not any(isinstance(operator, (ast.NotEq, ast.IsNot)) for operator in node.ops):
        return False
    if any(
        _ast_call_name(call).rsplit(".", 1)[-1].lower() == "commonpath"
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
    ):
        return True
    return bool(_referenced_names(node) & set(containment_aliases))


def _comparison_accepts_containment(
    node: ast.Compare,
    containment_aliases: dict[str, set[str]],
) -> bool:
    if not any(isinstance(operator, (ast.Eq, ast.Is)) for operator in node.ops):
        return False
    if any(
        _ast_call_name(call).rsplit(".", 1)[-1].lower() == "commonpath"
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
    ):
        return True
    return bool(_referenced_names(node) & set(containment_aliases))


def _function_returns_path_value(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    value: ast.AST,
) -> bool:
    if not _return_expression_can_be_path(value):
        return False
    name = node.name.lower()
    if any(token in name for token in ("path", "file")):
        return True
    return any(
        _ast_call_name(call).rsplit(".", 1)[-1].lower()
        in {"abspath", "join", "normpath", "realpath", "resolve"}
        for call in ast.walk(value)
        if isinstance(call, ast.Call)
    )


def _return_expression_can_be_path(value: ast.AST) -> bool:
    if isinstance(value, (ast.Name, ast.Attribute, ast.Subscript)):
        return True
    if isinstance(value, ast.BinOp) and isinstance(value.op, (ast.Add, ast.Div)):
        return True
    if isinstance(value, ast.IfExp):
        return (
            _return_expression_can_be_path(value.body)
            or _return_expression_can_be_path(value.orelse)
        )
    if isinstance(value, ast.Call):
        short = _ast_call_name(value).rsplit(".", 1)[-1].lower()
        return short in {
            "abspath",
            "join",
            "normpath",
            "path",
            "realpath",
            "replace",
            "resolve",
            "strip",
        }
    return False


def _incomplete_path_validation_line(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted: set[str],
) -> int | None:
    name = node.name.lower()
    if not any(token in name for token in ("safe", "validat")):
        return None

    canonicalizer_lines = [
        call.lineno
        for call in _ordered_function_events(node)
        if isinstance(call, ast.Call)
        and _ast_call_name(call).rsplit(".", 1)[-1].lower()
        in _PATCH_PATH_CANONICALIZERS
        and _call_path_sources(call, tainted)
    ]
    validation_lines = []
    for child in _ordered_function_events(node):
        if not isinstance(child, ast.If):
            continue
        text_literals = {
            str(value.value)
            for value in ast.walk(child.test)
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        }
        call_names = {
            _ast_call_name(call).rsplit(".", 1)[-1].lower()
            for call in ast.walk(child.test)
            if isinstance(call, ast.Call)
        }
        if (
            ".." in text_literals
            or call_names & {"is_absolute", "isabs"}
        ) and (_referenced_names(child.test) & tainted):
            validation_lines.append(child.lineno)

    if not validation_lines:
        return None
    first_validation = min(validation_lines)
    if any(line < first_validation for line in canonicalizer_lines):
        return None
    return first_validation


def _flow_aliases(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    sources: set[str],
) -> set[str]:
    aliases = set(sources)
    changed = True
    while changed:
        changed = False
        for candidate in ast.walk(node):
            targets: set[str] = set()
            value: ast.AST | None = None
            if isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets, value = _assignment_parts(candidate)
            elif isinstance(candidate, (ast.For, ast.AsyncFor)):
                targets = _target_names(candidate.target)
                value = candidate.iter
            if value is None or not (_referenced_names(value) & aliases):
                continue
            additions = targets - aliases
            if additions:
                aliases.update(additions)
                changed = True
    return aliases


def _function_class_names(tree: ast.Module) -> dict[int, str]:
    return {
        id(child): class_node.name
        for class_node in ast.walk(tree)
        if isinstance(class_node, ast.ClassDef)
        for child in class_node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def _unsafe_xml_parser_call_names(tree: ast.Module) -> set[str]:
    modules = {
        "cElementTree": {"fromstring", "iterparse", "parse"},
        "elementtree.ElementTree": {"fromstring", "iterparse", "parse"},
        "xml.dom.minidom": {"parse", "parseString"},
        "xml.dom.pulldom": {"parse", "parseString"},
        "xml.etree.ElementTree": {"fromstring", "iterparse", "parse"},
        "xml.etree.cElementTree": {"fromstring", "iterparse", "parse"},
        "xml.sax": {"parse", "parseString"},
    }
    calls: set[str] = set()
    for statement in ast.walk(tree):
        if isinstance(statement, ast.Import):
            for imported in statement.names:
                methods = modules.get(imported.name)
                if not methods:
                    continue
                prefix = imported.asname or imported.name
                calls.update(f"{prefix}.{method}" for method in methods)
            continue
        if not isinstance(statement, ast.ImportFrom):
            continue
        module = str(statement.module or "")
        if module in {"xml.etree", "xml.dom"}:
            for imported in statement.names:
                full_module = f"{module}.{imported.name}"
                methods = modules.get(full_module)
                if not methods:
                    continue
                prefix = imported.asname or imported.name
                calls.update(f"{prefix}.{method}" for method in methods)
            continue
        methods = modules.get(module)
        if not methods:
            continue
        for imported in statement.names:
            if imported.name not in methods:
                continue
            calls.add(imported.asname or imported.name)
    return calls


def _is_external_xml_boundary(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    sources: set[str],
    values: list[ast.AST],
) -> bool:
    if any(_references_request_context(value) for value in values):
        return True
    xml_tokens = {
        "assertion",
        "body",
        "document",
        "envelope",
        "message",
        "payload",
        "response",
        "saml",
        "soap",
        "xml",
    }
    source_tokens = {
        token
        for source in sources
        for token in re.split(r"[^a-z0-9]+", source.lower())
        if token
    }
    if source_tokens & xml_tokens:
        return True
    function_tokens = {
        token
        for token in re.split(r"[^a-z0-9]+", function.name.lower())
        if token
    }
    if function_tokens & {"parse", "parser", "saml", "soap", "xml"}:
        return True
    docstring = (ast.get_docstring(function) or "").lower()
    return bool(
        re.search(r"\b(?:http|request|response|saml|soap|wire|xml)\b", docstring)
    )


def _proven_crlf_sanitizer_names(tree: ast.Module) -> set[str]:
    regex_names: set[str] = set()
    for statement in tree.body:
        if not isinstance(statement, (ast.Assign, ast.AnnAssign)):
            continue
        value = statement.value
        if (
            value is None
            or not isinstance(value, ast.Call)
            or _ast_call_name(value).lower() not in {"compile", "re.compile"}
            or not value.args
            or not _is_crlf_pattern(value.args[0])
        ):
            continue
        targets = (
            statement.targets
            if isinstance(statement, ast.Assign)
            else [statement.target]
        )
        regex_names.update(
            name
            for target in targets
            for name in _target_names(target)
        )

    return {
        function.name
        for function in tree.body
        if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
        and _function_removes_crlf(function, regex_names)
    }


def _is_crlf_pattern(node: ast.AST) -> bool:
    if not isinstance(node, ast.Constant):
        return False
    value = node.value
    if isinstance(value, bytes):
        normalized = value.decode("latin-1", errors="ignore")
    elif isinstance(value, str):
        normalized = value
    else:
        return False
    return (
        ("\\r" in normalized and "\\n" in normalized)
        or ("\r" in normalized and "\n" in normalized)
    )


def _function_removes_crlf(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    regex_names: set[str],
) -> bool:
    parameters = _function_parameter_names(function) - {"self", "cls"}
    for returned in (
        candidate
        for candidate in ast.walk(function)
        if isinstance(candidate, ast.Return) and candidate.value is not None
    ):
        for call in (
            candidate
            for candidate in ast.walk(returned.value)
            if isinstance(candidate, ast.Call)
            and _ast_call_name(candidate).rsplit(".", 1)[-1].lower() == "sub"
        ):
            if len(call.args) < 2:
                continue
            receiver_names = (
                _referenced_names(call.func.value)
                if isinstance(call.func, ast.Attribute)
                else set()
            )
            replacement = call.args[0]
            replacement_is_empty = (
                isinstance(replacement, ast.Constant)
                and replacement.value in {"", b""}
            )
            if (
                replacement_is_empty
                and bool(receiver_names & regex_names)
                and bool(_referenced_names(call.args[1]) & parameters)
            ):
                return True
    return False


def _is_redirect_boundary_name(name: str) -> bool:
    normalized = str(name or "").strip("_").lower().replace("-", "_")
    tokens = set(normalized.split("_"))
    return bool(
        tokens
        & {
            "continue",
            "destination",
            "location",
            "next",
            "path",
            "redirect",
            "return",
            "target",
            "uri",
            "url",
        }
    ) or normalized.endswith(
        ("destination", "location", "path", "target", "uri", "url")
    )


def _redirect_taint_aliases(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    boundary_sources: set[str],
    tainted_attributes: set[str],
    sanitizers: set[str],
) -> set[str]:
    aliases = set(boundary_sources)
    changed = True
    while changed:
        changed = False
        for candidate in _ordered_function_events(function):
            targets: set[str] = set()
            value: ast.AST | None = None
            if isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets, value = _assignment_parts(candidate)
            elif isinstance(candidate, ast.AugAssign):
                targets = _target_names(candidate.target)
                value = candidate.value
            if value is None:
                continue
            if _expression_is_crlf_sanitized(value, sanitizers):
                aliases.difference_update(targets)
                continue
            if _expression_has_redirect_taint(
                value,
                aliases=aliases,
                tainted_attributes=tainted_attributes,
            ):
                additions = targets - aliases
                if additions:
                    aliases.update(additions)
                    changed = True
    return aliases


def _expression_is_crlf_sanitized(
    node: ast.AST,
    sanitizers: set[str],
) -> bool:
    if not isinstance(node, ast.Call):
        return False
    call_name = _ast_call_name(node)
    return (
        call_name in sanitizers
        or call_name.rsplit(".", 1)[-1] in sanitizers
    )


def _expression_has_redirect_taint(
    node: ast.AST,
    *,
    aliases: set[str],
    tainted_attributes: set[str],
) -> bool:
    return (
        bool(_referenced_names(node) & aliases)
        or _references_request_context(node)
        or any(
            _self_attribute_name(candidate) in tainted_attributes
            for candidate in ast.walk(node)
        )
    )


def _is_redirect_sink_call(call: ast.Call) -> bool:
    short_name = _ast_call_name(call).rsplit(".", 1)[-1].lower()
    return short_name in {"redirect", "redirect_to"}


def _redirect_call_values(call: ast.Call) -> list[ast.AST]:
    values = list(call.args[:1])
    values.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"location", "target", "uri", "url"}
    )
    return values


def _redirect_source_label(
    node: ast.AST,
    *,
    aliases: set[str],
    tainted_attributes: set[str],
) -> str:
    names = sorted(_referenced_names(node) & aliases)
    if names:
        return names[0]
    attributes = sorted({
        f"self.{attribute}"
        for candidate in ast.walk(node)
        if (attribute := _self_attribute_name(candidate)) in tainted_attributes
    })
    if attributes:
        return attributes[0]
    if _references_request_context(node):
        return "request redirect target"
    return "redirect target"


def _is_record_creation_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    tokens = set(node.name.lower().strip("_").split("_"))
    return bool(tokens & {"add", "create", "new", "register"})


def _is_mapping_boundary_name(name: str) -> bool:
    tokens = set(str(name or "").lower().strip("_").split("_"))
    return bool(
        tokens
        & {
            "attrs",
            "body",
            "data",
            "dict",
            "fields",
            "input",
            "payload",
            "record",
            "values",
        }
    )


def _documents_external_identifier(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    docstring = ast.get_docstring(node, clean=False) or ""
    normalized = docstring.lower()
    return bool(
        re.search(r":param\s+(?:str\s+)?id\s*:", normalized)
        or re.search(r"\bid\s+of\s+the\s+(?:new|created)\b", normalized)
        or re.search(r"\bid\s*\([^)]*optional[^)]*\)", normalized)
    )


def _is_record_persistence_call(call: ast.Call) -> bool:
    short_name = _ast_call_name(call).rsplit(".", 1)[-1].lower()
    return (
        short_name in {"create", "insert", "save", "upsert"}
        or short_name.endswith(("_create", "_insert", "_save", "_upsert"))
    )


def _has_external_identifier_guard(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: set[str],
    *,
    before_line: int,
) -> bool:
    unconditional_node_ids = {
        id(candidate)
        for statement in node.body
        if not isinstance(
            statement,
            (
                ast.For,
                ast.AsyncFor,
                ast.If,
                ast.Match,
                ast.Try,
                ast.While,
                ast.With,
                ast.AsyncWith,
            ),
        )
        for candidate in ast.walk(statement)
    }
    for candidate in ast.walk(node):
        line = int(getattr(candidate, "lineno", 0) or 0)
        if not line or line >= before_line:
            continue
        if isinstance(candidate, ast.Call):
            short_name = _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
            if short_name == "pop" and candidate.args:
                field = candidate.args[0]
                if (
                    isinstance(field, ast.Constant)
                    and str(field.value).lower() == "id"
                    and bool(_referenced_names(candidate.func) & aliases)
                    and id(candidate) in unconditional_node_ids
                ):
                    return True
        if isinstance(candidate, ast.Delete) and any(
            _is_identifier_subscript(target, aliases)
            for target in candidate.targets
        ) and id(candidate) in unconditional_node_ids:
            return True
        if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
            targets = (
                candidate.targets
                if isinstance(candidate, ast.Assign)
                else [candidate.target]
            )
            value = candidate.value
            if any(
                _is_identifier_subscript(target, aliases)
                for target in targets
            ) and value is not None and not bool(
                _referenced_names(value) & aliases
            ) and id(candidate) in unconditional_node_ids:
                return True
        if (
            isinstance(candidate, ast.If)
            and _condition_has_identifier_validation_marker(
                candidate.test,
                aliases,
            )
            and _branch_replaces_external_identifier(
                candidate.body,
                aliases,
            )
        ):
            return True
        if (
            isinstance(candidate, ast.If)
            and _branch_terminates(candidate.body)
            and _condition_rejects_external_identifier(
                candidate.test,
                aliases,
            )
        ):
            return True
    return False


def _is_identifier_subscript(
    node: ast.AST,
    aliases: set[str],
) -> bool:
    if not isinstance(node, ast.Subscript):
        return False
    field = node.slice
    return (
        isinstance(field, ast.Constant)
        and str(field.value).lower() == "id"
        and bool(_referenced_names(node.value) & aliases)
    )


def _condition_rejects_external_identifier(
    node: ast.AST,
    aliases: set[str],
) -> bool:
    references_identifier = bool(
        _referenced_names(node) & aliases
    ) and any(
        isinstance(candidate, ast.Constant)
        and str(candidate.value).lower() == "id"
        for candidate in ast.walk(node)
    )
    if not references_identifier:
        return False

    if _condition_has_identifier_validation_marker(node, aliases):
        return True

    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return False
    if isinstance(node, ast.BoolOp):
        if isinstance(node.op, ast.Or):
            return any(
                _condition_rejects_external_identifier(value, aliases)
                for value in node.values
            )
        return False
    if isinstance(node, ast.Call):
        return (
            _ast_call_name(node).rsplit(".", 1)[-1].lower() == "get"
            and bool(_referenced_names(node.func) & aliases)
            and any(
                isinstance(argument, ast.Constant)
                and str(argument.value).lower() == "id"
                for argument in node.args
            )
        )
    if isinstance(node, ast.Compare) and len(node.ops) == 1:
        operator = node.ops[0]
        if isinstance(operator, ast.In):
            return True
        if isinstance(operator, (ast.IsNot, ast.NotEq)):
            return any(
                isinstance(value, ast.Constant)
                and value.value in {None, "", False}
                for value in node.comparators
            )
    return False


def _condition_has_identifier_validation_marker(
    node: ast.AST,
    aliases: set[str],
) -> bool:
    if not (
        bool(_referenced_names(node) & aliases)
        and any(
            isinstance(candidate, ast.Constant)
            and str(candidate.value).lower() == "id"
            for candidate in ast.walk(node)
        )
    ):
        return False
    validation_tokens = {
        "admin",
        "allow",
        "auth",
        "authoriz",
        "exists",
        "owner",
        "permission",
        "privilege",
        "unique",
        "valid",
    }
    dotted_names = {
        _ast_dotted_name(candidate).lower()
        for candidate in ast.walk(node)
        if _ast_dotted_name(candidate)
    }
    if any(
        token in dotted
        for dotted in dotted_names
        for token in validation_tokens
    ):
        return True
    return False


def _branch_replaces_external_identifier(
    statements: list[ast.stmt],
    aliases: set[str],
) -> bool:
    for statement in statements:
        if isinstance(
            statement,
            (
                ast.For,
                ast.AsyncFor,
                ast.If,
                ast.Match,
                ast.Try,
                ast.While,
                ast.With,
                ast.AsyncWith,
            ),
        ):
            continue
        for candidate in ast.walk(statement):
            if isinstance(candidate, ast.Call) and candidate.args:
                short_name = (
                    _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
                )
                field = candidate.args[0]
                if (
                    short_name == "pop"
                    and isinstance(field, ast.Constant)
                    and str(field.value).lower() == "id"
                    and bool(_referenced_names(candidate.func) & aliases)
                ):
                    return True
            if isinstance(candidate, ast.Delete) and any(
                _is_identifier_subscript(target, aliases)
                for target in candidate.targets
            ):
                return True
            if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                targets = (
                    candidate.targets
                    if isinstance(candidate, ast.Assign)
                    else [candidate.target]
                )
                value = candidate.value
                if any(
                    _is_identifier_subscript(target, aliases)
                    for target in targets
                ) and value is not None and not bool(
                    _referenced_names(value) & aliases
                ):
                    return True
    return False


def _module_has_outbound_http_request(tree: ast.Module) -> bool:
    return _node_has_outbound_http_request(tree)


def _node_has_outbound_http_request(node: ast.AST) -> bool:
    return any(
        _is_outbound_http_call(candidate)
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
    )


def _is_outbound_http_call(call: ast.Call) -> bool:
    dotted = _ast_call_name(call).lower()
    short_name = dotted.rsplit(".", 1)[-1]
    if short_name in {"fetch", "urlopen"}:
        return True
    return dotted in {
        "httpx.get",
        "httpx.post",
        "httpx.put",
        "requests.get",
        "requests.post",
        "requests.put",
        "urllib.request.urlopen",
    }


def _is_route_registration_call(call: ast.Call) -> bool:
    short_name = _ast_call_name(call).rsplit(".", 1)[-1].lower()
    return short_name in {
        "add_handler",
        "add_handlers",
        "add_route",
        "add_routes",
        "route",
    }


def _route_references_handler(
    call: ast.Call,
    handler_names: set[str],
) -> bool:
    return any(
        isinstance(candidate, ast.Name)
        and candidate.id in handler_names
        for candidate in ast.walk(call)
    )


def _outbound_http_handler_names(tree: ast.Module) -> set[str]:
    classes = {
        candidate.name: candidate
        for candidate in ast.walk(tree)
        if isinstance(candidate, ast.ClassDef)
    }
    handler_names = {
        name
        for name, candidate in classes.items()
        if _node_has_outbound_http_request(candidate)
    }
    changed = True
    while changed:
        changed = False
        for name, candidate in classes.items():
            if name in handler_names:
                continue
            base_names = {
                _ast_dotted_name(base).rsplit(".", 1)[-1]
                for base in candidate.bases
            }
            if base_names & handler_names:
                handler_names.add(name)
                changed = True
    return handler_names


def _proxy_route_has_ambiguous_authority(pattern: str) -> bool:
    """Return true when a host capture admits URL authority delimiters."""

    captures = re.finditer(
        r"\(\[\^([^\]]*)\](?:\*|\+)\)\s*:\s*\(\\d\+\)",
        pattern,
    )
    return any(not {"/", ":", "@"}.issubset(set(match.group(1))) for match in captures)


def _forwarded_http_response_aliases(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    before_line: int | None = None,
) -> set[str]:
    response_aliases: set[str] = set()
    for event in _ordered_function_events(node):
        if (
            before_line is not None
            and int(getattr(event, "lineno", 0) or 0) >= before_line
        ):
            continue
        if not isinstance(
            event,
            (ast.Assign, ast.AnnAssign, ast.NamedExpr),
        ):
            continue
        targets, value = _assignment_parts(event)
        if value is None:
            continue
        derives_from_response = bool(
            _referenced_names(value) & response_aliases
        )
        receives_outbound_response = any(
            _is_outbound_http_call(candidate)
            for candidate in ast.walk(value)
            if isinstance(candidate, ast.Call)
        )
        response_aliases.difference_update(targets)
        if derives_from_response or receives_outbound_response:
            response_aliases.update(targets)
    if not response_aliases:
        return set()
    response_metadata_calls = {
        "add_header",
        "set_header",
        "set_status",
    }
    forwards_metadata = any(
        _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
        in response_metadata_calls
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
    )
    return response_aliases if forwards_metadata else set()


def _is_http_response_payload(
    node: ast.AST,
    response_aliases: set[str],
) -> bool:
    if not isinstance(node, ast.Attribute):
        return False
    owner = _ast_dotted_name(node.value).rsplit(".", 1)[-1]
    return (
        node.attr.lower() in {"body", "content", "data", "raw"}
        and owner in response_aliases
    )


def _class_has_process_sink(class_node: ast.ClassDef) -> bool:
    return any(
        _is_process_sink_call(candidate)
        for candidate in ast.walk(class_node)
        if isinstance(candidate, ast.Call)
    )


def _is_process_sink_call(call: ast.Call) -> bool:
    dotted = _ast_call_name(call).lower()
    short_name = dotted.rsplit(".", 1)[-1]
    if dotted.startswith("subprocess."):
        return short_name in {
            "call",
            "check_call",
            "check_output",
            "popen",
            "run",
        }
    return dotted in {"popen", "check_call", "check_output"}


def _boundary_backed_instance_attributes(
    initializer: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, tuple[str, int]]:
    parameters = _function_parameter_names(initializer) - {"self", "cls"}
    attributes: dict[str, tuple[str, int]] = {}
    for assignment in ast.walk(initializer):
        if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
            continue
        value = assignment.value
        if value is None:
            continue
        sources = sorted(_referenced_names(value) & parameters)
        if not sources:
            continue
        targets = (
            assignment.targets
            if isinstance(assignment, ast.Assign)
            else [assignment.target]
        )
        for target in targets:
            attribute = _self_attribute_name(target)
            if attribute:
                attributes.setdefault(
                    attribute,
                    (sources[0], assignment.lineno),
                )
    return attributes


def _self_attribute_name(node: ast.AST) -> str:
    if (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == "self"
    ):
        return node.attr
    return ""


def _expression_references_self_attribute(
    node: ast.AST,
    attribute: str,
) -> bool:
    return any(
        _self_attribute_name(candidate) == attribute
        for candidate in ast.walk(node)
    )


def _class_builds_process_args_from_attribute(
    class_node: ast.ClassDef,
    attribute: str,
) -> bool:
    methods = [
        child
        for child in class_node.body
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    tainted_attributes = {attribute}
    tainted_return_methods: set[str] = set()
    local_aliases: dict[int, set[str]] = {}

    changed = True
    while changed:
        changed = False
        for method in methods:
            aliases = _method_process_taint_aliases(
                method,
                tainted_attributes,
                tainted_return_methods,
            )
            local_aliases[id(method)] = aliases
            for candidate in ast.walk(method):
                targets: list[ast.AST] = []
                value: ast.AST | None = None
                if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
                    targets = (
                        candidate.targets
                        if isinstance(candidate, ast.Assign)
                        else [candidate.target]
                    )
                    value = candidate.value
                elif isinstance(candidate, ast.AugAssign):
                    targets = [candidate.target]
                    value = candidate.value
                if value is None or not _expression_has_process_taint(
                    value,
                    tainted_attributes,
                    aliases,
                    tainted_return_methods,
                ):
                    continue
                for target in targets:
                    target_attribute = _self_attribute_name(target)
                    if (
                        target_attribute
                        and target_attribute not in tainted_attributes
                    ):
                        tainted_attributes.add(target_attribute)
                        changed = True
            if (
                method.name not in tainted_return_methods
                and any(
                    isinstance(candidate, ast.Return)
                    and candidate.value is not None
                    and _expression_has_process_taint(
                        candidate.value,
                        tainted_attributes,
                        aliases,
                        tainted_return_methods,
                    )
                    for candidate in ast.walk(method)
                )
            ):
                tainted_return_methods.add(method.name)
                changed = True

    for method in methods:
        aliases = local_aliases.get(id(method), set())
        for call in (
            candidate
            for candidate in ast.walk(method)
            if isinstance(candidate, ast.Call)
            and _is_process_sink_call(candidate)
        ):
            if any(
                _expression_has_process_taint(
                    value,
                    tainted_attributes,
                    aliases,
                    tainted_return_methods,
                )
                for value in _process_command_values(call)
            ):
                return True
    return False


def _process_command_values(call: ast.Call) -> list[ast.AST]:
    values = list(call.args[:1])
    values.extend(
        keyword.value
        for keyword in call.keywords
        if keyword.arg in {"args", "cmd", "command"}
    )
    return values


def _method_process_taint_aliases(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
    tainted_attributes: set[str],
    tainted_return_methods: set[str],
) -> set[str]:
    aliases: set[str] = set()
    changed = True
    while changed:
        changed = False
        for candidate in ast.walk(method):
            targets: set[str] = set()
            value: ast.AST | None = None
            if isinstance(
                candidate,
                (ast.Assign, ast.AnnAssign, ast.NamedExpr),
            ):
                targets, value = _assignment_parts(candidate)
            elif isinstance(candidate, ast.AugAssign):
                targets = _target_names(candidate.target)
                value = candidate.value
            elif isinstance(candidate, (ast.For, ast.AsyncFor)):
                targets = _target_names(candidate.target)
                value = candidate.iter
            if value is not None and _expression_has_process_taint(
                value,
                tainted_attributes,
                aliases,
                tainted_return_methods,
            ):
                additions = targets - aliases
                if additions:
                    aliases.update(additions)
                    changed = True
            if not isinstance(candidate, ast.Call):
                continue
            short_name = _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
            dotted_name = _ast_dotted_name(candidate.func)
            owner = (
                dotted_name.rsplit(".", 1)[0]
                if "." in dotted_name
                else ""
            )
            values = [
                *candidate.args,
                *(keyword.value for keyword in candidate.keywords),
            ]
            if (
                short_name in {"append", "extend", "insert"}
                and owner
                and any(
                    _expression_has_process_taint(
                        item,
                        tainted_attributes,
                        aliases,
                        tainted_return_methods,
                    )
                    for item in values
                )
            ):
                owner_name = owner.rsplit(".", 1)[-1]
                if owner_name not in aliases:
                    aliases.add(owner_name)
                    changed = True
    return aliases


def _expression_has_process_taint(
    node: ast.AST,
    tainted_attributes: set[str],
    aliases: set[str],
    tainted_return_methods: set[str],
) -> bool:
    if any(
        _self_attribute_name(candidate) in tainted_attributes
        for candidate in ast.walk(node)
    ):
        return True
    if _referenced_names(node) & aliases:
        return True
    return any(
        _ast_call_name(candidate).rsplit(".", 1)[-1]
        in tainted_return_methods
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
    )


def _is_explicit_process_option_source(
    source: str,
    attribute: str,
) -> bool:
    names = {
        str(source or "").strip("_").lower(),
        str(attribute or "").strip("_").lower(),
    }
    tokens = {
        "arg",
        "args",
        "argument",
        "arguments",
        "argv",
        "binary",
        "cmd",
        "command",
        "executable",
        "option",
        "options",
        "program",
    }
    return any(
        set(name.replace("-", "_").split("_")) & tokens
        for name in names
    )


def _attribute_has_option_prefix_guard(
    initializer: ast.FunctionDef | ast.AsyncFunctionDef,
    methods: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    attribute: str,
) -> bool:
    for loop in (
        candidate
        for candidate in ast.walk(initializer)
        if isinstance(candidate, (ast.For, ast.AsyncFor))
        and _expression_references_self_attribute(
            candidate.iter,
            attribute,
        )
    ):
        item_names = _target_names(loop.target)
        for branch in (
            candidate
            for candidate in ast.walk(loop)
            if isinstance(candidate, ast.If)
            and _branch_terminates(candidate.body)
        ):
            if _test_rejects_leading_option(branch.test, item_names):
                return True
        for call in (
            candidate
            for candidate in ast.walk(loop)
            if isinstance(candidate, ast.Call)
            and bool(_referenced_names(candidate) & item_names)
        ):
            method = methods.get(
                _ast_call_name(call).rsplit(".", 1)[-1]
            )
            if method is not None and _validator_rejects_leading_option(
                method
            ):
                return True
    return False


def _validator_rejects_leading_option(
    method: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    parameters = _function_parameter_names(method) - {"self", "cls"}
    return any(
        _test_rejects_leading_option(candidate.test, parameters)
        for candidate in ast.walk(method)
        if isinstance(candidate, ast.If)
        and _branch_terminates(candidate.body)
    )


def _test_rejects_leading_option(
    test: ast.AST,
    names: set[str],
) -> bool:
    for call in (
        candidate
        for candidate in ast.walk(test)
        if isinstance(candidate, ast.Call)
        and _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
        == "startswith"
    ):
        if not call.args or not (_referenced_names(call.func) & names):
            continue
        value = call.args[0]
        if isinstance(value, ast.Constant) and value.value == "-":
            return True
    for comparison in (
        candidate
        for candidate in ast.walk(test)
        if isinstance(candidate, ast.Compare)
        and len(candidate.ops) == 1
        and isinstance(candidate.ops[0], (ast.Eq, ast.In))
    ):
        if not (_referenced_names(comparison) & names):
            continue
        literals = {
            value.value
            for value in ast.walk(comparison)
            if isinstance(value, ast.Constant)
            and isinstance(value.value, str)
        }
        if "-" in literals and any(
            isinstance(value, ast.Subscript)
            for value in ast.walk(comparison.left)
        ):
            return True
    return False


def _command_boundary_is_validated(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    boundary_parameters: set[str],
) -> bool:
    if not boundary_parameters:
        return False
    validator_names = {
        "quote",
        "sanitize_command",
        "shlex.quote",
        "validate_command",
        "validate_target",
    }
    for candidate in ast.walk(node):
        if isinstance(candidate, ast.Call):
            call_name = _ast_call_name(candidate).lower()
            short_name = call_name.rsplit(".", 1)[-1]
            if (
                call_name in validator_names
                or short_name in validator_names
                or short_name.startswith("validate_")
            ) and (_referenced_names(candidate) & boundary_parameters):
                return True
        if not isinstance(candidate, ast.If) or not _branch_terminates(
            candidate.body
        ):
            continue
        if not (_referenced_names(candidate.test) & boundary_parameters):
            continue
        if any(
            _ast_call_name(call).rsplit(".", 1)[-1].lower() == "fullmatch"
            and bool(_referenced_names(call) & boundary_parameters)
            for call in ast.walk(candidate.test)
            if isinstance(call, ast.Call)
        ):
            return True
        literals = {
            value.value
            for value in ast.walk(candidate.test)
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        }
        if any(
            any(character in literal for character in "!;&|`$<>\n\r")
            for literal in literals
        ):
            return True
    return False


def _contains_interpreter_delimiter(node: ast.AST) -> bool:
    literals = [
        value.value
        for value in ast.walk(node)
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    ]
    return any(
        any(delimiter in literal for delimiter in (";", "\n", "\r"))
        for literal in literals
    )


def _patch_command_evidence(
    analysis_profile: str,
    boundary_parameters: set[str],
    sink: str,
    sink_line: int,
    source_line: int,
) -> tuple[tuple[str, ...], dict[str, object] | None]:
    if analysis_profile != "patch_review" or not boundary_parameters:
        return (), None
    variables = tuple(sorted(boundary_parameters))
    source = variables[0]
    return variables, {
        "analysis_profile": "patch_review",
        "dataflow": {
            "source": source,
            "source_line": source_line,
            "sink": sink,
            "sink_line": sink_line,
            "path": [source, sink],
            "missing_guarantees": [
                "command.argument_is_validated == true"
            ],
        },
    }


def _sql_fragments_are_validated(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    aliases: set[str],
) -> bool:
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        short_name = _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
        if not (
            short_name in _PATCH_SQL_VALIDATORS
            or short_name.startswith(("check_", "validate_"))
        ):
            continue
        if _expression_references_alias(candidate, aliases):
            return True

    for candidate in ast.walk(node):
        if not isinstance(candidate, (ast.For, ast.AsyncFor)):
            continue
        target_names = _target_names(candidate.target)
        if not any(
            token in name.lower()
            for name in target_names
            for token in ("allow", "valid", "whitelist")
        ):
            continue
        if any(
            _expression_references_alias(statement, aliases)
            for statement in candidate.body
        ):
            return True

    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Compare):
            continue
        if not _expression_references_alias(candidate, aliases):
            continue
        dotted_names = {
            _ast_dotted_name(value).lower()
            for value in ast.walk(candidate)
            if _ast_dotted_name(value)
        }
        if any(
            token in dotted
            for dotted in dotted_names
            for token in ("allow", "valid", "whitelist")
        ):
            return True
    return False


def _sql_expression_has_validated_fragments(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    expression: ast.AST,
) -> bool:
    fragments = {
        candidate.id
        for candidate in ast.walk(expression)
        if isinstance(candidate, ast.Name) and candidate.id not in {"self", "cls"}
    }
    fragments.update(
        dotted.rsplit(".", 1)[-1]
        for candidate in ast.walk(expression)
        if (dotted := _ast_dotted_name(candidate))
        and "." in dotted
        and dotted.rsplit(".", 1)[-1] not in {"format", "join"}
    )
    fragments.update(
        name
        for name in _function_parameter_names(node)
        if name in _PATCH_SQL_FRAGMENT_NAMES
    )
    return bool(fragments) and _sql_fragments_are_validated(node, fragments)


def _expression_references_alias(node: ast.AST, aliases: set[str]) -> bool:
    normalized = {alias.lower() for alias in aliases}
    for candidate in ast.walk(node):
        if isinstance(candidate, ast.Name) and candidate.id.lower() in normalized:
            return True
        dotted = _ast_dotted_name(candidate).lower()
        if dotted and dotted.rsplit(".", 1)[-1] in normalized:
            return True
    return False


def _escaped_regex_substitution_callbacks(
    tree: ast.AST,
) -> dict[int, set[str]]:
    """Map regex callbacks whose match text comes from an escaped string."""

    callbacks: dict[int, set[str]] = {}
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        nested = {
            statement.name: statement
            for statement in function.body
            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        if not nested:
            continue

        sanitized_aliases: set[str] = set()
        for event in _ordered_function_events(function):
            if isinstance(event, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                targets, value = _assignment_parts(event)
                if value is None:
                    continue
                for call in ast.walk(value):
                    if isinstance(call, ast.Call):
                        _record_escaped_regex_callback(
                            call,
                            nested=nested,
                            sanitized_aliases=sanitized_aliases,
                            callbacks=callbacks,
                        )
                if _expression_has_xss_sanitizer(value):
                    sanitized_aliases.update(targets)
                elif (
                    isinstance(value, (ast.Name, ast.Attribute, ast.Subscript))
                    and _referenced_names(value)
                    and _referenced_names(value).issubset(sanitized_aliases)
                ):
                    sanitized_aliases.update(targets)
                else:
                    sanitized_aliases.difference_update(targets)
                continue
            if isinstance(event, ast.Call):
                _record_escaped_regex_callback(
                    event,
                    nested=nested,
                    sanitized_aliases=sanitized_aliases,
                    callbacks=callbacks,
                )
    return callbacks


def _record_escaped_regex_callback(
    call: ast.Call,
    *,
    nested: dict[str, ast.FunctionDef | ast.AsyncFunctionDef],
    sanitized_aliases: set[str],
    callbacks: dict[int, set[str]],
) -> None:
    parts = _regex_substitution_parts(call)
    if parts is None:
        return
    callback_expression, subject = parts
    if not isinstance(callback_expression, ast.Name):
        return
    callback = nested.get(callback_expression.id)
    if callback is None:
        return
    subject_names = _referenced_names(subject)
    if not (
        _expression_has_xss_sanitizer(subject)
        or (
            subject_names
            and subject_names.issubset(sanitized_aliases)
        )
    ):
        return
    parameters = [
        argument.arg
        for argument in [
            *callback.args.posonlyargs,
            *callback.args.args,
        ]
        if argument.arg not in {"self", "cls"}
    ]
    if parameters:
        callbacks.setdefault(id(callback), set()).add(parameters[0])


def _regex_substitution_parts(
    call: ast.Call,
) -> tuple[ast.AST, ast.AST] | None:
    call_name = _ast_call_name(call).lower()
    if call_name.rsplit(".", 1)[-1] not in {"sub", "subn"}:
        return None
    keywords = {
        keyword.arg: keyword.value
        for keyword in call.keywords
        if keyword.arg
    }
    callback = keywords.get("repl")
    subject = keywords.get("string")
    module_form = call_name.split(".", 1)[0] in {"re", "re2", "regex"}
    if module_form:
        if callback is None and len(call.args) >= 2:
            callback = call.args[1]
        if subject is None and len(call.args) >= 3:
            subject = call.args[2]
    else:
        if callback is None and call.args:
            callback = call.args[0]
        if subject is None and len(call.args) >= 2:
            subject = call.args[1]
    if callback is None or subject is None:
        return None
    return callback, subject


def _url_attribute_interpolation_names(node: ast.AST) -> set[str]:
    """Return names interpolated directly into a security-sensitive URL attribute."""

    names: set[str] = set()
    for joined in ast.walk(node):
        if not isinstance(joined, ast.JoinedStr):
            continue
        for index, part in enumerate(joined.values):
            if not isinstance(part, ast.FormattedValue) or index == 0:
                continue
            prefix = joined.values[index - 1]
            if not (
                isinstance(prefix, ast.Constant)
                and isinstance(prefix.value, str)
                and _PATCH_URL_ATTRIBUTE_PREFIX.search(prefix.value)
            ):
                continue
            names.update(_referenced_names(part.value))
    return names


def _rejected_url_scheme_sources(
    guard: ast.If,
    *,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    before_line: int,
) -> set[str]:
    """Return URL inputs protected by a top-level abortive HTTP(S) allowlist."""

    if guard not in node.body or not _branch_terminates(guard.body):
        return set()

    parsed_aliases: dict[str, str] = {}
    scheme_aliases: dict[str, str] = {}
    for statement in node.body:
        if getattr(statement, "lineno", before_line) >= before_line:
            break
        if not isinstance(statement, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        targets, value = _assignment_parts(statement)
        if value is None:
            continue
        parsed_source = _parsed_url_source(value)
        if parsed_source:
            for target in targets:
                parsed_aliases[target] = parsed_source
            continue
        scheme_source = _url_scheme_source(
            value,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
        if scheme_source:
            for target in targets:
                scheme_aliases[target] = scheme_source

    source = _rejected_safe_scheme_predicate(
        guard.test,
        parsed_aliases=parsed_aliases,
        scheme_aliases=scheme_aliases,
    )
    return {source} if source else set()


def _parsed_url_source(node: ast.AST) -> str:
    if not isinstance(node, ast.Call):
        return ""
    if _ast_call_name(node).rsplit(".", 1)[-1].lower() not in {
        "urlparse",
        "urlsplit",
    }:
        return ""
    if not node.args:
        return ""
    names = _referenced_names(node.args[0])
    return next(iter(names)) if len(names) == 1 else ""


def _url_scheme_source(
    node: ast.AST,
    *,
    parsed_aliases: dict[str, str],
    scheme_aliases: dict[str, str],
) -> str:
    if isinstance(node, ast.Name):
        return scheme_aliases.get(node.id, "")
    if not isinstance(node, ast.Attribute) or node.attr.lower() != "scheme":
        return ""
    base = _ast_dotted_name(node.value).rsplit(".", 1)[-1]
    return parsed_aliases.get(base, "")


def _rejected_safe_scheme_predicate(
    node: ast.AST,
    *,
    parsed_aliases: dict[str, str],
    scheme_aliases: dict[str, str],
) -> str:
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _accepted_safe_scheme_predicate(
            node.operand,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        sources = [
            source
            for value in node.values
            if (
                source := _negative_safe_scheme_comparison(
                    value,
                    parsed_aliases=parsed_aliases,
                    scheme_aliases=scheme_aliases,
                )
            )
        ]
        if (
            len(sources) == len(node.values)
            and sources
            and len(set(sources)) == 1
        ):
            return sources[0]
        return ""
    return _negative_safe_scheme_comparison(
        node,
        parsed_aliases=parsed_aliases,
        scheme_aliases=scheme_aliases,
    )


def _accepted_safe_scheme_predicate(
    node: ast.AST,
    *,
    parsed_aliases: dict[str, str],
    scheme_aliases: dict[str, str],
) -> str:
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        sources = [
            _accepted_safe_scheme_predicate(
                value,
                parsed_aliases=parsed_aliases,
                scheme_aliases=scheme_aliases,
            )
            for value in node.values
        ]
        if sources and all(sources) and len(set(sources)) == 1:
            return sources[0]
        return ""
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return ""
    operator = node.ops[0]
    left = node.left
    right = node.comparators[0]
    if isinstance(operator, ast.Eq):
        return _safe_scheme_equality_source(
            left,
            right,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
    if isinstance(operator, ast.In):
        source = _url_scheme_source(
            left,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
        schemes = _literal_scheme_values(right)
        if source and _schemes_are_safe(schemes):
            return source
    return ""


def _negative_safe_scheme_comparison(
    node: ast.AST,
    *,
    parsed_aliases: dict[str, str],
    scheme_aliases: dict[str, str],
) -> str:
    if not isinstance(node, ast.Compare) or len(node.ops) != 1:
        return ""
    operator = node.ops[0]
    left = node.left
    right = node.comparators[0]
    if isinstance(operator, ast.NotEq):
        return _safe_scheme_equality_source(
            left,
            right,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
    if isinstance(operator, ast.NotIn):
        source = _url_scheme_source(
            left,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
        schemes = _literal_scheme_values(right)
        if source and _schemes_are_safe(schemes):
            return source
    return ""


def _safe_scheme_equality_source(
    left: ast.AST,
    right: ast.AST,
    *,
    parsed_aliases: dict[str, str],
    scheme_aliases: dict[str, str],
) -> str:
    source = _url_scheme_source(
        left,
        parsed_aliases=parsed_aliases,
        scheme_aliases=scheme_aliases,
    )
    schemes = _literal_scheme_values(right)
    if not source:
        source = _url_scheme_source(
            right,
            parsed_aliases=parsed_aliases,
            scheme_aliases=scheme_aliases,
        )
        schemes = _literal_scheme_values(left)
    return source if source and _schemes_are_safe(schemes) else ""


def _literal_scheme_values(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value.strip().lower()}
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        values = {
            item.value.strip().lower()
            for item in node.elts
            if isinstance(item, ast.Constant) and isinstance(item.value, str)
        }
        return values if len(values) == len(node.elts) else set()
    return set()


def _schemes_are_safe(values: set[str]) -> bool:
    return bool(values) and values.issubset(_PATCH_SAFE_URL_SCHEMES)


def _expression_has_xss_sanitizer(node: ast.AST) -> bool:
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.Call):
            continue
        short_name = _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
        if (
            short_name in _PATCH_XSS_SANITIZERS
            or "sanitize" in short_name
            or "escape" in short_name
            or short_name.startswith(("_safe_", "safe_"))
        ):
            return True
    return False


def _expression_is_xss_boundary_source(node: ast.AST) -> bool:
    if _references_request_context(node):
        return True
    source_calls = {
        "form_data",
        "get_params",
        "get_query_params",
        "query_parameters",
        "url_parameters",
    }
    return any(
        _ast_call_name(candidate).rsplit(".", 1)[-1].lower() in source_calls
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
    )


def _record_sanitized_container(
    event: ast.Assign | ast.AnnAssign | ast.NamedExpr,
    value: ast.AST,
    sanitized_containers: set[str],
) -> None:
    if not _expression_has_xss_sanitizer(value):
        return
    if isinstance(event, ast.Assign):
        raw_targets = event.targets
    else:
        raw_targets = [event.target]
    for target in raw_targets:
        if not isinstance(target, ast.Subscript):
            continue
        dotted = _ast_dotted_name(target.value)
        if dotted:
            sanitized_containers.add(dotted.rsplit(".", 1)[-1])


def _is_http_output_context(scope: Scope) -> bool:
    context = f"{scope.file_path} {scope.class_name or ''}".lower()
    return any(
        token in context
        for token in (
            "component",
            "controller",
            "handler",
            "http",
            "route",
            "view",
            "web",
        )
    )


def _enables_tls_hostname_check(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    for candidate in ast.walk(node):
        if isinstance(candidate, (ast.Assign, ast.AnnAssign)):
            targets = (
                candidate.targets
                if isinstance(candidate, ast.Assign)
                else [candidate.target]
            )
            value = candidate.value
            if not (
                isinstance(value, ast.Constant)
                and value.value is True
            ):
                continue
            if any(
                isinstance(target, ast.Attribute)
                and target.attr == "check_hostname"
                for target in targets
            ):
                return True
        if not isinstance(candidate, ast.Call):
            continue
        if _ast_call_name(candidate).rsplit(".", 1)[-1].lower() != "setattr":
            continue
        if (
            len(candidate.args) >= 3
            and isinstance(candidate.args[1], ast.Constant)
            and candidate.args[1].value == "check_hostname"
            and isinstance(candidate.args[2], ast.Constant)
            and candidate.args[2].value is True
        ):
            return True
    return False


def _has_crypto_block_operation(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    blocks: set[str],
) -> bool:
    operation_tokens = (
        "bytes2int",
        "decrypt",
        "unpack",
        "verify",
    )
    return any(
        any(token in _ast_call_name(candidate).lower() for token in operation_tokens)
        and bool(_referenced_names(candidate) & blocks)
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
    )


def _has_abortive_length_guard(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    blocks: set[str],
) -> bool:
    for candidate in ast.walk(node):
        if not isinstance(candidate, ast.If) or not _branch_terminates(
            candidate.body
        ):
            continue
        for call in ast.walk(candidate.test):
            if not isinstance(call, ast.Call):
                continue
            if _ast_call_name(call).rsplit(".", 1)[-1].lower() != "len":
                continue
            if call.args and (_referenced_names(call.args[0]) & blocks):
                return True
    return False


def _forwards_keyword_arguments(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    kwargs_name: str,
) -> bool:
    return any(
        keyword.arg is None
        and isinstance(keyword.value, ast.Name)
        and keyword.value.id == kwargs_name
        for call in ast.walk(node)
        if isinstance(call, ast.Call)
        for keyword in call.keywords
    )


def _named_assignments(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> dict[str, ast.AST]:
    assignments: dict[str, ast.AST] = {}
    for candidate in ast.walk(node):
        if not isinstance(candidate, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            continue
        targets, value = _assignment_parts(candidate)
        if value is None:
            continue
        for target in targets:
            assignments[target] = value
    return assignments


def _is_authorization_call(node: ast.Call) -> bool:
    return (
        _ast_call_name(node).rsplit(".", 1)[-1].lower()
        in _PATCH_AUTHORIZATION_CALLS
    )


def _authorization_resource_names(node: ast.Call) -> tuple[str, ...]:
    candidates: list[str] = []
    for value in [
        *node.args,
        *(keyword.value for keyword in node.keywords),
    ]:
        if not isinstance(value, ast.Name):
            continue
        normalized = value.id.lower()
        if (
            normalized.endswith(("_id", "_key", "_name"))
            or normalized
            in {
                "account",
                "object",
                "project",
                "resource",
                "tenant",
            }
        ):
            candidates.append(value.id)
    return tuple(dict.fromkeys(candidates))


def _references_request_context(node: ast.AST) -> bool:
    for candidate in ast.walk(node):
        dotted = _ast_dotted_name(candidate)
        if not dotted:
            continue
        normalized = dotted.lower()
        if (
            normalized == "request"
            or normalized.startswith("request.")
            or normalized.startswith("self.request.")
        ):
            return True
    return False


def _is_web_view_class(node: ast.ClassDef) -> bool:
    if node.name.lower().endswith(("view", "controller", "handler")):
        return True
    return any(
        _ast_dotted_name(base).lower().endswith(
            ("view", "viewset", "controller", "handler")
        )
        for base in node.bases
        if _ast_dotted_name(base)
    )


def _route_selected_object_lookup(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> ast.Call | None:
    if node.name.lower() not in {
        "delete",
        "destroy",
        "get_object",
        "get_queryset",
        "retrieve",
        "update",
    }:
        return None
    for call in ast.walk(node):
        if not isinstance(call, ast.Call):
            continue
        call_name = _ast_call_name(call).lower()
        if not (
            ".objects." in call_name
            or ".query." in call_name
            or call_name.rsplit(".", 1)[-1]
            in {"find_by_id", "get_object_or_404", "load_object"}
        ):
            continue
        if _call_references_route_selector(call):
            return call
    return None


def _call_references_route_selector(node: ast.Call) -> bool:
    values = [
        *node.args,
        *(keyword.value for keyword in node.keywords),
    ]
    return any(_is_route_selector(candidate) for value in values for candidate in ast.walk(value))


def _is_route_selector(node: ast.AST) -> bool:
    dotted = _ast_dotted_name(node).lower()
    if not dotted:
        return False
    route_containers = {
        "kwargs",
        "request.args",
        "request.form",
        "request.get",
        "request.json",
        "request.post",
        "self.kwargs",
        "self.request.args",
        "self.request.get",
        "self.request.post",
    }
    return any(
        dotted == container or dotted.startswith(f"{container}.")
        for container in route_containers
    )


def _has_object_authorization_guard(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    has_rejection = any(isinstance(candidate, ast.Raise) for candidate in ast.walk(node))
    if not has_rejection:
        has_rejection = any(
            _ast_call_name(candidate).rsplit(".", 1)[-1].lower()
            in _PATCH_ACCESS_REJECTION_CALLS
            for candidate in ast.walk(node)
            if isinstance(candidate, ast.Call)
        )
    if not has_rejection:
        return False

    has_permission_call = any(
        _is_authorization_call(candidate)
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Call)
    )
    has_identity_comparison = any(
        _comparison_has_identity_and_resource(candidate)
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Compare)
    )
    return has_permission_call or has_identity_comparison


def _comparison_has_identity_and_resource(node: ast.Compare) -> bool:
    dotted_names = {
        _ast_dotted_name(candidate).lower()
        for candidate in ast.walk(node)
        if _ast_dotted_name(candidate)
    }
    identity_prefixes = (
        "current_user",
        "g.user",
        "request.user",
        "self.request.user",
    )
    has_identity = any(
        value == prefix or value.startswith(f"{prefix}.")
        for value in dotted_names
        for prefix in identity_prefixes
    )
    has_resource = any(
        value == "kwargs"
        or value.startswith(("kwargs.", "self.kwargs."))
        or (
            not any(
                value == prefix or value.startswith(f"{prefix}.")
                for prefix in identity_prefixes
            )
            and any(
                token in value.split(".")
                for token in ("owner", "owner_id", "user", "user_id")
            )
        )
        for value in dotted_names
    )
    return has_identity and has_resource


def _ast_dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _ast_dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return _ast_dotted_name(node.value)
    return ""
