"""Detect unsafe remote filenames used as local download destinations.

The rule is intentionally conservative.  It requires all of the following in
one function:

* a filename-like value read from an externally supplied object;
* that value flowing into a filesystem path or destination argument; and
* a file sink, or a download sink with explicit destination context.

Reducing the value to a leaf with ``basename`` or ``Path(...).name`` clears the
flow.  Normalization alone (for example ``normpath`` or stripping NUL bytes)
does not establish containment and is therefore not treated as sanitization.

``scan_source`` is pure: it parses the supplied string and performs no I/O,
network access, subprocess execution, or third-party imports.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any


RULE_ID = "BELIEF-DOWNLOAD-DESTINATION-001"

_FILENAME_ATTRIBUTES = {
    "file_name",
    "filename",
    "original_file_name",
    "original_filename",
    "suggested_file_name",
    "suggested_filename",
}
_REMOTE_NAME_PREFIXES = {
    "attachment",
    "client",
    "media",
    "original",
    "remote",
    "source",
    "suggested",
    "supplied",
    "upload",
    "uploaded",
    "user",
}
_LEAF_SANITIZERS = {
    "basename",
    "safe_file_name",
    "safe_filename",
    "sanitize_file_name",
    "sanitize_filename",
    "sanitise_file_name",
    "sanitise_filename",
    "secure_filename",
}
_PATH_TYPES = {"path", "pure_path", "pure_posix_path", "pure_windows_path"}
_NON_FILESYSTEM_DOWNLOAD_WORDS = {
    "audit",
    "event",
    "log",
    "metadata",
    "metric",
    "notify",
    "record",
    "status",
    "telemetry",
    "track",
}
_EXACT_FILE_SINKS = {
    "copy",
    "copy2",
    "copyfile",
    "move",
    "open",
    "write_bytes",
    "write_text",
}


@dataclass
class _FlowState:
    external: set[str] = field(default_factory=set)
    unsafe_filename: dict[str, int] = field(default_factory=dict)
    directory_names: set[str] = field(default_factory=set)
    path_objects: dict[str, int] = field(default_factory=dict)
    path_roots: dict[str, str] = field(default_factory=dict)
    resolved_paths: set[str] = field(default_factory=set)

    def clone(self) -> _FlowState:
        return _FlowState(
            external=set(self.external),
            unsafe_filename=dict(self.unsafe_filename),
            directory_names=set(self.directory_names),
            path_objects=dict(self.path_objects),
            path_roots=dict(self.path_roots),
            resolved_paths=set(self.resolved_paths),
        )

    @classmethod
    def merge(cls, *states: _FlowState) -> _FlowState:
        merged = cls()
        for state in states:
            merged.external.update(state.external)
            merged.directory_names.update(state.directory_names)
            for name, line in state.unsafe_filename.items():
                prior = merged.unsafe_filename.get(name)
                merged.unsafe_filename[name] = line if prior is None else min(prior, line)
        if states:
            merged.path_objects = dict(states[0].path_objects)
            merged.path_roots = dict(states[0].path_roots)
            merged.resolved_paths = set(states[0].resolved_paths)
            for state in states[1:]:
                merged.path_objects = {
                    name: line
                    for name, line in merged.path_objects.items()
                    if state.path_objects.get(name) == line
                }
                merged.path_roots = {
                    name: root
                    for name, root in merged.path_roots.items()
                    if state.path_roots.get(name) == root
                }
                merged.resolved_paths.intersection_update(state.resolved_paths)
        return merged

    def replace_with(self, other: _FlowState) -> None:
        self.external = other.external
        self.unsafe_filename = other.unsafe_filename
        self.directory_names = other.directory_names
        self.path_objects = other.path_objects
        self.path_roots = other.path_roots
        self.resolved_paths = other.resolved_paths


def scan_source(source: str, filename: str) -> list[dict[str, Any]]:
    """Return deterministic CWE-22 findings for one Python source string.

    Invalid Python is outside this bridge's evidence boundary and yields no
    finding.  Syntax diagnostics remain the responsibility of the caller's
    source-snapshot layer.
    """

    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, TypeError, ValueError):
        return []

    scanner = _ModuleScanner(filename or "<unknown>")
    scanner.visit(tree)
    return sorted(
        scanner.findings,
        key=lambda finding: (
            int(finding["line"]),
            int(finding["col"]),
            str(finding["rule_id"]),
        ),
    )


class _ModuleScanner(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        _FunctionScanner(self.filename, self.findings).scan(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        _FunctionScanner(self.filename, self.findings).scan(node)
        self.generic_visit(node)


class _FunctionScanner:
    def __init__(self, filename: str, findings: list[dict[str, Any]]) -> None:
        self.filename = filename
        self.findings = findings

    def scan(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        state = _FlowState()
        parameters = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg is not None:
            parameters.append(node.args.vararg)
        if node.args.kwarg is not None:
            parameters.append(node.args.kwarg)

        for parameter in parameters:
            name = parameter.arg
            if name not in {"self", "cls"}:
                state.external.add(name)
            self._record_name_role(name, state)
            if _looks_like_remote_filename_parameter(name):
                state.unsafe_filename[name] = parameter.lineno

        self._process_statements(node.body, state)

    def _process_statements(self, statements: list[ast.stmt], state: _FlowState) -> None:
        for statement in statements:
            self._process_statement(statement, state)

    def _process_statement(self, statement: ast.stmt, state: _FlowState) -> None:
        if isinstance(statement, ast.Assign):
            self._scan_expression(statement.value, state)
            for target in statement.targets:
                self._assign(target, statement.value, state)
            return

        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                self._scan_expression(statement.value, state)
                self._assign(statement.target, statement.value, state)
            return

        if isinstance(statement, ast.AugAssign):
            self._scan_expression(statement.value, state)
            origin = self._unsafe_origin(statement.value, state)
            if isinstance(statement.target, ast.Name) and origin is not None:
                state.unsafe_filename[statement.target.id] = origin
            return

        if isinstance(statement, ast.Expr):
            self._scan_expression(statement.value, state)
            return

        if isinstance(statement, ast.Return):
            if statement.value is not None:
                self._scan_expression(statement.value, state)
            return

        if isinstance(statement, ast.Raise):
            if statement.exc is not None:
                self._scan_expression(statement.exc, state)
            return

        if isinstance(statement, ast.If):
            self._scan_expression(statement.test, state)
            guaranteed_safe = self._guarded_value_after_if(statement, state)
            body_state = state.clone()
            else_state = state.clone()
            truthy_name = _simple_truthiness_name(statement.test)
            if truthy_name is not None:
                name, body_is_truthy = truthy_name
                falsy_state = else_state if body_is_truthy else body_state
                falsy_state.unsafe_filename.pop(name, None)
            self._process_statements(statement.body, body_state)
            self._process_statements(statement.orelse, else_state)
            state.replace_with(_FlowState.merge(body_state, else_state))
            if guaranteed_safe is not None:
                state.unsafe_filename.pop(guaranteed_safe, None)
            return

        if isinstance(statement, (ast.For, ast.AsyncFor)):
            self._scan_expression(statement.iter, state)
            body_state = state.clone()
            self._assign(statement.target, statement.iter, body_state)
            self._process_statements(statement.body, body_state)
            else_state = state.clone()
            self._process_statements(statement.orelse, else_state)
            state.replace_with(_FlowState.merge(state, body_state, else_state))
            return

        if isinstance(statement, ast.While):
            self._scan_expression(statement.test, state)
            body_state = state.clone()
            self._process_statements(statement.body, body_state)
            else_state = state.clone()
            self._process_statements(statement.orelse, else_state)
            state.replace_with(_FlowState.merge(state, body_state, else_state))
            return

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            for item in statement.items:
                self._scan_expression(item.context_expr, state)
                if item.optional_vars is not None:
                    self._assign(item.optional_vars, item.context_expr, state)
            self._process_statements(statement.body, state)
            return

        if isinstance(statement, ast.Try):
            body_state = state.clone()
            self._process_statements(statement.body, body_state)
            self._process_statements(statement.orelse, body_state)
            branches = [body_state]
            for handler in statement.handlers:
                handler_state = state.clone()
                self._process_statements(handler.body, handler_state)
                branches.append(handler_state)
            merged = _FlowState.merge(*branches)
            self._process_statements(statement.finalbody, merged)
            state.replace_with(merged)
            return

        if isinstance(statement, ast.Match):
            self._scan_expression(statement.subject, state)
            branches = [state.clone()]
            for case in statement.cases:
                case_state = state.clone()
                if case.guard is not None:
                    self._scan_expression(case.guard, case_state)
                self._process_statements(case.body, case_state)
                branches.append(case_state)
            state.replace_with(_FlowState.merge(*branches))
            return

        # Nested functions and classes are scanned independently by
        # ``_ModuleScanner`` and must not inherit the outer local state.
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._scan_expression(child, state)

    def _assign(self, target: ast.AST, value: ast.AST, state: _FlowState) -> None:
        if isinstance(target, (ast.Tuple, ast.List)) and _is_path_split_call(value):
            names = [_target_name(element) for element in target.elts]
            origin = self._unsafe_origin(value, state)
            if names:
                first = names[0]
                if first is not None:
                    state.directory_names.add(first)
                    if origin is None:
                        state.unsafe_filename.pop(first, None)
                    else:
                        state.unsafe_filename[first] = origin
                last = names[-1]
                if last is not None:
                    state.unsafe_filename.pop(last, None)
            return

        if isinstance(target, (ast.Tuple, ast.List)):
            if isinstance(value, (ast.Tuple, ast.List)) and len(target.elts) == len(
                value.elts
            ):
                for element, assigned_value in zip(target.elts, value.elts):
                    self._assign(element, assigned_value, state)
                return
            for element in target.elts:
                self._assign(element, value, state)
            return

        if not isinstance(target, ast.Name):
            return

        name = target.id
        self._record_name_role(name, state)
        path_root = self._path_root_name(value, state)
        if path_root is None:
            state.path_roots.pop(name, None)
        else:
            state.path_roots[name] = path_root
        if self._expression_is_resolved_path(value, state):
            state.resolved_paths.add(name)
        else:
            state.resolved_paths.discard(name)
        path_object_origin = self._path_object_origin(value, state)
        if path_object_origin is None:
            state.path_objects.pop(name, None)
        else:
            state.path_objects[name] = path_object_origin
        if self._expression_is_external(value, state):
            state.external.add(name)
        else:
            state.external.discard(name)

        origin = self._unsafe_origin(value, state)
        if origin is None:
            state.unsafe_filename.pop(name, None)
        else:
            state.unsafe_filename[name] = origin

    @staticmethod
    def _record_name_role(name: str, state: _FlowState) -> None:
        if _looks_like_directory(name):
            state.directory_names.add(name)

    def _path_object_origin(
        self,
        expression: ast.AST,
        state: _FlowState,
    ) -> int | None:
        if isinstance(expression, ast.Name):
            return state.path_objects.get(expression.id)
        if isinstance(expression, ast.Call):
            if _snake_case(_call_name(expression)) not in _PATH_TYPES:
                return None
            origins = [
                origin
                for argument in expression.args
                if (origin := self._unsafe_origin(argument, state)) is not None
            ]
            return min(origins) if origins else None
        return None

    def _path_root_name(
        self,
        expression: ast.AST,
        state: _FlowState,
    ) -> str | None:
        if isinstance(expression, ast.Name):
            return state.path_roots.get(expression.id)
        if isinstance(expression, ast.Call):
            qualified = _qualified_name(expression.func)
            if qualified in {"os.path.abspath", "os.path.realpath"} and expression.args:
                return self._path_root_name(expression.args[0], state)
            if (
                isinstance(expression.func, ast.Attribute)
                and expression.func.attr == "resolve"
            ):
                return self._path_root_name(expression.func.value, state)
            if _is_path_join_call(expression) and expression.args:
                return _directory_name(expression.args[0], state)
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
            return _directory_name(expression.left, state)
        return None

    def _expression_is_resolved_path(
        self,
        expression: ast.AST,
        state: _FlowState,
    ) -> bool:
        if isinstance(expression, ast.Name):
            return expression.id in state.resolved_paths
        if not isinstance(expression, ast.Call):
            return False
        qualified = _qualified_name(expression.func)
        if qualified in {"os.path.abspath", "os.path.realpath"}:
            return bool(expression.args)
        return bool(
            isinstance(expression.func, ast.Attribute)
            and expression.func.attr == "resolve"
        )

    def _expression_is_external(self, expression: ast.AST, state: _FlowState) -> bool:
        return any(
            isinstance(node, ast.Name) and node.id in state.external
            for node in ast.walk(expression)
        )

    def _unsafe_origin(self, expression: ast.AST, state: _FlowState) -> int | None:
        if _is_leaf_sanitizer(expression, state):
            return None

        origins: list[int] = []
        direct = self._direct_remote_filename_line(expression, state)
        if direct is not None:
            origins.append(direct)
        if isinstance(expression, ast.Name):
            prior = state.unsafe_filename.get(expression.id)
            if prior is not None:
                origins.append(prior)

        for child in ast.iter_child_nodes(expression):
            child_origin = self._unsafe_origin(child, state)
            if child_origin is not None:
                origins.append(child_origin)
        return min(origins) if origins else None

    def _guarded_value_after_if(
        self,
        statement: ast.If,
        state: _FlowState,
    ) -> str | None:
        """Return the exact value proven leaf-safe after an ordered ``if``."""

        if statement.orelse:
            return None
        compared_name = _basename_comparison_name(statement.test)
        if compared_name not in state.unsafe_filename:
            compared_name = None
        terminates = bool(statement.body) and isinstance(
            statement.body[-1],
            (ast.Raise, ast.Return, ast.Break, ast.Continue),
        )
        if compared_name is not None and terminates:
            return compared_name
        if compared_name is not None and _body_sanitizes_name(
            statement.body,
            compared_name,
        ):
            return compared_name

        contained_name = _fail_closed_containment_name(statement, state)
        if contained_name in state.unsafe_filename and terminates:
            return contained_name
        return None

    def _direct_remote_filename_line(
        self,
        expression: ast.AST,
        state: _FlowState,
    ) -> int | None:
        if isinstance(expression, ast.Attribute):
            if _looks_like_filename(expression.attr) and self._expression_is_external(
                expression.value, state
            ):
                return expression.lineno

        if isinstance(expression, ast.Call) and _call_name(expression) == "getattr":
            if len(expression.args) >= 2:
                key = _constant_string(expression.args[1])
                if (
                    key is not None
                    and _looks_like_filename(key)
                    and self._expression_is_external(expression.args[0], state)
                ):
                    return expression.lineno

        if isinstance(expression, ast.Subscript):
            key = _subscript_key(expression)
            if (
                key is not None
                and _looks_like_filename(key)
                and self._expression_is_external(expression.value, state)
            ):
                return expression.lineno
        return None

    def _scan_expression(self, expression: ast.AST, state: _FlowState) -> None:
        for node in ast.walk(expression):
            if (
                isinstance(node, ast.Call)
                and self._destination_sink_kind(node) is not None
            ):
                self._record_sink(node, state)

    def _record_sink(self, call: ast.Call, state: _FlowState) -> None:
        sink_kind = self._destination_sink_kind(call)
        if sink_kind is None:
            return
        all_values = [*call.args, *(keyword.value for keyword in call.keywords)]
        values = self._sink_path_values(call, sink_kind)
        unsafe: list[tuple[str, int]] = []
        for value in values:
            unsafe.extend(self._unsafe_leaf_values(value, state))
        if not unsafe:
            return

        has_directory_context = any(
            isinstance(node, ast.Name) and node.id in state.directory_names
            for value in all_values
            for node in ast.walk(value)
        ) or any(
            keyword.arg is not None and _looks_like_directory(keyword.arg)
            for keyword in call.keywords
        )
        has_destination_keyword = any(
            keyword.arg is not None
            and _looks_like_destination_keyword(keyword.arg)
            and self._unsafe_origin(keyword.value, state) is not None
            for keyword in call.keywords
        )
        if sink_kind == "custom_download" and not (
            has_directory_context
            or has_destination_keyword
        ):
            return

        variables = sorted({name for name, _ in unsafe})
        source_line = min(line for _, line in unsafe)
        sink_name = _call_name(call) or "file sink"
        description = (
            "An externally supplied filename reaches a download destination with "
            "explicit directory or destination context without basename-style "
            "leaf sanitization."
            if sink_kind == "custom_download"
            else "An externally supplied filename reaches a filesystem path sink "
            "without basename-style leaf sanitization."
        )
        self.findings.append({
            "rule_id": RULE_ID,
            "cwe": "CWE-22",
            "severity": "high",
            "confidence": 0.84,
            "file": self.filename,
            "line": call.lineno,
            "col": call.col_offset,
            "title": "Unsanitized remote filename used as download destination",
            "description": description,
            "message": description,
            "evidence": (
                f"filename source line {source_line} reaches {sink_name} "
                f"through {', '.join(variables)}"
            ),
            "source_line": source_line,
            "sink": sink_name,
            "variables": variables,
        })

    @staticmethod
    def _sink_path_values(call: ast.Call, sink_kind: str) -> list[ast.AST]:
        if sink_kind == "receiver_file":
            if isinstance(call.func, ast.Attribute):
                return [call.func.value]
            return []

        if sink_kind == "file_path_first":
            values = list(call.args[:1])
            values.extend(
                keyword.value
                for keyword in call.keywords
                if keyword.arg in {"file", "filename", "path"}
            )
            return values

        if sink_kind == "file_destination":
            values = list(call.args[1:2])
            values.extend(
                keyword.value
                for keyword in call.keywords
                if keyword.arg
                in {"dest", "destination", "dst", "target", "target_path"}
            )
            return values

        return [*call.args, *(keyword.value for keyword in call.keywords)]

    def _unsafe_leaf_values(
        self,
        expression: ast.AST,
        state: _FlowState,
    ) -> list[tuple[str, int]]:
        if _is_leaf_sanitizer(expression, state):
            return []

        values: list[tuple[str, int]] = []
        if isinstance(expression, ast.Name):
            origin = state.unsafe_filename.get(expression.id)
            if origin is not None:
                values.append((expression.id, origin))

        direct = self._direct_remote_filename_line(expression, state)
        if direct is not None:
            values.append(("<filename expression>", direct))

        for child in ast.iter_child_nodes(expression):
            values.extend(self._unsafe_leaf_values(child, state))
        return values

    @staticmethod
    def _destination_sink_kind(call: ast.Call) -> str | None:
        name = _call_name(call)
        if not name:
            return None
        normalized = _snake_case(name)
        words = set(normalized.split("_"))
        if normalized in _EXACT_FILE_SINKS:
            if isinstance(call.func, ast.Attribute) and normalized in {
                "open",
                "write_bytes",
                "write_text",
            }:
                return "receiver_file"
            if normalized in {"copy", "copy2", "copyfile", "move"}:
                return "file_destination"
            return "file_path_first"
        if "download" not in words:
            return None
        if words & _NON_FILESYSTEM_DOWNLOAD_WORDS:
            return None
        return "custom_download"


def _call_name(call: ast.Call) -> str:
    function = call.func
    if isinstance(function, ast.Name):
        return function.id
    if isinstance(function, ast.Attribute):
        return function.attr
    return ""


def _snake_case(name: str) -> str:
    with_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name)
    return re.sub(r"[^a-zA-Z0-9]+", "_", with_boundaries).strip("_").lower()


def _looks_like_filename(name: str) -> bool:
    normalized = _snake_case(name)
    return (
        normalized in _FILENAME_ATTRIBUTES
        or normalized.endswith("_filename")
        or normalized.endswith("_file_name")
    )


def _looks_like_remote_filename_parameter(name: str) -> bool:
    normalized = _snake_case(name)
    if not _looks_like_filename(normalized):
        return False
    return bool(set(normalized.split("_")) & _REMOTE_NAME_PREFIXES)


def _looks_like_directory(name: str) -> bool:
    normalized = _snake_case(name)
    return (
        normalized
        in {
            "base",
            "base_dir",
            "base_directory",
            "directory",
            "folder",
            "root",
            "tempdir",
            "tmpdir",
        }
        or normalized.endswith("_dir")
        or normalized.endswith("_directory")
        or normalized.endswith("_folder")
    )


def _looks_like_destination_keyword(name: str) -> bool:
    normalized = _snake_case(name)
    return _looks_like_filename(normalized) or normalized in {
        "dest",
        "destination",
        "destination_name",
        "local_name",
        "output",
        "output_name",
        "target",
        "target_name",
    }


def _is_leaf_sanitizer(expression: ast.AST, state: _FlowState) -> bool:
    if isinstance(expression, ast.Call):
        return _snake_case(_call_name(expression)) in _LEAF_SANITIZERS

    if isinstance(expression, ast.Attribute) and expression.attr == "name":
        value = expression.value
        if isinstance(value, ast.Call):
            return _snake_case(_call_name(value)) in _PATH_TYPES
        if isinstance(value, ast.Name):
            return value.id in state.path_objects

    if isinstance(expression, ast.Subscript) and _subscript_index(expression) == 1:
        return _is_path_split_call(expression.value)
    return False


def _is_path_split_call(expression: ast.AST) -> bool:
    return bool(
        isinstance(expression, ast.Call)
        and _qualified_name(expression.func)
        in {"ntpath.split", "os.path.split", "posixpath.split"}
    )


def _qualified_name(expression: ast.AST) -> str:
    parts: list[str] = []
    current = expression
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _is_path_join_call(expression: ast.AST) -> bool:
    return bool(
        isinstance(expression, ast.Call)
        and _qualified_name(expression.func)
        in {"ntpath.join", "os.path.join", "posixpath.join"}
    )


def _directory_name(expression: ast.AST, state: _FlowState) -> str | None:
    if isinstance(expression, ast.Name):
        return expression.id if expression.id in state.directory_names else None
    if isinstance(expression, ast.Call) and len(expression.args) == 1:
        if _snake_case(_call_name(expression)) in _PATH_TYPES | {"str"}:
            return _directory_name(expression.args[0], state)
    return None


def _guard_root_name(
    expression: ast.AST,
    state: _FlowState,
    *,
    require_separator: bool,
) -> str | None:
    if not require_separator:
        return _directory_name(expression, state)
    if not isinstance(expression, ast.BinOp) or not isinstance(expression.op, ast.Add):
        return None
    if _qualified_name(expression.right) != "os.sep":
        return None
    return _directory_name(expression.left, state)


def _basename_comparison_name(expression: ast.AST) -> str | None:
    if not isinstance(expression, ast.Compare) or len(expression.ops) != 1:
        return None
    if not isinstance(expression.ops[0], (ast.NotEq, ast.IsNot)):
        return None
    if len(expression.comparators) != 1:
        return None
    pairs = (
        (expression.left, expression.comparators[0]),
        (expression.comparators[0], expression.left),
    )
    for candidate, sanitized in pairs:
        if not isinstance(candidate, ast.Name):
            continue
        if _is_direct_leaf_sanitizer_for(sanitized, candidate.id):
            return candidate.id
    return None


def _is_direct_leaf_sanitizer_for(expression: ast.AST, name: str) -> bool:
    if isinstance(expression, ast.Call):
        if _snake_case(_call_name(expression)) not in _LEAF_SANITIZERS:
            return False
        return bool(
            expression.args
            and isinstance(expression.args[0], ast.Name)
            and expression.args[0].id == name
        )
    if isinstance(expression, ast.Attribute) and expression.attr == "name":
        value = expression.value
        return bool(
            isinstance(value, ast.Call)
            and _snake_case(_call_name(value)) in _PATH_TYPES
            and value.args
            and isinstance(value.args[0], ast.Name)
            and value.args[0].id == name
        )
    if isinstance(expression, ast.Subscript) and _subscript_index(expression) == 1:
        call = expression.value
        return bool(
            _is_path_split_call(call)
            and isinstance(call, ast.Call)
            and call.args
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == name
        )
    return False


def _body_sanitizes_name(statements: list[ast.stmt], name: str) -> bool:
    for statement in statements:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            value = statement.value
            if value is None:
                continue
            if any(isinstance(target, ast.Name) and target.id == name for target in targets):
                return _is_direct_leaf_sanitizer_for(value, name)
    return False


def _fail_closed_containment_name(
    statement: ast.If,
    state: _FlowState,
) -> str | None:
    test = statement.test
    if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
        return None
    call = test.operand
    if not isinstance(call, ast.Call) or call.keywords or len(call.args) != 1:
        return None
    function = call.func
    if not isinstance(function, ast.Attribute) or function.attr not in {
        "is_relative_to",
        "startswith",
    }:
        return None
    if not isinstance(function.value, ast.Name):
        return None
    candidate = function.value.id
    if candidate not in state.resolved_paths:
        return None
    require_separator = function.attr == "startswith"
    root = _guard_root_name(
        call.args[0],
        state,
        require_separator=require_separator,
    )
    if root is None or state.path_roots.get(candidate) != root:
        return None
    return candidate


def _simple_truthiness_name(expression: ast.AST) -> tuple[str, bool] | None:
    if isinstance(expression, ast.Name):
        return expression.id, True
    if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
        if isinstance(expression.operand, ast.Name):
            return expression.operand.id, False
    return None


def _target_name(target: ast.AST) -> str | None:
    return target.id if isinstance(target, ast.Name) else None


def _constant_string(expression: ast.AST) -> str | None:
    if isinstance(expression, ast.Constant) and isinstance(expression.value, str):
        return expression.value
    return None


def _subscript_key(expression: ast.Subscript) -> str | None:
    return _constant_string(expression.slice)


def _subscript_index(expression: ast.Subscript) -> int | None:
    value = expression.slice
    if isinstance(value, ast.Constant) and isinstance(value.value, int):
        return value.value
    return None


__all__ = ["RULE_ID", "scan_source"]
