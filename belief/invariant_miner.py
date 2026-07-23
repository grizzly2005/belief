"""Lightweight invariant mining for real-code counter-evidence.

This module extracts small, explicit guarantees from common defensive Python
patterns. It does not emit normal scan findings by itself; callers can use the
returned beliefs as supporting evidence for hypotheses.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import PurePosixPath
from typing import Iterable

from .models import (
    ArtifactKind,
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)


RUNTIME_SURFACES = {
    "runtime_web",
    "migration",
    "test",
    "deployment_or_packaging",
    "source",
}


@dataclass(frozen=True)
class InvariantSpec:
    expression: str
    invariant_type: str
    rule_id: str
    description: str
    lineno: int = 1
    function_name: str | None = None
    class_name: str | None = None
    confidence: float = 0.9
    variables: tuple[str, ...] | None = None
    result_used: bool | None = None


class InvariantMiner:
    """Extract defensive invariants from Python source with narrow AST rules."""

    def extract(
        self,
        source_code: str,
        file_path: str = "",
        module: str = "",
    ) -> list[Belief]:
        specs: list[InvariantSpec] = [
            InvariantSpec(
                expression=f"runtime.surface.{classify_runtime_surface(file_path)} == true",
                invariant_type="runtime_surface",
                rule_id="INVARIANT_RUNTIME_SURFACE",
                description=f"Runtime surface classified from path: {file_path or '<memory>'}.",
                lineno=1,
                confidence=0.75,
            )
        ]

        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return _dedupe_beliefs(
                self._belief_from_spec(spec, file_path, module) for spec in specs
            )

        specs.extend(self._module_filename_guarantees(tree, source_code))
        specs.extend(self._module_credential_context_guarantees(tree))

        class_names: dict[int, str] = {}
        for class_node in ast.walk(tree):
            if isinstance(class_node, ast.ClassDef):
                for child in class_node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        class_names[id(child)] = class_node.name

        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                specs.extend(
                    self._function_guarantees(
                        node,
                        source_code,
                        class_name=class_names.get(id(node)),
                    )
                )

        return _dedupe_beliefs(
            self._belief_from_spec(spec, file_path, module) for spec in specs
        )

    def _function_guarantees(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        source_code: str,
        *,
        class_name: str | None = None,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        function_nodes = list(_function_body_nodes(node))
        calls = [child for child in function_nodes if isinstance(child, ast.Call)]
        parent_map = _parent_map(node)
        call_names = {
            name.lower()
            for child in calls
            for name in [_call_name(child)]
            if name
        }
        func_name = node.name.lower()

        decorators = {_decorator_name(decorator).lower() for decorator in node.decorator_list}
        if "login_required" in decorators or any(name.endswith(".login_required") for name in decorators):
            specs.append(self._spec(
                "route.requires_login == true",
                "authorization",
                "INVARIANT_ROUTE_LOGIN_REQUIRED",
                "@login_required protects this route.",
                node.lineno,
                node.name,
                0.95,
            ))
        if "admin_required" in decorators or any(name.endswith(".admin_required") for name in decorators):
            specs.append(self._spec(
                "route.requires_admin == true",
                "authorization",
                "INVARIANT_ROUTE_ADMIN_REQUIRED",
                "@admin_required protects this route.",
                node.lineno,
                node.name,
                0.95,
            ))

        for call in calls:
            call_name = (_call_name(call) or "").lower()
            line = getattr(call, "lineno", node.lineno)
            result_used = _call_result_used(call, parent_map)
            if call_name.endswith(("realpath", "abspath")):
                specs.append(self._spec(
                    "path.is_normalized == true",
                    "path_safety",
                    "INVARIANT_PATH_NORMALIZED",
                    "Path is normalized through realpath/abspath before use.",
                    line,
                    node.name,
                    0.86,
                    variables=_call_output_variables(call, parent_map),
                    result_used=result_used,
                ))
            if call_name.endswith("commonpath"):
                specs.append(self._spec(
                    "path.is_within_store == true",
                    "path_safety",
                    "INVARIANT_PATH_COMMONPATH_BOUNDARY",
                    "commonpath is used to enforce a storage boundary.",
                    line,
                    node.name,
                    0.9,
                    variables=_commonpath_checked_variables(call, parent_map),
                    result_used=(
                        result_used and _call_enforces_guard(call, parent_map)
                    ),
                ))
            if call_name.endswith("basename"):
                specs.append(self._spec(
                    "filename.basename_only == true",
                    "path_safety",
                    "INVARIANT_FILENAME_BASENAME",
                    "basename strips directory components from a filename.",
                    line,
                    node.name,
                    0.82,
                    variables=_call_output_variables(call, parent_map),
                    result_used=result_used,
                ))
            if call_name.endswith("secure_filename"):
                specs.extend([
                    self._spec(
                        "filename.matches_allowed_pattern == true",
                        "path_safety",
                        "INVARIANT_FILENAME_SECURE_FILENAME",
                        "secure_filename derives a safe filename.",
                        line,
                        node.name,
                        0.9,
                        variables=_call_output_variables(call, parent_map),
                        result_used=result_used,
                    ),
                    self._spec(
                        "filename.user_controlled == false",
                        "generated_value",
                        "INVARIANT_FILENAME_SANITIZED_DERIVED",
                        "Filename is derived through a sanitizing transformation.",
                        line,
                        node.name,
                        0.8,
                        variables=_call_output_variables(call, parent_map),
                        result_used=result_used,
                    ),
                ])

        boundary_calls = [
            call
            for call in calls
            if _call_is_storage_boundary(call, parent_map)
        ]
        if func_name in {"verify", "store_contains", "path"}:
            if boundary_calls:
                boundary_call = min(
                    boundary_calls,
                    key=lambda call: (
                        getattr(call, "lineno", node.lineno),
                        getattr(call, "col_offset", 0),
                    ),
                )
                specs.append(self._spec(
                    f"storage.{func_name}.enforces_store_boundary == true",
                    "path_safety",
                    f"INVARIANT_STORAGE_{func_name.upper()}_BOUNDARY",
                    f"{node.name} enforces or delegates storage boundary validation.",
                    getattr(boundary_call, "lineno", node.lineno),
                    node.name,
                    0.92,
                    variables=(
                        _commonpath_checked_variables(boundary_call, parent_map)
                        if (_call_name(boundary_call) or "").lower().endswith("commonpath")
                        else _call_flow_variables(boundary_call, parent_map)
                    ),
                    result_used=_call_result_used(boundary_call, parent_map),
                ))

        if any(name.endswith(("uuid4", "token_urlsafe", "token_hex", "token_bytes")) for name in call_names):
            specs.append(self._spec(
                "identifier.server_generated == true",
                "generated_value",
                "INVARIANT_IDENTIFIER_SERVER_GENERATED",
                "Identifier value is generated server-side.",
                node.lineno,
                node.name,
                0.9,
            ))

        specs.extend(self._assignment_generated_value_guarantees(node))
        specs.extend(self._return_generated_value_guarantees(node))
        specs.extend(self._authorization_query_guarantees(node))
        specs.extend(self._escaping_guarantees(node))
        specs.extend(self._credential_context_guarantees(node))
        if class_name:
            return [replace(spec, class_name=class_name) for spec in specs]
        return specs

    def _module_filename_guarantees(
        self,
        tree: ast.Module,
        source_code: str,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                target_names = [name.lower() for target in targets for name in _target_names(target)]
                if not any("filename" in name or name.endswith("_re") for name in target_names):
                    continue
                value = node.value
                if value is None:
                    continue
                if isinstance(value, ast.Call):
                    name = (_call_name(value) or "").lower()
                    if name.endswith("compile") or name == "re.compile":
                        specs.append(self._spec(
                            "filename.matches_allowed_pattern == true",
                            "path_safety",
                            "INVARIANT_FILENAME_REGEX",
                            "Filename validation regex is compiled in this module.",
                            getattr(node, "lineno", 1),
                            None,
                            0.82,
                        ))
                segment = ast.get_source_segment(source_code, value) or ""
                if "filename" in " ".join(target_names) and re.search(r"[A-Za-z0-9_.-]", segment):
                    if "re.compile" in segment:
                        specs.append(self._spec(
                            "filename.matches_allowed_pattern == true",
                            "path_safety",
                            "INVARIANT_FILENAME_REGEX_SOURCE",
                            "Filename regex source suggests an allow-list pattern.",
                            getattr(node, "lineno", 1),
                            None,
                            0.78,
                        ))
        return specs

    def _module_credential_context_guarantees(self, tree: ast.Module) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            specs.extend(self._credential_context_from_node(node, None))
        return specs

    def _assignment_generated_value_guarantees(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        for node in _function_body_nodes(function):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            if value is None:
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [name.lower() for target in targets for name in _target_names(target)]
            if not names:
                continue
            dump = ast.dump(value).lower()
            is_generated = any(token in dump for token in [
                "uuid4", "token_urlsafe", "token_hex", "token_bytes",
                "interaction_count", "secure_filename",
            ])
            if not is_generated:
                continue
            if any("filename" in name or name.endswith("path") for name in names):
                variables = tuple(dict.fromkeys(names))
                specs.extend([
                    self._spec(
                        "filename.server_generated == true",
                        "generated_value",
                        "INVARIANT_FILENAME_SERVER_GENERATED",
                        "Filename/path is derived from server-side state.",
                        getattr(node, "lineno", function.lineno),
                        function.name,
                        0.84,
                        variables=variables,
                        result_used=True,
                    ),
                    self._spec(
                        "filename.user_controlled == false",
                        "generated_value",
                        "INVARIANT_FILENAME_NOT_DIRECT_USER_INPUT",
                        "Filename/path is not directly user-controlled.",
                        getattr(node, "lineno", function.lineno),
                        function.name,
                        0.8,
                        variables=variables,
                        result_used=True,
                    ),
                ])
        return specs

    def _return_generated_value_guarantees(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        if "filename" not in function.name.lower():
            return specs
        for node in _function_body_nodes(function):
            if not isinstance(node, ast.Return) or node.value is None:
                continue
            dump = ast.dump(node.value).lower()
            if not any(token in dump for token in [
                "uuid4", "token_urlsafe", "token_hex", "token_bytes", "interaction_count",
            ]):
                continue
            variables = tuple(sorted({
                child.id
                for child in ast.walk(node.value)
                if isinstance(child, ast.Name)
            }))
            specs.extend([
                self._spec(
                    "filename.server_generated == true",
                    "generated_value",
                    "INVARIANT_FILENAME_RETURN_SERVER_GENERATED",
                    "Returned filename is derived from server-side state.",
                    getattr(node, "lineno", function.lineno),
                    function.name,
                    0.84,
                    variables=variables,
                    result_used=True,
                ),
                self._spec(
                    "filename.user_controlled == false",
                    "generated_value",
                    "INVARIANT_FILENAME_RETURN_NOT_DIRECT_USER_INPUT",
                    "Returned filename is not directly user-controlled.",
                    getattr(node, "lineno", function.lineno),
                    function.name,
                    0.8,
                    variables=variables,
                    result_used=True,
                ),
            ])
        return specs

    def _authorization_query_guarantees(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        parent_map = _parent_map(function)
        for node in _function_body_nodes(function):
            if not isinstance(node, ast.Call):
                continue
            name = (_call_name(node) or "").lower()
            variables = _call_flow_variables(node, parent_map)
            result_used = _call_result_used(node, parent_map)
            if name.endswith("filter_by"):
                for kw in node.keywords:
                    if kw.arg is None:
                        continue
                    if kw.arg in {"source_id", "source_uuid"} and _looks_current_principal(kw.value):
                        specs.append(self._spec(
                            "query.scoped_to_current_source == true",
                            "authorization",
                            "INVARIANT_QUERY_SOURCE_SCOPED",
                            "Query is scoped to the logged-in/current source.",
                            getattr(node, "lineno", function.lineno),
                            function.name,
                            0.94,
                            variables=variables,
                            result_used=result_used,
                        ))
                    if kw.arg in {"user_id", "owner_id"} and _looks_current_principal(kw.value):
                        specs.append(self._spec(
                            "query.scoped_to_current_user == true",
                            "authorization",
                            "INVARIANT_QUERY_USER_SCOPED",
                            "Query is scoped to the logged-in/current user.",
                            getattr(node, "lineno", function.lineno),
                            function.name,
                            0.94,
                            variables=variables,
                            result_used=result_used,
                        ))
            if name.endswith("filter"):
                for arg in node.args:
                    if _comparison_scopes_to_principal(arg):
                        specs.append(self._spec(
                            "query.scoped_to_current_user == true",
                            "authorization",
                            "INVARIANT_QUERY_FILTER_OWNER_SCOPED",
                            "ORM filter ties owner/source/user id to the current principal.",
                            getattr(node, "lineno", function.lineno),
                            function.name,
                            0.9,
                            variables=variables,
                            result_used=result_used,
                        ))
        return specs

    def _escaping_guarantees(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        parent_map = _parent_map(function)
        for node in _function_body_nodes(function):
            if not isinstance(node, ast.Call):
                continue
            name = (_call_name(node) or "").lower()
            if name in {"escape", "html.escape"} or name.endswith(".escape"):
                specs.append(self._spec(
                    "html_output.user_values_escaped == true",
                    "escaping",
                    "INVARIANT_HTML_ESCAPE",
                    "User-visible HTML value is escaped.",
                    getattr(node, "lineno", function.lineno),
                    function.name,
                    0.9,
                    variables=_call_output_variables(node, parent_map),
                    result_used=_call_result_used(node, parent_map),
                ))
            if name.endswith("markup") or name == "markup":
                if _call_contains_escape(node):
                    specs.append(self._spec(
                        "markup.has_unescaped_user_input == false",
                        "escaping",
                        "INVARIANT_MARKUP_ESCAPED_FORMAT",
                        "Markup is built from an escaped formatted value.",
                        getattr(node, "lineno", function.lineno),
                        function.name,
                        0.9,
                        variables=_call_flow_variables(node, parent_map),
                        result_used=_call_result_used(node, parent_map),
                    ))
        return specs

    def _credential_context_guarantees(
        self,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        for node in ast.walk(function):
            specs.extend(self._credential_context_from_node(node, function.name))
        return specs

    def _credential_context_from_node(
        self,
        node: ast.AST,
        function_name: str | None,
    ) -> list[InvariantSpec]:
        specs: list[InvariantSpec] = []
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            return specs
        if value is None:
            return specs

        target_dump = " ".join(ast.dump(target).lower() for target in targets)
        value_dump = ast.dump(value).lower()
        if "authorization" in target_dump:
            specs.append(self._spec(
                "credential.value_is_header_name == true",
                "authorization",
                "INVARIANT_CREDENTIAL_HEADER_CONTEXT",
                "Authorization appears as an HTTP header name, not a stored secret.",
                getattr(node, "lineno", 1),
                function_name,
                0.78,
            ))
        if "bearer" in value_dump and ("access_token" in value_dump or "token" in value_dump):
            specs.append(self._spec(
                "credential.value_is_runtime_supplied == true",
                "authorization",
                "INVARIANT_CREDENTIAL_RUNTIME_SUPPLIED",
                "Bearer credential is derived from a runtime token variable.",
                getattr(node, "lineno", 1),
                function_name,
                0.78,
            ))
        return specs

    def _spec(
        self,
        expression: str,
        invariant_type: str,
        rule_id: str,
        description: str,
        lineno: int,
        function_name: str | None,
        confidence: float,
        *,
        variables: tuple[str, ...] | None = None,
        result_used: bool | None = None,
    ) -> InvariantSpec:
        return InvariantSpec(
            expression=expression,
            invariant_type=invariant_type,
            rule_id=rule_id,
            description=description,
            lineno=lineno,
            function_name=function_name,
            confidence=confidence,
            variables=variables,
            result_used=result_used,
        )

    def _belief_from_spec(
        self,
        spec: InvariantSpec,
        file_path: str,
        module: str,
    ) -> Belief:
        scope = Scope(
            file_path=file_path,
            function_name=spec.function_name,
            class_name=spec.class_name,
            module=module,
            line_start=spec.lineno,
            line_end=spec.lineno,
        )
        function_qualname = _function_qualname(spec.class_name, spec.function_name)
        stable_id = _stable_id(
            file_path,
            function_qualname or spec.function_name,
            spec.expression,
            spec.lineno,
        )
        return Belief(
            predicate=Predicate(
                expression=spec.expression,
                variables=(
                    spec.variables
                    if spec.variables is not None
                    else tuple(_variables_from_expression(spec.expression))
                ),
                anchor_lines=(spec.lineno,),
                natural_language=spec.description,
            ),
            scope=scope,
            justification=JustificationCategory.C1_FORMAL_VERIFICATION,
            epistemic_status=EpistemicStatus.BELIEF,
            logic_type=LogicType.FOL,
            artifact_kind=ArtifactKind.SOURCE_CODE,
            confidence_score=spec.confidence,
            id=stable_id,
            source_metadata={
                "source": "invariant_miner",
                "category": "guarantee",
                "invariant_type": spec.invariant_type,
                "rule_id": spec.rule_id,
                "severity": "info",
                "function_qualname": function_qualname,
                **(
                    {"result_used": spec.result_used}
                    if spec.result_used is not None
                    else {}
                ),
            },
        )


def classify_runtime_surface(file_path: str) -> str:
    """Classify a path into a broad runtime surface."""
    normalized = str(PurePosixPath(str(file_path or "").replace("\\", "/"))).lower()
    parts = [part for part in normalized.split("/") if part]
    part_set = set(parts)

    if "alembic" in part_set and "versions" in part_set:
        return "migration"
    if (
        "tests" in part_set
        or "test" in part_set
        or any(part.startswith("test_") or part.endswith("_test.py") for part in parts)
    ):
        return "test"
    if part_set & {"debian", "install_files", "devops", "molecule", "build"}:
        return "deployment_or_packaging"
    if part_set & {"source_app", "journalist_app"} or "/api/" in f"/{normalized}/" or "api2" in part_set:
        return "runtime_web"
    return "source"


def extract_invariants(
    source_code: str,
    file_path: str = "",
    module: str = "",
) -> list[Belief]:
    return InvariantMiner().extract(source_code, file_path=file_path, module=module)


def _dedupe_beliefs(beliefs: Iterable[Belief]) -> list[Belief]:
    seen: set[tuple[str, str, str | None, int | None]] = set()
    deduped: list[Belief] = []
    for belief in beliefs:
        key = (
            belief.predicate.expression,
            belief.scope.file_path,
            belief.scope.function_name,
            belief.scope.line_start,
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(belief)
    return sorted(
        deduped,
        key=lambda b: (
            b.scope.file_path,
            b.scope.line_start or 0,
            b.scope.function_name or "",
            b.predicate.expression,
        ),
    )


def _function_body_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterable[ast.AST]:
    """Yield nodes owned by ``function`` without entering nested scopes."""

    nested_scopes = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)

    def walk_owned(node: ast.AST) -> Iterable[ast.AST]:
        yield node
        if isinstance(node, nested_scopes):
            return
        for child in ast.iter_child_nodes(node):
            yield from walk_owned(child)

    for statement in function.body:
        yield from walk_owned(statement)


def _parent_map(root: ast.AST) -> dict[int, ast.AST]:
    return {
        id(child): parent
        for parent in ast.walk(root)
        for child in ast.iter_child_nodes(parent)
    }


def _flow_variables_in_nodes(nodes: Iterable[ast.AST]) -> tuple[str, ...]:
    names: list[str] = []

    def collect(node: ast.AST) -> None:
        if isinstance(node, ast.Name):
            names.append(node.id)
            return
        if isinstance(node, ast.Attribute):
            qualified = _name(node)
            if qualified:
                names.append(qualified)
            collect(node.value)
            return
        if isinstance(node, ast.Call):
            for argument in node.args:
                collect(argument)
            for keyword in node.keywords:
                collect(keyword.value)
            return
        for child in ast.iter_child_nodes(node):
            collect(child)

    for node in nodes:
        collect(node)
    return tuple(dict.fromkeys(name for name in names if name))


def _argument_flow_variables(call: ast.Call) -> tuple[str, ...]:
    return _flow_variables_in_nodes([
        *call.args,
        *(keyword.value for keyword in call.keywords),
    ])


def _commonpath_checked_variables(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> tuple[str, ...]:
    """Exclude the compared storage root from commonpath's checked value."""

    variables = _argument_flow_variables(call)
    current: ast.AST = call
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, ast.Compare):
            comparison_values = [parent.left, *parent.comparators]
            root_variables = set(_flow_variables_in_nodes(
                value
                for value in comparison_values
                if not _is_descendant(call, value)
            ))
            filtered = tuple(name for name in variables if name not in root_variables)
            if filtered:
                return filtered
            break
        if isinstance(parent, ast.stmt):
            break
        current = parent

    if call.args and isinstance(call.args[0], (ast.List, ast.Tuple)):
        elements = call.args[0].elts
        if len(elements) >= 2:
            candidates = _flow_variables_in_nodes(elements[1:])
            if candidates:
                return candidates
    return variables


def _assignment_targets_for_call(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> tuple[str, ...]:
    current: ast.AST = call
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, ast.Assign):
            return tuple(dict.fromkeys(
                name for target in parent.targets for name in _target_names(target)
            ))
        if isinstance(parent, ast.AnnAssign):
            return tuple(dict.fromkeys(_target_names(parent.target)))
        if isinstance(parent, ast.NamedExpr):
            return tuple(dict.fromkeys(_target_names(parent.target)))
        if isinstance(parent, (ast.Return, ast.Expr, ast.If, ast.While, ast.Assert)):
            break
        current = parent
    return ()


def _call_flow_variables(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> tuple[str, ...]:
    return tuple(dict.fromkeys((
        *_argument_flow_variables(call),
        *_assignment_targets_for_call(call, parent_map),
    )))


def _call_output_variables(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> tuple[str, ...]:
    """Name the transformed value, not the unsanitized input, when assigned."""

    targets = _assignment_targets_for_call(call, parent_map)
    return targets or _argument_flow_variables(call)


def _containing_statement(
    node: ast.AST,
    parent_map: dict[int, ast.AST],
) -> ast.stmt | None:
    current = node
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, ast.stmt):
            return parent
        current = parent
    return None


def _containing_function(
    node: ast.AST,
    parent_map: dict[int, ast.AST],
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    current = node
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return parent
        current = parent
    return None


def _call_result_used(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> bool:
    """Return whether the produced value participates in later computation."""

    current: ast.AST = call
    nested_expression_use = False
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, ast.Expr):
            return nested_expression_use
        if isinstance(parent, (ast.Return, ast.If, ast.While, ast.Assert)):
            return True
        if isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
            targets = _assignment_targets_for_call(call, parent_map)
            if not targets:
                return False
            statement = _containing_statement(call, parent_map)
            function = _containing_function(call, parent_map)
            if statement is None or function is None:
                return False
            statement_position = (
                getattr(statement, "lineno", 0),
                getattr(statement, "col_offset", 0),
            )
            for node in _function_body_nodes(function):
                if not isinstance(node, ast.Name) or not isinstance(node.ctx, ast.Load):
                    continue
                if node.id not in targets:
                    continue
                if (
                    getattr(node, "lineno", 0),
                    getattr(node, "col_offset", 0),
                ) > statement_position:
                    return True
            return False
        if isinstance(parent, ast.Call) and parent is not call:
            nested_expression_use = True
        current = parent
    return nested_expression_use


def _call_enforces_guard(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> bool:
    """Recognize only a returned assertion or a branch that blocks execution."""

    current: ast.AST = call
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, ast.Return):
            if (_call_name(call) or "").lower().endswith("commonpath"):
                return bool(
                    _condition_truth_means_safe(call, parent.value) is True
                    and _guard_context_is_unconditional(parent, parent_map)
                )
            return _guard_context_is_unconditional(parent, parent_map)
        if isinstance(parent, ast.Assert):
            return bool(
                _condition_truth_means_safe(call, parent.test) is True
                and _guard_context_is_unconditional(parent, parent_map)
            )
        if isinstance(parent, (ast.If, ast.While)) and _is_descendant(call, parent.test):
            return bool(
                _condition_truth_means_safe(call, parent.test) is False
                and _suite_blocks_execution(parent.body)
                and _guard_context_is_unconditional(parent, parent_map)
            )
        if isinstance(parent, ast.stmt):
            return False
        current = parent
    return False


def _call_is_storage_boundary(
    call: ast.Call,
    parent_map: dict[int, ast.AST],
) -> bool:
    name = (_call_name(call) or "").lower()
    result_used = _call_result_used(call, parent_map)
    if name.endswith("commonpath"):
        return result_used and _call_enforces_guard(call, parent_map)
    if name in {"verify", "store_contains"} or name.endswith((".verify", ".store_contains")):
        return result_used and _call_enforces_guard(call, parent_map)
    return False


def _condition_truth_means_safe(call: ast.Call, expression: ast.AST | None) -> bool | None:
    """Return whether a true expression means the checked value is contained."""

    if expression is None or not _is_descendant(call, expression):
        return None
    call_name = (_call_name(call) or "").lower()
    safe_when_true: bool | None = (
        True
        if call_name in {"store_contains", "verify"}
        or call_name.endswith((".store_contains", ".verify"))
        else None
    )
    current: ast.AST = call
    while current is not expression:
        parent = next(
            (
                candidate
                for candidate in ast.walk(expression)
                if current in ast.iter_child_nodes(candidate)
            ),
            None,
        )
        if parent is None:
            return None
        if isinstance(parent, ast.Compare):
            if len(parent.ops) != 1:
                return None
            if (
                (_call_name(call) or "").lower().endswith("commonpath")
                and not _commonpath_compare_matches_base(call, parent)
            ):
                return None
            if isinstance(parent.ops[0], ast.Eq):
                safe_when_true = True
            elif isinstance(parent.ops[0], ast.NotEq):
                safe_when_true = False
            else:
                return None
        elif isinstance(parent, ast.UnaryOp) and isinstance(parent.op, ast.Not):
            if safe_when_true is None:
                return None
            safe_when_true = not safe_when_true
        elif isinstance(parent, (ast.BoolOp, ast.IfExp, ast.Call)):
            return None
        current = parent
    return safe_when_true


def _commonpath_compare_matches_base(call: ast.Call, comparison: ast.Compare) -> bool:
    if (
        len(comparison.ops) != 1
        or len(comparison.comparators) != 1
        or not call.args
        or not isinstance(call.args[0], (ast.List, ast.Tuple))
        or not call.args[0].elts
    ):
        return False
    if _is_descendant(call, comparison.left):
        compared_value = comparison.comparators[0]
    elif _is_descendant(call, comparison.comparators[0]):
        compared_value = comparison.left
    else:
        return False
    return ast.dump(call.args[0].elts[0]) == ast.dump(compared_value)


def _suite_blocks_execution(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    final = statements[-1]
    if isinstance(final, ast.Raise):
        return True
    if isinstance(final, ast.Return):
        return final.value is None or isinstance(final.value, ast.Constant)
    if isinstance(final, ast.If):
        return bool(
            final.orelse
            and _suite_blocks_execution(final.body)
            and _suite_blocks_execution(final.orelse)
        )
    return False


def _guard_context_is_unconditional(
    guard_statement: ast.stmt,
    parent_map: dict[int, ast.AST],
) -> bool:
    """Reject guards that run only in an outer branch or absorbable try block."""

    current: ast.AST = guard_statement
    conditional_ancestors = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.IfExp,
        ast.Match,
    )
    while (parent := parent_map.get(id(current))) is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return True
        if isinstance(parent, conditional_ancestors):
            return False
        current = parent
    return False


def _is_descendant(candidate: ast.AST, root: ast.AST) -> bool:
    return any(node is candidate for node in ast.walk(root))


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        base = _name(node.func.value)
        return f"{base}.{node.func.attr}" if base else node.func.attr
    return None


def _decorator_name(node: ast.AST) -> str:
    if isinstance(node, ast.Call):
        return _name(node.func) or ""
    return _name(node) or ""


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Subscript):
        return _name(node.value)
    return None


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Attribute):
        name = _name(node)
        return [name] if name else []
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for element in node.elts for name in _target_names(element)]
    if isinstance(node, ast.Subscript):
        names = []
        base = _name(node.value)
        if base:
            names.append(base)
        key = _literal_string(node.slice)
        if key:
            names.append(key)
        return names
    return []


def _literal_string(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _looks_current_principal(node: ast.AST) -> bool:
    lowered = ast.dump(node).lower()
    return any(token in lowered for token in [
        "current_user",
        "logged_in_source",
        "session",
        "g.user",
        "request.user",
    ])


def _comparison_scopes_to_principal(node: ast.AST) -> bool:
    if not isinstance(node, ast.Compare):
        return False
    left = ast.dump(node.left).lower()
    comparators = " ".join(ast.dump(comp).lower() for comp in node.comparators)
    scoped_left = any(token in left for token in ["owner_id", "user_id", "source_id"])
    return scoped_left and any(token in comparators for token in [
        "current_user", "logged_in_source", "session", "g.user",
    ])


def _call_contains_escape(node: ast.Call) -> bool:
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = (_call_name(child) or "").lower()
        if name in {"escape", "html.escape"} or name.endswith(".escape"):
            return True
    return False


def _variables_from_expression(expression: str) -> list[str]:
    if "==" in expression:
        expression = expression.split("==", 1)[0]
    return [part for part in expression.strip().split(".") if part]


def _stable_id(*parts: object) -> str:
    raw = "\x1f".join(str(part or "") for part in parts)
    return "inv_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _function_qualname(class_name: str | None, function_name: str | None) -> str:
    if class_name and function_name:
        return f"{class_name}.{function_name}"
    return function_name or ""


__all__ = [
    "InvariantMiner",
    "extract_invariants",
    "classify_runtime_surface",
    "RUNTIME_SURFACES",
]
