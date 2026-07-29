"""Bounded AST semantics for Python web path and object-authorization flows.

This module is intentionally framework-light.  It discovers route-reachable
functions from decorators and local calls, summarizes transparent local
wrappers, and emits issues only when a concrete path or resource reaches a
security-sensitive use without the required dominating guard.
"""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, replace
from typing import Iterable


_PATH_IO_METHODS = frozenset({
    "open",
    "read_bytes",
    "read_text",
    "unlink",
    "write_bytes",
    "write_text",
})
_PATH_IO_FUNCTIONS = frozenset({
    "builtins.open",
    "io.open",
    "open",
    "os.open",
    "os.remove",
    "os.unlink",
    "shutil.rmtree",
})
_PATH_SANITIZERS = frozenset({
    "basename",
    "secure_filename",
})
_REJECTION_CALLS = frozenset({
    "abort",
    "deny",
    "forbidden",
    "handle_no_permission",
})
_ROUTE_DECORATORS = frozenset({
    "api_route",
    "delete",
    "get",
    "patch",
    "post",
    "put",
    "route",
    "websocket",
})
_AUTHORIZATION_TOKENS = (
    "authorize",
    "can_access",
    "has_object_permission",
    "has_permission",
    "is_authorized",
    "permission",
)


@dataclass(frozen=True)
class WebSecurityIssue:
    """One deterministic web-security concern projected into BELIEF."""

    cwe: str
    predicate: str
    description: str
    function_name: str
    line_start: int
    line_end: int
    line: int
    source: str
    sink: str
    variables: tuple[str, ...]
    missing_guarantees: tuple[str, ...]

    @property
    def sort_key(self) -> tuple:
        return (
            self.line,
            self.cwe,
            self.function_name,
            self.sink,
            self.source,
        )


@dataclass(frozen=True)
class _FunctionInfo:
    qualname: str
    parent: str
    node: ast.FunctionDef | ast.AsyncFunctionDef

    @property
    def name(self) -> str:
        return self.node.name


@dataclass(frozen=True)
class _PathValue:
    tainted: bool = False
    sanitized: bool = False
    bounded: bool = False
    unknown: bool = False
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class _ResourceValue:
    external: bool = False
    bindings: frozenset[str] = frozenset()
    externally_authorized: bool = False
    sources: tuple[str, ...] = ()


@dataclass(frozen=True)
class _LocalSummaries:
    path_sinks: dict[str, tuple[int, ...]]
    serializers: dict[str, tuple[int, ...]]
    mutators: dict[str, tuple[int, ...]]


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.stack: list[str] = []
        self.functions: list[_FunctionInfo] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(
        self,
        node: ast.AsyncFunctionDef,
    ) -> None:
        self._visit_function(node)

    def _visit_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        parent = ".".join(self.stack)
        qualname = ".".join((*self.stack, node.name))
        self.functions.append(
            _FunctionInfo(
                qualname=qualname,
                parent=parent,
                node=node,
            )
        )
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()


def analyze_web_security_semantics(
    tree: ast.AST,
) -> tuple[WebSecurityIssue, ...]:
    """Return route-reachable path and IDOR/BOLA issues in stable order."""

    collector = _FunctionCollector()
    collector.visit(tree)
    functions = collector.functions
    exposed = _route_reachable_functions(functions)
    summaries = _local_summaries(functions)
    issues: list[WebSecurityIssue] = []
    for info in functions:
        if info.qualname not in exposed:
            continue
        issues.extend(_path_issues(info, summaries))
        issues.extend(_resource_issues(info, summaries))
    unique = {
        issue.sort_key: issue
        for issue in issues
    }
    return tuple(unique[key] for key in sorted(unique))


def _route_reachable_functions(
    functions: list[_FunctionInfo],
) -> frozenset[str]:
    by_name: defaultdict[str, list[_FunctionInfo]] = defaultdict(list)
    by_parent: defaultdict[str, list[_FunctionInfo]] = defaultdict(list)
    for info in functions:
        by_name[info.name].append(info)
        by_parent[info.parent].append(info)

    reachable = {
        info.qualname
        for info in functions
        if _has_route_decorator(info.node)
    }
    changed = True
    while changed:
        changed = False
        for info in functions:
            if info.qualname not in reachable:
                continue
            referenced = _local_function_references(info.node)
            for name in referenced:
                for target in by_name.get(name, ()):
                    if target.qualname not in reachable:
                        reachable.add(target.qualname)
                        changed = True
            for nested in by_parent.get(info.qualname, ()):
                if nested.qualname not in reachable:
                    reachable.add(nested.qualname)
                    changed = True
    return frozenset(reachable)


def _has_route_decorator(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    for decorator in node.decorator_list:
        name = _call_name(
            decorator.func
            if isinstance(decorator, ast.Call)
            else decorator
        )
        if name.rsplit(".", 1)[-1].lower() in _ROUTE_DECORATORS:
            return True
    return False


def _local_function_references(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    names = set()
    for decorator in node.decorator_list:
        selected = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = _call_name(selected)
        if name:
            names.add(name.rsplit(".", 1)[-1])
        if isinstance(decorator, ast.Call):
            names.update(_name_references(decorator))
    for default in (
        *node.args.defaults,
        *(
            value
            for value in node.args.kw_defaults
            if value is not None
        ),
    ):
        names.update(_name_references(default))
        for call in (
            item
            for item in ast.walk(default)
            if isinstance(item, ast.Call)
        ):
            selected = _call_name(call.func)
            if selected:
                names.add(selected.rsplit(".", 1)[-1])
    for item in _function_nodes(node):
        if not isinstance(item, ast.Call):
            continue
        call = _call_name(item.func)
        if call:
            names.add(call.rsplit(".", 1)[-1])
        if call.rsplit(".", 1)[-1].lower() == "depends":
            names.update(_name_references(item))
    return names


def _local_summaries(
    functions: list[_FunctionInfo],
) -> _LocalSummaries:
    path_sinks: dict[str, set[int]] = defaultdict(set)
    serializers: dict[str, set[int]] = defaultdict(set)
    mutators: dict[str, set[int]] = defaultdict(set)
    signatures = {
        info.name: _parameters(info.node)
        for info in functions
    }

    for info in functions:
        parameters = signatures[info.name]
        for item in _function_nodes(info.node):
            if isinstance(item, ast.Call):
                for expression in _direct_path_sink_inputs(item):
                    path_sinks[info.name].update(
                        _parameter_references(expression, parameters)
                    )
            if isinstance(item, ast.Return) and item.value is not None:
                serializers[info.name].update(
                    _parameter_references(item.value, parameters)
                )
            if isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                targets = (
                    item.targets
                    if isinstance(item, ast.Assign)
                    else [item.target]
                )
                for target in targets:
                    mutators[info.name].update(
                        _mutated_parameter_references(
                            target,
                            parameters,
                        )
                    )
            if isinstance(item, ast.Call):
                tail = _call_name(item.func).rsplit(".", 1)[-1].lower()
                if tail in {"append", "clear", "delete", "pop", "remove", "set", "update"}:
                    mutators[info.name].update(
                        _parameter_references(item.func, parameters)
                    )

    changed = True
    while changed:
        changed = False
        for info in functions:
            parameters = signatures[info.name]
            for call in (
                item
                for item in _function_nodes(info.node)
                if isinstance(item, ast.Call)
            ):
                target = _call_name(call.func).rsplit(".", 1)[-1]
                for summaries in (path_sinks, serializers, mutators):
                    before = len(summaries[info.name])
                    for index in tuple(summaries.get(target, ())):
                        argument = _call_argument(call, index)
                        if argument is not None:
                            summaries[info.name].update(
                                _parameter_references(
                                    argument,
                                    parameters,
                                )
                            )
                    if len(summaries[info.name]) != before:
                        changed = True

    return _LocalSummaries(
        path_sinks={
            name: tuple(sorted(indices))
            for name, indices in path_sinks.items()
            if indices
        },
        serializers={
            name: tuple(sorted(indices))
            for name, indices in serializers.items()
            if indices
        },
        mutators={
            name: tuple(sorted(indices))
            for name, indices in mutators.items()
            if indices
        },
    )


def _path_issues(
    info: _FunctionInfo,
    summaries: _LocalSummaries,
) -> list[WebSecurityIssue]:
    state = {
        name: _PathValue(tainted=True, sources=(name,))
        for name in _parameters(info.node)
        if _looks_path_parameter(name)
    }
    issues: list[WebSecurityIssue] = []
    _process_path_block(
        info.node.body,
        state,
        info=info,
        summaries=summaries,
        issues=issues,
    )
    return issues


def _process_path_block(
    statements: list[ast.stmt],
    state: dict[str, _PathValue],
    *,
    info: _FunctionInfo,
    summaries: _LocalSummaries,
    issues: list[WebSecurityIssue],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(statement, ast.Assign):
            _scan_path_expression(
                statement.value,
                state,
                info=info,
                summaries=summaries,
                issues=issues,
            )
            value = _path_value(statement.value, state)
            for target in statement.targets:
                _assign_path_value(target, value, state)
            continue
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                _scan_path_expression(
                    statement.value,
                    state,
                    info=info,
                    summaries=summaries,
                    issues=issues,
                )
                _assign_path_value(
                    statement.target,
                    _path_value(statement.value, state),
                    state,
                )
            continue
        if isinstance(statement, ast.Expr):
            _scan_path_expression(
                statement.value,
                state,
                info=info,
                summaries=summaries,
                issues=issues,
            )
            continue
        if isinstance(statement, ast.Return):
            if statement.value is not None:
                _scan_path_expression(
                    statement.value,
                    state,
                    info=info,
                    summaries=summaries,
                    issues=issues,
                )
            continue
        if isinstance(statement, ast.If):
            _scan_path_expression(
                statement.test,
                state,
                info=info,
                summaries=summaries,
                issues=issues,
            )
            body_state = dict(state)
            for name in _allowed_path_boundaries(statement.test):
                current = body_state.get(name)
                if current is not None:
                    body_state[name] = replace(current, bounded=True)
            _process_path_block(
                statement.body,
                body_state,
                info=info,
                summaries=summaries,
                issues=issues,
            )
            _process_path_block(
                statement.orelse,
                dict(state),
                info=info,
                summaries=summaries,
                issues=issues,
            )
            if _suite_rejects(statement.body):
                for name in _enforced_path_boundaries(statement.test):
                    current = state.get(name)
                    if current is not None:
                        state[name] = replace(current, bounded=True)
            continue
        for child in _statement_blocks(statement):
            _process_path_block(
                child,
                dict(state),
                info=info,
                summaries=summaries,
                issues=issues,
            )


def _scan_path_expression(
    expression: ast.AST,
    state: dict[str, _PathValue],
    *,
    info: _FunctionInfo,
    summaries: _LocalSummaries,
    issues: list[WebSecurityIssue],
) -> None:
    for call in (
        item
        for item in ast.walk(expression)
        if isinstance(item, ast.Call)
    ):
        for value, sink in _path_sink_values(call, state, summaries):
            if (
                not value.tainted
                or value.unknown
                or value.sanitized
                or value.bounded
            ):
                continue
            source = value.sources[0] if value.sources else "web path input"
            issues.append(
                WebSecurityIssue(
                    cwe="CWE-22",
                    predicate="path.web_boundary_enforced == true",
                    description=(
                        "Route-reachable path input reaches a filesystem "
                        f"operation without a dominating boundary at line "
                        f"{call.lineno} (CWE-22)."
                    ),
                    function_name=info.qualname,
                    line_start=info.node.lineno,
                    line_end=info.node.end_lineno or info.node.lineno,
                    line=call.lineno,
                    source=source,
                    sink=sink,
                    variables=value.sources,
                    missing_guarantees=(
                        "path.is_within_store == true",
                        "filename allow-list or basename reduction",
                    ),
                )
            )


def _path_sink_values(
    call: ast.Call,
    state: dict[str, _PathValue],
    summaries: _LocalSummaries,
) -> list[tuple[_PathValue, str]]:
    name = _call_name(call.func)
    lowered = name.lower()
    result: list[tuple[_PathValue, str]] = []
    if isinstance(call.func, ast.Attribute):
        tail = call.func.attr.lower()
        if tail in _PATH_IO_METHODS:
            result.append((_path_value(call.func.value, state), name))
    elif lowered in _PATH_IO_FUNCTIONS and call.args:
        result.append((_path_value(call.args[0], state), name))

    target = name.rsplit(".", 1)[-1]
    for index in summaries.path_sinks.get(target, ()):
        argument = _call_argument(call, index)
        if argument is not None:
            result.append((_path_value(argument, state), name))
    return result


def _path_value(
    node: ast.AST | None,
    state: dict[str, _PathValue],
) -> _PathValue:
    if node is None:
        return _PathValue()
    if isinstance(node, ast.Name):
        return state.get(node.id, _PathValue())
    if isinstance(node, ast.Constant):
        return _PathValue()
    if isinstance(node, ast.Attribute):
        value = _path_value(node.value, state)
        if node.attr.lower() == "name" and value.tainted:
            return replace(value, sanitized=True, bounded=False)
        return value
    if isinstance(node, ast.Subscript):
        dotted = _call_name(node.value).lower()
        if _is_request_source_name(dotted):
            return _PathValue(
                tainted=True,
                sources=(dotted or "request value",),
            )
        return _merge_path_values(
            _path_value(node.value, state),
            _path_value(node.slice, state),
        )
    if isinstance(node, ast.BinOp):
        return _merge_path_values(
            _path_value(node.left, state),
            _path_value(node.right, state),
        )
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return _merge_path_values(
            *(_path_value(item, state) for item in node.elts)
        )
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        lowered = name.lower()
        tail = lowered.rsplit(".", 1)[-1]
        if _is_request_source_name(lowered):
            return _PathValue(
                tainted=True,
                sources=(name or "request value",),
            )
        if tail in _PATH_SANITIZERS and node.args:
            value = _path_value(node.args[0], state)
            return replace(value, sanitized=value.tainted, bounded=False)
        if tail == "path" and node.args:
            return _path_value(node.args[0], state)
        if tail in {"resolve", "absolute", "normpath", "abspath"}:
            receiver = (
                node.func.value
                if isinstance(node.func, ast.Attribute)
                else node.args[0] if node.args else None
            )
            return _path_value(receiver, state)
        if tail in {"join", "joinpath"}:
            values = [
                _path_value(argument, state)
                for argument in node.args
            ]
            if isinstance(node.func, ast.Attribute):
                values.insert(0, _path_value(node.func.value, state))
            return _merge_path_values(*values)
        values = [
            _path_value(argument, state)
            for argument in (
                *node.args,
                *(keyword.value for keyword in node.keywords)
            )
        ]
        combined = _merge_path_values(*values)
        if combined.tainted:
            return _PathValue(
                unknown=True,
                sources=combined.sources,
            )
        return combined
    return _merge_path_values(
        *(_path_value(child, state) for child in ast.iter_child_nodes(node))
    )


def _merge_path_values(*values: _PathValue) -> _PathValue:
    active = [value for value in values if value.tainted or value.unknown]
    if not active:
        return _PathValue()
    sources = tuple(sorted({
        source
        for value in active
        for source in value.sources
    }))
    tainted = any(value.tainted for value in active)
    return _PathValue(
        tainted=tainted,
        sanitized=tainted and all(
            value.sanitized
            for value in active
            if value.tainted
        ),
        bounded=tainted and all(
            value.bounded
            for value in active
            if value.tainted
        ),
        unknown=any(value.unknown for value in active),
        sources=sources,
    )


def _assign_path_value(
    target: ast.AST,
    value: _PathValue,
    state: dict[str, _PathValue],
) -> None:
    for name in _target_names(target):
        state[name] = value


def _enforced_path_boundaries(test: ast.AST) -> tuple[str, ...]:
    candidate = test.operand if isinstance(test, ast.UnaryOp) and isinstance(
        test.op,
        ast.Not,
    ) else None
    if not isinstance(candidate, ast.Call):
        return ()
    name = _call_name(candidate.func).lower()
    if not name.endswith(".is_relative_to"):
        return ()
    if not isinstance(candidate.func, ast.Attribute):
        return ()
    selected = _call_name(candidate.func.value)
    return (selected,) if selected else ()


def _allowed_path_boundaries(test: ast.AST) -> tuple[str, ...]:
    if not isinstance(test, ast.Call):
        return ()
    name = _call_name(test.func).lower()
    if not name.endswith(".is_relative_to"):
        return ()
    if not isinstance(test.func, ast.Attribute):
        return ()
    selected = _call_name(test.func.value)
    return (selected,) if selected else ()


def _resource_issues(
    info: _FunctionInfo,
    summaries: _LocalSummaries,
) -> list[WebSecurityIssue]:
    external_ids = {
        name
        for name in _parameters(info.node)
        if _looks_resource_identifier(name)
    }
    authority = _authority_dimensions(info.node)
    if not authority:
        return []
    output_names = {
        name
        for item in _function_nodes(info.node)
        if isinstance(item, ast.Return) and item.value is not None
        for name in _name_references(item.value)
    }
    state: dict[str, _ResourceValue] = {}
    issues: list[WebSecurityIssue] = []
    _process_resource_block(
        info.node.body,
        state,
        info=info,
        summaries=summaries,
        external_ids=external_ids,
        required_bindings=authority,
        output_names=output_names,
        issues=issues,
    )
    return issues


def _process_resource_block(
    statements: list[ast.stmt],
    state: dict[str, _ResourceValue],
    *,
    info: _FunctionInfo,
    summaries: _LocalSummaries,
    external_ids: set[str],
    required_bindings: frozenset[str],
    output_names: set[str],
    issues: list[WebSecurityIssue],
) -> None:
    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(statement, ast.Assign):
            targets = {
                name
                for target in statement.targets
                for name in _target_names(target)
            }
            if _is_external_identifier_expr(
                statement.value,
                external_ids,
            ):
                external_ids.update(
                    name
                    for name in targets
                    if _looks_resource_identifier(name)
                )
            _scan_resource_expression(
                statement.value,
                state,
                info=info,
                summaries=summaries,
                required_bindings=required_bindings,
                exposed_result=bool(
                    (targets & output_names) - {"_"}
                ),
                issues=issues,
            )
            value = _resource_value(
                statement.value,
                state,
                external_ids=external_ids,
            )
            for target in statement.targets:
                for name in _target_names(target):
                    state[name] = value
            continue
        if isinstance(statement, ast.AnnAssign):
            if statement.value is not None:
                targets = set(_target_names(statement.target))
                if _is_external_identifier_expr(
                    statement.value,
                    external_ids,
                ):
                    external_ids.update(
                        name
                        for name in targets
                        if _looks_resource_identifier(name)
                    )
                _scan_resource_expression(
                    statement.value,
                    state,
                    info=info,
                    summaries=summaries,
                    required_bindings=required_bindings,
                    exposed_result=bool(
                        (targets & output_names) - {"_"}
                    ),
                    issues=issues,
                )
                value = _resource_value(
                    statement.value,
                    state,
                    external_ids=external_ids,
                )
                for name in targets:
                    state[name] = value
            continue
        if isinstance(statement, ast.Expr):
            _scan_resource_expression(
                statement.value,
                state,
                info=info,
                summaries=summaries,
                required_bindings=required_bindings,
                exposed_result=False,
                issues=issues,
            )
            continue
        if isinstance(statement, ast.Return):
            if statement.value is not None:
                _scan_resource_expression(
                    statement.value,
                    state,
                    info=info,
                    summaries=summaries,
                    required_bindings=required_bindings,
                    exposed_result=True,
                    issues=issues,
                )
                direct = _resource_value(
                    statement.value,
                    state,
                    external_ids=external_ids,
                )
                _append_resource_issue(
                    direct,
                    sink="return",
                    line=statement.lineno,
                    info=info,
                    required_bindings=required_bindings,
                    issues=issues,
                )
            continue
        if isinstance(statement, ast.If):
            body_state = dict(state)
            for name, bindings in _resource_allow_bindings(
                statement.test
            ).items():
                current = body_state.get(name)
                if current is not None:
                    body_state[name] = replace(
                        current,
                        bindings=current.bindings | bindings,
                    )
            for name in _externally_authorized_resources(
                statement.test
            ):
                current = body_state.get(name)
                if current is not None:
                    body_state[name] = replace(
                        current,
                        externally_authorized=True,
                    )
            _process_resource_block(
                statement.body,
                body_state,
                info=info,
                summaries=summaries,
                external_ids=external_ids,
                required_bindings=required_bindings,
                output_names=output_names,
                issues=issues,
            )
            _process_resource_block(
                statement.orelse,
                dict(state),
                info=info,
                summaries=summaries,
                external_ids=external_ids,
                required_bindings=required_bindings,
                output_names=output_names,
                issues=issues,
            )
            if _suite_rejects(statement.body):
                for name, bindings in _resource_guard_bindings(
                    statement.test
                ).items():
                    current = state.get(name)
                    if current is not None:
                        state[name] = replace(
                            current,
                            bindings=current.bindings | bindings,
                        )
                for name in _externally_authorized_resources(
                    statement.test
                ):
                    current = state.get(name)
                    if current is not None:
                        state[name] = replace(
                            current,
                            externally_authorized=True,
                        )
            continue
        for child in _statement_blocks(statement):
            _process_resource_block(
                child,
                dict(state),
                info=info,
                summaries=summaries,
                external_ids=external_ids,
                required_bindings=required_bindings,
                output_names=output_names,
                issues=issues,
            )


def _scan_resource_expression(
    expression: ast.AST,
    state: dict[str, _ResourceValue],
    *,
    info: _FunctionInfo,
    summaries: _LocalSummaries,
    required_bindings: frozenset[str],
    exposed_result: bool,
    issues: list[WebSecurityIssue],
) -> None:
    for call in (
        item
        for item in ast.walk(expression)
        if isinstance(item, ast.Call)
    ):
        target = _call_name(call.func).rsplit(".", 1)[-1]
        for index in summaries.mutators.get(target, ()):
            argument = _call_argument(call, index)
            if argument is None:
                continue
            _append_resource_issue(
                _resource_value(argument, state, external_ids=set()),
                sink=_call_name(call.func),
                line=call.lineno,
                info=info,
                required_bindings=required_bindings,
                issues=issues,
            )
        if not exposed_result:
            continue
        for index in summaries.serializers.get(target, ()):
            argument = _call_argument(call, index)
            if argument is None:
                continue
            _append_resource_issue(
                _resource_value(argument, state, external_ids=set()),
                sink=_call_name(call.func),
                line=call.lineno,
                info=info,
                required_bindings=required_bindings,
                issues=issues,
            )


def _append_resource_issue(
    value: _ResourceValue,
    *,
    sink: str,
    line: int,
    info: _FunctionInfo,
    required_bindings: frozenset[str],
    issues: list[WebSecurityIssue],
) -> None:
    if (
        not value.external
        or value.externally_authorized
        or required_bindings <= value.bindings
    ):
        return
    missing = tuple(sorted(required_bindings - value.bindings))
    source = value.sources[0] if value.sources else "resource identifier"
    issues.append(
        WebSecurityIssue(
            cwe="CWE-639",
            predicate=(
                "resource.access_bound_to_required_principal == true"
            ),
            description=(
                "Route-controlled resource reaches an observable or "
                "state-changing use without binding "
                f"{', '.join(missing)} before line {line} (CWE-639)."
            ),
            function_name=info.qualname,
            line_start=info.node.lineno,
            line_end=info.node.end_lineno or info.node.lineno,
            line=line,
            source=source,
            sink=sink,
            variables=value.sources,
            missing_guarantees=tuple(
                f"resource bound to {dimension}"
                for dimension in missing
            ),
        )
    )


def _resource_value(
    node: ast.AST | None,
    state: dict[str, _ResourceValue],
    *,
    external_ids: set[str],
) -> _ResourceValue:
    if node is None:
        return _ResourceValue()
    if isinstance(node, ast.Name):
        return state.get(node.id, _ResourceValue())
    if isinstance(node, ast.Call):
        name = _call_name(node.func)
        tail = name.rsplit(".", 1)[-1].lower()
        if tail == "get" and node.args:
            sources = tuple(sorted(
                external_ids & _name_references(node.args[0])
            ))
            if sources:
                return _ResourceValue(
                    external=True,
                    sources=sources,
                )
        if tail == "next" and node.args:
            selected = _generator_resource_value(
                node.args[0],
                external_ids,
            )
            if selected.external:
                return selected
    if isinstance(node, ast.Subscript):
        sources = tuple(sorted(
            external_ids & _name_references(node.slice)
        ))
        if sources:
            return _ResourceValue(
                external=True,
                sources=sources,
            )
    return _ResourceValue()


def _generator_resource_value(
    node: ast.AST,
    external_ids: set[str],
) -> _ResourceValue:
    if not isinstance(node, ast.GeneratorExp):
        return _ResourceValue()
    comparisons = [
        candidate
        for generator in node.generators
        for condition in generator.ifs
        for candidate in ast.walk(condition)
        if isinstance(candidate, ast.Compare)
    ]
    identifier_sources: set[str] = set()
    bindings: set[str] = set()
    for comparison in comparisons:
        expressions = [comparison.left, *comparison.comparators]
        for expression in expressions:
            field = _field_dimension(expression)
            if field is None:
                continue
            _, dimension = field
            others = [
                item
                for item in expressions
                if item is not expression
            ]
            referenced = {
                name
                for item in others
                for name in _name_references(item)
            }
            if dimension == "resource":
                identifier_sources.update(referenced & external_ids)
            elif dimension == "owner" and any(
                _is_owner_authority_name(name)
                for name in referenced
            ):
                bindings.add("owner")
            elif dimension == "tenant" and any(
                _is_tenant_authority_name(name)
                for name in referenced
            ):
                bindings.add("tenant")
    if not identifier_sources:
        return _ResourceValue()
    return _ResourceValue(
        external=True,
        bindings=frozenset(bindings),
        sources=tuple(sorted(identifier_sources)),
    )


def _resource_guard_bindings(
    test: ast.AST,
) -> dict[str, frozenset[str]]:
    return _resource_comparison_bindings(
        test,
        operator_types=(ast.NotEq, ast.IsNot),
    )


def _resource_allow_bindings(
    test: ast.AST,
) -> dict[str, frozenset[str]]:
    return _resource_comparison_bindings(
        test,
        operator_types=(ast.Eq, ast.Is),
    )


def _resource_comparison_bindings(
    test: ast.AST,
    *,
    operator_types: tuple[type[ast.cmpop], ...],
) -> dict[str, frozenset[str]]:
    result: defaultdict[str, set[str]] = defaultdict(set)
    for comparison in (
        item
        for item in ast.walk(test)
        if isinstance(item, ast.Compare)
        and any(
            isinstance(operator, operator_types)
            for operator in item.ops
        )
    ):
        expressions = [comparison.left, *comparison.comparators]
        for expression in expressions:
            field = _field_dimension(expression)
            if field is None:
                continue
            resource, dimension = field
            referenced = {
                name
                for other in expressions
                if other is not expression
                for name in _name_references(other)
            }
            if dimension == "owner" and any(
                _is_owner_authority_name(name)
                for name in referenced
            ):
                result[resource].add("owner")
            if dimension == "tenant" and any(
                _is_tenant_authority_name(name)
                for name in referenced
            ):
                result[resource].add("tenant")
    return {
        name: frozenset(bindings)
        for name, bindings in result.items()
    }


def _is_external_identifier_expr(
    node: ast.AST,
    external_ids: set[str],
) -> bool:
    if external_ids & _name_references(node):
        return True
    if isinstance(node, (ast.Call, ast.Subscript)):
        return _is_request_source_name(
            _call_name(node.func)
            if isinstance(node, ast.Call)
            else _call_name(node.value)
        )
    return False


def _externally_authorized_resources(test: ast.AST) -> tuple[str, ...]:
    result = set()
    for call in (
        item
        for item in ast.walk(test)
        if isinstance(item, ast.Call)
    ):
        name = _call_name(call.func).lower()
        if not any(token in name for token in _AUTHORIZATION_TOKENS):
            continue
        result.update(
            argument.id
            for argument in call.args
            if isinstance(argument, ast.Name)
        )
    return tuple(sorted(result))


def _field_dimension(node: ast.AST) -> tuple[str, str] | None:
    resource = ""
    field = ""
    if isinstance(node, ast.Call):
        name = (
            _call_name(node.func)
            .rsplit(".", 1)[-1]
            .lower()
            .strip("_")
        )
        if (
            name in {"field", "getattr"}
            or "field" in name
            or "attribute" in name
        ) and len(node.args) >= 2:
            resource = _call_name(node.args[0])
            field = _literal_string(node.args[1])
    elif isinstance(node, ast.Attribute):
        resource = _call_name(node.value)
        field = node.attr
    elif isinstance(node, ast.Subscript):
        resource = _call_name(node.value)
        field = _literal_string(node.slice)
    if not resource or not field:
        return None
    normalized = field.lower()
    if any(token in normalized for token in ("owner", "user", "principal")):
        return resource, "owner"
    if any(token in normalized for token in ("tenant", "organization", "workspace")):
        return resource, "tenant"
    if normalized == "id" or normalized.endswith(("_id", "_uuid")):
        return resource, "resource"
    return None


def _authority_dimensions(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> frozenset[str]:
    names = {
        name
        for name in _parameters(node)
    }
    for item in _function_nodes(node):
        if isinstance(item, (ast.Assign, ast.AnnAssign)):
            targets = (
                item.targets
                if isinstance(item, ast.Assign)
                else [item.target]
            )
            names.update(
                name
                for target in targets
                for name in _target_names(target)
            )
    dimensions = set()
    if any(_is_owner_authority_name(name) for name in names):
        dimensions.add("owner")
    if any(_is_tenant_authority_name(name) for name in names):
        dimensions.add("tenant")
    return frozenset(dimensions)


def _is_owner_authority_name(name: str) -> bool:
    normalized = name.lower()
    return (
        normalized
        in {
            "current_user",
            "current_user_id",
            "principal",
            "principal_id",
            "user",
            "user_id",
        }
        or normalized.endswith("_user_id")
        or normalized.endswith("_principal_id")
    )


def _is_tenant_authority_name(name: str) -> bool:
    normalized = name.lower()
    return (
        normalized
        in {
            "organization_id",
            "org_id",
            "tenant_id",
            "workspace_id",
        }
        or normalized.endswith("_tenant_id")
        or normalized.endswith("_organization_id")
    )


def _looks_resource_identifier(name: str) -> bool:
    normalized = name.lower()
    if normalized in {"id", "resource_id", "resource_uuid"}:
        return True
    return (
        normalized.endswith(("_id", "_uuid"))
        and not _is_owner_authority_name(normalized)
        and not _is_tenant_authority_name(normalized)
    )


def _looks_path_parameter(name: str) -> bool:
    normalized = name.lower()
    return (
        normalized in {"file", "filename", "path", "raw_path"}
        or normalized.endswith(("_file", "_filename", "_path"))
        and not normalized.endswith((
            "output_path",
            "project_path",
        ))
    )


def _is_request_source_name(name: str) -> bool:
    lowered = name.lower()
    return any(
        lowered == prefix or lowered.startswith(prefix + ".")
        for prefix in (
            "request.args",
            "request.form",
            "request.get",
            "request.headers",
            "request.json",
            "request.query_params",
            "self.request.args",
            "self.request.get",
        )
    )


def _direct_path_sink_inputs(call: ast.Call) -> tuple[ast.AST, ...]:
    name = _call_name(call.func).lower()
    if isinstance(call.func, ast.Attribute):
        if call.func.attr.lower() in _PATH_IO_METHODS:
            return (call.func.value,)
    elif name in _PATH_IO_FUNCTIONS and call.args:
        return (call.args[0],)
    return ()


def _parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    return tuple(
        argument.arg
        for argument in (
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        )
    )


def _parameter_references(
    node: ast.AST,
    parameters: tuple[str, ...],
) -> set[int]:
    names = _name_references(node)
    return {
        index
        for index, parameter in enumerate(parameters)
        if parameter in names
    }


def _mutated_parameter_references(
    target: ast.AST,
    parameters: tuple[str, ...],
) -> set[int]:
    base = target
    while isinstance(base, (ast.Attribute, ast.Subscript)):
        base = base.value
    if not isinstance(base, ast.Name):
        return set()
    return {
        index
        for index, parameter in enumerate(parameters)
        if parameter == base.id
    }


def _call_argument(call: ast.Call, index: int) -> ast.AST | None:
    if index < len(call.args):
        return call.args[index]
    return None


def _function_nodes(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterable[ast.AST]:
    stack: list[ast.AST] = list(reversed(node.body))
    while stack:
        current = stack.pop()
        yield current
        children = []
        for child in ast.iter_child_nodes(current):
            if isinstance(
                child,
                (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
            ):
                continue
            children.append(child)
        stack.extend(reversed(children))


def _statement_blocks(statement: ast.stmt) -> list[list[ast.stmt]]:
    result = []
    for name in ("body", "orelse", "finalbody"):
        value = getattr(statement, name, None)
        if isinstance(value, list):
            result.append(value)
    handlers = getattr(statement, "handlers", None)
    if isinstance(handlers, list):
        result.extend(
            handler.body
            for handler in handlers
            if isinstance(handler, ast.ExceptHandler)
        )
    return result


def _suite_rejects(statements: list[ast.stmt]) -> bool:
    if not statements:
        return False
    for statement in statements:
        if isinstance(statement, (ast.Raise, ast.Return)):
            return True
        if isinstance(statement, ast.Expr) and isinstance(
            statement.value,
            ast.Call,
        ):
            tail = _call_name(statement.value.func).rsplit(".", 1)[-1].lower()
            if tail in _REJECTION_CALLS:
                return True
    return False


def _target_names(node: ast.AST) -> tuple[str, ...]:
    if isinstance(node, ast.Name):
        return (node.id,)
    if isinstance(node, (ast.Tuple, ast.List)):
        return tuple(
            name
            for item in node.elts
            for name in _target_names(item)
        )
    return ()


def _name_references(node: ast.AST) -> set[str]:
    return {
        item.id
        for item in ast.walk(node)
        if isinstance(item, ast.Name)
    }


def _call_name(node: ast.AST | None) -> str:
    if node is None:
        return ""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _call_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _call_name(node.func)
    if isinstance(node, ast.Subscript):
        return _call_name(node.value)
    return ""


def _literal_string(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


__all__ = [
    "WebSecurityIssue",
    "analyze_web_security_semantics",
]
