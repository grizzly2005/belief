"""Lightweight local dataflow and def-use tracing for BELIEF v4.

This module is intentionally small. It complements the existing taint engine
with explainable source -> variable -> sanitizer/guarantee -> sink paths that
can be attached to hypothesis metadata, without turning PyT/Pyre/Semgrep into
core dependencies.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from .models import (
    Belief,
    EpistemicStatus,
    Finding,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from .security_taxonomy import sanitizer_names, source_names


@dataclass(frozen=True)
class DataFlowNode:
    """A stable node in a local dataflow explanation."""

    node_id: str
    kind: str
    expression: str
    line: int | None = None
    variable: str = ""
    function_name: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    file_path: str = ""
    column: int | None = None
    statement_order: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "expression": self.expression,
            "line": self.line,
            "variable": self.variable,
            "function_name": self.function_name,
            "file": self.file_path,
            "column": self.column,
            "statement_order": self.statement_order,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DataFlowEdge:
    """A stable edge between two local dataflow nodes."""

    source_id: str
    target_id: str
    kind: str = "flows_to"
    line: int | None = None
    file_path: str = ""
    column: int | None = None
    function_name: str = ""
    statement_order: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "kind": self.kind,
            "line": self.line,
            "file": self.file_path,
            "column": self.column,
            "function_name": self.function_name,
            "statement_order": self.statement_order,
        }


@dataclass(frozen=True)
class DataFlowPath:
    """A compact path from a source-like value to a security-sensitive sink."""

    source: DataFlowNode
    sink: DataFlowNode
    nodes: tuple[DataFlowNode, ...]
    edges: tuple[DataFlowEdge, ...] = ()
    file_path: str = ""
    function_name: str = ""
    intermediate_variables: tuple[str, ...] = ()
    sanitizers: tuple[DataFlowNode, ...] = ()
    guarantees: tuple[DataFlowNode, ...] = ()
    missing_sanitizers: tuple[str, ...] = ()
    confidence: float = 0.75
    review_priority: str = "medium"
    sink_category: str = ""
    cwe: str = ""
    diagnostics: tuple[dict[str, Any], ...] = ()
    rejection_reason: str = ""
    truncation_reason: str = ""

    @property
    def sink_line(self) -> int | None:
        return self.sink.line

    @property
    def source_line(self) -> int | None:
        return self.source.line

    @property
    def sanitized(self) -> bool:
        return bool(self.sanitizers or self.guarantees)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.expression,
            "sink": self.sink.expression,
            "path": [node.expression for node in self.nodes],
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "file": self.file_path,
            "function": self.function_name,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "source_column": self.source.column,
            "sink_column": self.sink.column,
            "sink_category": self.sink_category,
            "cwe": self.cwe,
            "intermediate_variables": list(self.intermediate_variables),
            "sanitizers": [node.expression for node in self.sanitizers],
            "guarantees": [node.expression for node in self.guarantees],
            "missing_sanitizers": list(self.missing_sanitizers),
            "missing_guarantees": list(self.missing_sanitizers),
            "confidence": round(float(self.confidence), 3),
            "review_priority": self.review_priority,
            "diagnostics": [dict(item) for item in self.diagnostics],
            "rejection_reason": self.rejection_reason,
            "truncation_reason": self.truncation_reason,
        }


@dataclass
class DataFlowSummary:
    """Local dataflow facts extracted from one Python module."""

    file_path: str
    definitions: dict[str, list[DataFlowNode]] = field(default_factory=dict)
    uses: dict[str, list[DataFlowNode]] = field(default_factory=dict)
    edges: list[DataFlowEdge] = field(default_factory=list)
    paths: list[DataFlowPath] = field(default_factory=list)
    variable_origins: dict[str, DataFlowNode] = field(default_factory=dict)
    functions: list[str] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "definitions": {
                name: [node.to_dict() for node in nodes]
                for name, nodes in sorted(self.definitions.items())
            },
            "uses": {
                name: [node.to_dict() for node in nodes]
                for name, nodes in sorted(self.uses.items())
            },
            "edges": [edge.to_dict() for edge in self.edges],
            "paths": [path.to_dict() for path in self.paths],
            "functions": sorted(self.functions),
            "diagnostics": [dict(item) for item in self.diagnostics],
        }


@dataclass(frozen=True)
class _SinkSpec:
    name: str
    category: str
    cwe: str
    required_guarantees: tuple[str, ...]
    severity: str = "high"


@dataclass(frozen=True)
class _ReturnModel:
    kind: str
    expression: str
    call_name: str
    argument_index: int | None = None


@dataclass(frozen=True)
class _FunctionSignature:
    parameters: tuple[str, ...]
    positional_parameters: tuple[str, ...]
    implicit_receiver: bool = False


@dataclass
class _ExpressionState:
    source: DataFlowNode | None = None
    nodes: tuple[DataFlowNode, ...] = ()
    sanitizers: tuple[DataFlowNode, ...] = ()
    guarantees: tuple[DataFlowNode, ...] = ()
    variables: tuple[str, ...] = ()
    confidence: float = 0.75

    @property
    def active(self) -> bool:
        return self.source is not None or bool(self.nodes or self.sanitizers or self.guarantees)


DEFAULT_SOURCE_PATTERNS = source_names()

DEFAULT_SANITIZER_PATTERNS = sanitizer_names()

DEFAULT_GUARANTEE_PATTERNS = (
    "Storage.path",
    "Storage.get_default.path",
    "safe_join",
    "secure_filename",
    "os.path.basename",
)

_PATH_GUARANTEE_BY_PATTERN = {
    "storage.path": "storage.path.enforces_store_boundary == true",
    "storage.get_default.path": "storage.path.enforces_store_boundary == true",
    "safe_join": "path.is_within_store == true",
    "secure_filename": "filename.matches_allowed_pattern == true",
    "os.path.basename": "filename.basename_only == true",
    "basename": "filename.basename_only == true",
}


def analyze_source_dataflow(
    source_code: str,
    filename: str = "",
    *,
    sources: Iterable[str] | None = None,
    sinks: Iterable[str] | None = None,
    sanitizers: Iterable[str] | None = None,
    max_depth: int = 32,
    max_nodes: int = 10_000,
    cycle_detection: bool = True,
) -> DataFlowSummary:
    """Parse and analyze one Python source string."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return DataFlowSummary(file_path=filename)
    return extract_local_def_use(
        tree,
        filename,
        source_code=source_code,
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        max_depth=max_depth,
        max_nodes=max_nodes,
        cycle_detection=cycle_detection,
    )


def extract_local_def_use(
    module_ast: ast.AST,
    filename: str = "",
    *,
    source_code: str = "",
    sources: Iterable[str] | None = None,
    sinks: Iterable[str] | None = None,
    sanitizers: Iterable[str] | None = None,
    max_depth: int = 32,
    max_nodes: int = 10_000,
    cycle_detection: bool = True,
) -> DataFlowSummary:
    """Extract local def-use facts and source-to-sink paths from a module AST."""
    analyzer = _LocalDataFlowAnalyzer(
        filename=filename,
        source_code=source_code,
        sources=tuple(sources or DEFAULT_SOURCE_PATTERNS),
        sinks=tuple(sinks or ()),
        sanitizers=tuple(sanitizers or DEFAULT_SANITIZER_PATTERNS),
        max_depth=max_depth,
        max_nodes=max_nodes,
        cycle_detection=cycle_detection,
    )
    return analyzer.analyze(module_ast)


def find_source_to_sink_paths(
    module_ast: ast.AST,
    sources: Iterable[str] | None = None,
    sinks: Iterable[str] | None = None,
    sanitizers: Iterable[str] | None = None,
    *,
    filename: str = "",
    source_code: str = "",
    max_depth: int = 32,
    max_nodes: int = 10_000,
    cycle_detection: bool = True,
) -> list[DataFlowPath]:
    """Return deterministic local source/sanitizer/guarantee/sink paths."""
    return extract_local_def_use(
        module_ast,
        filename,
        source_code=source_code,
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        max_depth=max_depth,
        max_nodes=max_nodes,
        cycle_detection=cycle_detection,
    ).paths


def trace_variable_origin(name: str, scope: DataFlowSummary | dict[str, Any]) -> DataFlowNode | None:
    """Return the last known local origin for a variable from a summary-like scope."""
    if isinstance(scope, DataFlowSummary):
        return scope.variable_origins.get(name)
    value = scope.get(name) if isinstance(scope, dict) else None
    if isinstance(value, DataFlowNode):
        return value
    if isinstance(value, list) and value and isinstance(value[-1], DataFlowNode):
        return value[-1]
    return None


def dataflow_paths_to_beliefs(paths: Iterable[DataFlowPath]) -> list[Belief]:
    """Convert paths to optional BELIEF information-flow beliefs."""
    beliefs = []
    for path in sorted(paths, key=_path_sort_key):
        expr = (
            f"dataflow({path.source.expression}) reaches {path.sink.expression} "
            f"{'with sanitizer_or_guarantee' if path.sanitized else 'without sanitizer_or_guarantee'}"
        )
        beliefs.append(Belief(
            predicate=Predicate(
                expression=expr,
                variables=tuple(path.intermediate_variables),
                anchor_lines=tuple(
                    line for line in (path.source_line, path.sink_line) if line is not None
                ),
                natural_language=(
                    f"Local dataflow from {path.source.expression} to {path.sink.expression}."
                ),
            ),
            scope=Scope(
                file_path=path.file_path,
                function_name=path.function_name or None,
                line_start=path.source_line,
                line_end=path.sink_line,
            ),
            justification=(
                JustificationCategory.C2_CALLER_VERIFICATION
                if path.sanitized
                else JustificationCategory.C5_NO_JUSTIFICATION
            ),
            epistemic_status=EpistemicStatus.BELIEF if path.sanitized else EpistemicStatus.HOPE,
            logic_type=LogicType.INFORMATION_FLOW,
            confidence_score=path.confidence,
            cwe=path.cwe,
            source_metadata={
                "source": "dataflow",
                "rule_id": "LOCAL_DATAFLOW_PATH",
                "severity": "info" if path.sanitized else path.review_priority,
                "dataflow": path.to_dict(),
            },
        ))
    return beliefs


def dataflow_paths_to_hypotheses(paths: Iterable[DataFlowPath]) -> list[dict[str, Any]]:
    """Serialize paths in the compact shape used by hypothesis metadata."""
    return [_path_to_hypothesis_payload(path) for path in sorted(paths, key=_path_sort_key)]


def attach_dataflow_to_findings(
    findings: Iterable[Finding],
    summaries: dict[str, DataFlowSummary] | Iterable[DataFlowSummary],
    *,
    show_dataflow: bool = False,
) -> list[Finding]:
    """Attach top-level dataflow metadata to findings in place."""
    summary_map = _summary_map(summaries)
    enriched = list(findings)
    for finding in enriched:
        payload = dataflow_for_finding(finding, summary_map, show_dataflow=show_dataflow)
        if not payload:
            continue
        metadata = dict(finding.metadata or {})
        metadata["dataflow"] = payload
        finding.metadata = metadata
    return enriched


def dataflow_for_finding(
    finding: Finding,
    summaries: dict[str, DataFlowSummary] | Iterable[DataFlowSummary],
    *,
    show_dataflow: bool = False,
) -> dict[str, Any] | None:
    """Select the best local dataflow paths for a finding."""
    paths = dataflow_paths_for_finding(finding, summaries)
    if not paths:
        return None
    best = paths[0]
    payload = _path_to_hypothesis_payload(best)
    payload["path_count"] = len(paths)
    if show_dataflow:
        payload["paths"] = [_path_to_hypothesis_payload(path) for path in paths[:5]]
    return payload


def dataflow_paths_for_finding(
    finding: Finding,
    summaries: dict[str, DataFlowSummary] | Iterable[DataFlowSummary],
) -> list[DataFlowPath]:
    """Return deterministic candidate paths related to a finding."""
    summary_map = _summary_map(summaries)
    file_key = _norm_path(finding.file)
    candidate_summaries = []
    if file_key in summary_map:
        candidate_summaries.append(summary_map[file_key])
    else:
        file_tail = file_key.split("/")[-1]
        candidate_summaries.extend(
            summary for key, summary in summary_map.items()
            if key.endswith("/" + file_tail) or key == file_tail
        )

    wanted = _categories_for_finding(finding)
    wanted_function = _finding_function_context(finding)
    paths: list[DataFlowPath] = []
    for summary in candidate_summaries:
        for path in summary.paths:
            if wanted and path.sink_category not in wanted and path.cwe not in wanted:
                continue
            if wanted_function and not _same_function(path.function_name, wanted_function):
                continue
            paths.append(path)
    line = _finding_sink_line(finding)
    return sorted(paths, key=lambda path: (
        0 if line and path.sink_line == line else 1,
        abs((path.sink_line or 0) - line) if line else 0,
        0 if not path.sanitized else 1,
        _path_sort_key(path),
    ))


def _finding_function_context(finding: Finding) -> str:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    explicit = str(
        metadata.get("function_qualname")
        or metadata.get("function_name")
        or ""
    ).strip()
    class_name = str(metadata.get("class_name") or "").strip()
    if class_name and explicit and "." not in explicit:
        return f"{class_name}.{explicit}"
    return explicit


def _same_function(path_function: str, finding_function: str) -> bool:
    path_name = str(path_function or "").replace("::", ".").strip(".")
    finding_name = str(finding_function or "").replace("::", ".").strip(".")
    if not path_name or not finding_name:
        return False
    if "." in path_name and "." in finding_name:
        return path_name == finding_name
    return (
        path_name == finding_name
        or path_name.endswith("." + finding_name)
        or finding_name.endswith("." + path_name)
    )


def _finding_sink_line(finding: Finding) -> int:
    metadata = finding.metadata if isinstance(finding.metadata, dict) else {}
    dataflow = metadata.get("dataflow") if isinstance(metadata.get("dataflow"), dict) else {}
    for value in (
        metadata.get("sink_line"),
        dataflow.get("sink_line"),
        metadata.get("line_number"),
    ):
        if isinstance(value, int) and value > 0:
            return value
        if isinstance(value, str) and value.isdigit() and int(value) > 0:
            return int(value)
    for text in (finding.evidence, finding.description, finding.title):
        match = re.search(r"\bline\s*[:#]?\s*(\d+)\b", str(text or ""), re.IGNORECASE)
        if match:
            return int(match.group(1))
    return int(finding.line or 0)


class _LocalDataFlowAnalyzer:
    def __init__(
        self,
        *,
        filename: str,
        source_code: str,
        sources: tuple[str, ...],
        sinks: tuple[str, ...],
        sanitizers: tuple[str, ...],
        max_depth: int,
        max_nodes: int,
        cycle_detection: bool,
    ) -> None:
        self.filename = filename
        self.source_code = source_code
        self.sources = tuple(pattern.lower() for pattern in sources)
        self.extra_sinks = tuple(pattern.lower() for pattern in sinks)
        self.sanitizers = tuple(pattern.lower() for pattern in sanitizers)
        self.max_depth = max(0, int(max_depth))
        self.max_nodes = max(0, int(max_nodes))
        self.cycle_detection = bool(cycle_detection)
        self.summary = DataFlowSummary(file_path=filename)
        self.return_models: dict[str, _ReturnModel] = {}
        self.return_signatures: dict[str, _FunctionSignature] = {}
        self.local_function_names: set[str] = set()
        self._visited_nodes = 0
        self._statement_order = 0
        self._current_statement_order = 0
        self._diagnostic_keys: set[tuple[Any, ...]] = set()

    def analyze(self, module_ast: ast.AST) -> DataFlowSummary:
        self.return_models = self._collect_return_models(module_ast)
        for node in getattr(module_ast, "body", []):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.summary.functions.append(node.name)
                self._analyze_function(node)
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        function_name = f"{node.name}.{child.name}"
                        self.summary.functions.append(function_name)
                        self._analyze_function(child, function_name=function_name)
        diagnostics = tuple(dict(item) for item in self.summary.diagnostics)
        truncation_reason = next(
            (
                str(item["reason"])
                for item in diagnostics
                if str(item.get("reason", "")).startswith("analysis_truncated_")
            ),
            "",
        )
        self.summary.paths = sorted(
            (
                replace(
                    path,
                    diagnostics=diagnostics,
                    truncation_reason=truncation_reason,
                )
                for path in self._dedupe_paths(self.summary.paths)
            ),
            key=_path_sort_key,
        )
        return self.summary

    def _collect_return_models(self, module_ast: ast.AST) -> dict[str, _ReturnModel]:
        functions = [
            node for node in ast.walk(module_ast)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self.local_function_names = {node.name for node in functions}
        self.return_signatures = {}
        models: dict[str, _ReturnModel] = {}
        for node in functions:
            positional_parameters = [
                arg.arg
                for arg in (
                    list(node.args.posonlyargs)
                    + list(node.args.args)
                )
            ]
            parameters = [
                *positional_parameters,
                *(arg.arg for arg in node.args.kwonlyargs),
            ]
            decorators = {
                (_expr_name(decorator) or "").lower()
                for decorator in node.decorator_list
            }
            implicit_receiver = bool(
                positional_parameters
                and positional_parameters[0] in {"self", "cls"}
                and "staticmethod" not in decorators
            )
            self.return_signatures[node.name] = _FunctionSignature(
                parameters=tuple(parameters),
                positional_parameters=tuple(positional_parameters),
                implicit_receiver=implicit_receiver,
            )
            returns = _function_returns(node)
            inferred = [self._infer_return_model(item.value, parameters) for item in returns]
            if not returns:
                inferred = [_ReturnModel("constant", "None", "")]
            if inferred and all(item is not None for item in inferred):
                first = inferred[0]
                if first is not None and all(item == first for item in inferred[1:]):
                    models[node.name] = first
        return models

    def _infer_return_model(
        self,
        value: ast.AST | None,
        parameters: list[str],
    ) -> _ReturnModel | None:
        if value is None or _is_static_constant(value):
            expression = "None" if value is None else _source_segment(value, self.source_code)
            return _ReturnModel("constant", expression, "")
        if isinstance(value, ast.Name) and value.id in parameters:
            return _ReturnModel("identity", value.id, "", parameters.index(value.id))
        if not isinstance(value, ast.Call):
            return None
        call_name = _call_name(value) or ""
        argument_index = _parameter_index_for_call(value, parameters)
        if argument_index is None:
            return None
        lowered = call_name.lower()
        expression = _source_segment(value, self.source_code)
        if self._is_sanitizer_call(lowered):
            return _ReturnModel("sanitizer", expression, call_name, argument_index)
        if self._is_guarantee_call(lowered):
            return _ReturnModel(
                "guarantee",
                _guarantee_expression(call_name) or expression,
                call_name,
                argument_index,
            )
        if call_name.rsplit(".", 1)[-1] in self.local_function_names:
            return _ReturnModel("delegate", expression, call_name, argument_index)
        return None

    def _analyze_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        function_name: str | None = None,
    ) -> None:
        state: dict[str, _ExpressionState] = {}
        function = function_name or node.name
        for arg in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            source = self._make_node(
                "source",
                arg.arg,
                getattr(arg, "lineno", node.lineno),
                variable=arg.arg,
                function_name=function,
                metadata={"source_type": "function_parameter"},
                column=getattr(arg, "col_offset", None),
            )
            state[arg.arg] = _ExpressionState(
                source=source,
                nodes=(source,),
                variables=(arg.arg,),
                confidence=0.55,
            )
            self.summary.variable_origins[arg.arg] = source

        for stmt in node.body:
            self._process_stmt(stmt, state, function)

    def _process_stmt(
        self,
        stmt: ast.stmt,
        state: dict[str, _ExpressionState],
        function: str,
    ) -> None:
        self._statement_order += 1
        self._current_statement_order = self._statement_order
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            nested_name = f"{function}.{stmt.name}"
            self.summary.functions.append(nested_name)
            self._analyze_function(stmt, function_name=nested_name)
            return

        if isinstance(stmt, ast.Assign):
            expr_state = self._eval_expr(stmt.value, state, function)
            self._scan_expr_for_sinks(stmt.value, state, function)
            for target in stmt.targets:
                self._assign_target(target, expr_state, state, function, getattr(stmt, "lineno", None))
            return

        if isinstance(stmt, ast.AnnAssign):
            expr_state = (
                self._eval_expr(stmt.value, state, function)
                if stmt.value is not None
                else _ExpressionState()
            )
            if stmt.value is not None:
                self._scan_expr_for_sinks(stmt.value, state, function)
            self._assign_target(stmt.target, expr_state, state, function, getattr(stmt, "lineno", None))
            return

        if isinstance(stmt, ast.AugAssign):
            self._scan_expr_for_sinks(stmt.value, state, function)
            target_name = _expr_name(stmt.target)
            if target_name and target_name in state:
                self._assign_target(stmt.target, state[target_name], state, function, getattr(stmt, "lineno", None))
            return

        if isinstance(stmt, ast.Expr):
            self._scan_expr_for_sinks(stmt.value, state, function)
            return

        if isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._scan_expr_for_sinks(stmt.value, state, function)
            return

        if isinstance(stmt, ast.With):
            for item in stmt.items:
                context_state = self._eval_expr(item.context_expr, state, function)
                self._scan_expr_for_sinks(item.context_expr, state, function)
                if item.optional_vars is not None:
                    self._assign_target(
                        item.optional_vars,
                        context_state,
                        state,
                        function,
                        getattr(item.context_expr, "lineno", getattr(stmt, "lineno", None)),
                    )
            for child in stmt.body:
                self._process_stmt(child, state, function)
            return

        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            control_expression = (
                getattr(stmt, "test", None)
                or getattr(stmt, "iter", None)
            )
            if control_expression is not None:
                self._scan_expr_for_sinks(control_expression, state, function)
            enforced_guards = (
                self._enforced_commonpath_guards(stmt, state, function)
                if isinstance(stmt, ast.If)
                else ()
            )
            branch_states: list[dict[str, _ExpressionState]] = []
            for branch in (list(stmt.body), list(stmt.orelse)):
                branch_state = dict(state)
                for child in branch:
                    self._process_stmt(child, branch_state, function)
                branch_states.append(branch_state)
            self._merge_control_flow_states(state, branch_states)
            for variable, expected_nodes, guarantee in enforced_guards:
                current = state.get(variable)
                if current is None:
                    continue
                if tuple(node.node_id for node in current.nodes) != expected_nodes:
                    continue
                state[variable] = _with_flow_node(current, guarantee)
            return

        if isinstance(stmt, ast.Try):
            branches = [list(stmt.body), *(list(handler.body) for handler in stmt.handlers)]
            if stmt.orelse:
                branches.append(list(stmt.orelse))
            branch_states = []
            for branch in branches:
                branch_state = dict(state)
                for child in branch:
                    self._process_stmt(child, branch_state, function)
                branch_states.append(branch_state)
            self._merge_control_flow_states(state, branch_states)
            for child in stmt.finalbody:
                self._process_stmt(child, state, function)
            return

        for child in ast.iter_child_nodes(stmt):
            if isinstance(child, ast.expr):
                self._scan_expr_for_sinks(child, state, function)

    def _assign_target(
        self,
        target: ast.AST,
        expr_state: _ExpressionState,
        state: dict[str, _ExpressionState],
        function: str,
        line: int | None,
    ) -> None:
        target_names = _target_names(target)
        for target_name in target_names:
            target_node = self._make_node(
                "variable",
                target_name,
                line,
                variable=target_name,
                function_name=function,
                column=getattr(target, "col_offset", None),
            )
            self.summary.definitions.setdefault(target_name, []).append(target_node)
            new_nodes = _append_node(expr_state.nodes, target_node)
            new_edges = _edges_for_nodes(new_nodes)
            self.summary.edges.extend(new_edges)
            assigned = replace(
                expr_state,
                nodes=new_nodes,
                variables=_dedupe_strings((*expr_state.variables, target_name)),
            )
            state[target_name] = assigned
            self.summary.variable_origins[target_name] = expr_state.source or target_node

    def _eval_expr(
        self,
        node: ast.AST | None,
        state: dict[str, _ExpressionState],
        function: str,
        *,
        depth: int = 0,
        call_stack: tuple[str, ...] = (),
    ) -> _ExpressionState:
        if node is None:
            return _ExpressionState()
        if depth > self.max_depth:
            self._diagnose(
                "analysis_truncated_max_depth",
                function=function,
                line=getattr(node, "lineno", None),
            )
            return _ExpressionState()
        if not self._visit_node(node, function):
            return _ExpressionState()

        expr = _source_segment(node, self.source_code)
        line = getattr(node, "lineno", None)

        if isinstance(node, ast.Name):
            if node.id in state:
                self._record_use(node.id, line, function, getattr(node, "col_offset", None))
                return state[node.id]
            return _ExpressionState()

        source_kind = self._source_kind(node)
        if source_kind:
            source = self._make_node(
                "source",
                expr,
                line,
                variable=_expr_name(node) or "",
                function_name=function,
                metadata={"source_type": source_kind},
                column=getattr(node, "col_offset", None),
            )
            return _ExpressionState(
                source=source,
                nodes=(source,),
                variables=tuple(_names_in(node)),
                confidence=0.86,
            )

        if isinstance(node, ast.Call):
            call_name = _call_name(node) or ""
            lowered = call_name.lower()
            argument_nodes = [
                *node.args,
                *(kw.value for kw in node.keywords if kw.value is not None),
            ]
            argument_states = [
                self._eval_expr(
                    child,
                    state,
                    function,
                    depth=depth + 1,
                    call_stack=call_stack,
                )
                for child in argument_nodes
            ]
            arg_state = _ExpressionState()
            for child_state in argument_states:
                arg_state = _combine_states(arg_state, child_state)

            if lowered.endswith(".read") or lowered == "read":
                source = self._make_node(
                    "source",
                    expr,
                    line,
                    function_name=function,
                    metadata={"source_type": "file"},
                    column=getattr(node, "col_offset", None),
                )
                return _ExpressionState(
                    source=source,
                    nodes=(source,),
                    variables=tuple(_names_in(node)),
                    confidence=0.68,
                )

            declared_return_model = (
                self.return_models.get(call_name)
                or self.return_models.get(call_name.rsplit(".", 1)[-1])
            )
            return_model = None
            if declared_return_model is not None:
                return_model = self._resolve_return_model(
                    declared_return_model,
                    function=function,
                    line=line,
                    depth=depth,
                    call_stack=call_stack,
                )
                if return_model is None:
                    # A known same-file call whose model cannot be resolved is
                    # unknown, not an identity transform.  In particular, a
                    # depth/node/cycle cutoff must never turn into a positive
                    # source-to-sink path through the generic argument fallback.
                    return _ExpressionState()
            if return_model and return_model.kind == "constant":
                return _ExpressionState()
            if return_model and arg_state.active:
                selected_state = self._select_return_argument_state(
                    node,
                    argument_states,
                    return_model,
                )
                if not selected_state.active:
                    return _ExpressionState()
                kind = return_model.kind
                metadata = {"call_name": call_name, "source": "same_file_return_model"}
                expression = return_model.expression
                if kind == "guarantee":
                    expression = return_model.expression or _guarantee_expression(call_name)
                if kind == "identity":
                    node_kind = "call"
                    expression = expr
                else:
                    node_kind = "guarantee" if kind == "guarantee" else "sanitizer"
                flow_node = self._make_node(
                    node_kind,
                    expression or expr,
                    line,
                    function_name=function,
                    metadata=metadata,
                    column=getattr(node, "col_offset", None),
                )
                return _with_flow_node(selected_state, flow_node)

            receiver_state = _ExpressionState()
            if declared_return_model is None and isinstance(node.func, ast.Attribute):
                receiver_state = self._eval_expr(
                    node.func.value,
                    state,
                    function,
                    depth=depth + 1,
                    call_stack=call_stack,
                )
            transform_state = _combine_states(receiver_state, arg_state)

            if self._is_sanitizer_call(lowered) and transform_state.active:
                sanitizer = self._make_node(
                    "sanitizer",
                    expr,
                    line,
                    function_name=function,
                    metadata={"call_name": call_name},
                    column=getattr(node, "col_offset", None),
                )
                return _with_flow_node(transform_state, sanitizer)

            if self._is_guarantee_call(lowered):
                guarantee = self._make_node(
                    "guarantee",
                    _guarantee_expression(call_name) or expr,
                    line,
                    function_name=function,
                    metadata={"call_name": call_name},
                    column=getattr(node, "col_offset", None),
                )
                if transform_state.source is not None:
                    return _with_flow_node(transform_state, guarantee)
                return _ExpressionState()

            # A receiver participates in the result of an unknown transforming
            # method (for example ``tainted_path.resolve()``), but it is not an
            # argument to a sink such as ``file.open()``.  Sink arguments are
            # evaluated independently by ``_sink_argument_states``.
            if self._sink_spec(node) is not None:
                return arg_state
            return transform_state

        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr, ast.FormattedValue)):
            return self._combine_child_states(
                list(ast.iter_child_nodes(node)),
                state,
                function,
                depth=depth + 1,
                call_stack=call_stack,
            )

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._combine_child_states(
                list(ast.iter_child_nodes(node)),
                state,
                function,
                depth=depth + 1,
                call_stack=call_stack,
            )

        return self._combine_child_states(
            list(ast.iter_child_nodes(node)),
            state,
            function,
            depth=depth + 1,
            call_stack=call_stack,
        )

    def _scan_expr_for_sinks(
        self,
        node: ast.AST,
        state: dict[str, _ExpressionState],
        function: str,
    ) -> None:
        for child in self._walk_expression(node, function):
            if isinstance(child, ast.Call):
                self._maybe_record_sink_path(child, state, function)

    def _maybe_record_sink_path(
        self,
        call: ast.Call,
        state: dict[str, _ExpressionState],
        function: str,
    ) -> None:
        spec = self._sink_spec(call)
        if spec is None:
            return

        line = getattr(call, "lineno", None)
        call_expr = _source_segment(call, self.source_code)
        sink = self._make_node(
            "sink",
            call_expr,
            line,
            function_name=function,
            metadata={"sink_name": spec.name, "category": spec.category, "cwe": spec.cwe},
            column=getattr(call, "col_offset", None),
        )

        states = self._sink_argument_states(call, spec, state, function)
        call_guarantees = self._call_guarantees(call, function)
        for expr_state in states:
            # Guards constrain a demonstrated flow; they are never a source of
            # taint by themselves.  A constant lookup with an owner/tenant
            # predicate must therefore remain path-free.
            if expr_state.source is None:
                continue
            guarantees = _dedupe_nodes((*expr_state.guarantees, *call_guarantees))
            source = expr_state.source
            nodes = _dedupe_nodes((*expr_state.nodes, *call_guarantees, sink))
            edges = _edges_for_nodes(nodes)
            missing = _missing_for_sink(spec, expr_state.sanitizers, guarantees)
            confidence = _path_confidence(spec, expr_state, guarantees)
            self.summary.paths.append(DataFlowPath(
                source=source,
                sink=sink,
                nodes=nodes,
                edges=edges,
                file_path=self.filename,
                function_name=function,
                intermediate_variables=_dedupe_strings(expr_state.variables),
                sanitizers=_dedupe_nodes(expr_state.sanitizers),
                guarantees=guarantees,
                missing_sanitizers=missing,
                confidence=confidence,
                review_priority=_review_priority(spec, missing, guarantees, expr_state.sanitizers),
                sink_category=spec.category,
                cwe=spec.cwe,
                diagnostics=tuple(dict(item) for item in self.summary.diagnostics),
                truncation_reason=next(
                    (
                        str(item["reason"])
                        for item in self.summary.diagnostics
                        if str(item.get("reason", "")).startswith("analysis_truncated_")
                    ),
                    "",
                ),
            ))

    def _sink_argument_states(
        self,
        call: ast.Call,
        spec: _SinkSpec,
        state: dict[str, _ExpressionState],
        function: str,
    ) -> list[_ExpressionState]:
        if spec.category == "query":
            return [
                self._eval_expr(kw.value, state, function)
                for kw in call.keywords
                if kw.arg in {"filename", "path", "slug", "uuid", "id", "object_id"}
            ]
        if spec.category == "command":
            return [self._eval_expr(call.args[0], state, function)] if call.args else []
        if spec.category in {"path", "network", "template", "deserialization"}:
            if call.args:
                return [self._eval_expr(call.args[0], state, function)]
            return [
                self._eval_expr(kw.value, state, function)
                for kw in call.keywords
                if kw.arg in {"file", "filename", "path", "url", "data", "value"}
            ]
        return [self._combine_child_states([*call.args, *(kw.value for kw in call.keywords)], state, function)]

    def _sink_spec(self, call: ast.Call) -> _SinkSpec | None:
        name = _call_name(call) or ""
        lowered = name.lower()
        if self.extra_sinks and not any(pattern in lowered for pattern in self.extra_sinks):
            return None
        if lowered.endswith("filter_by"):
            return _SinkSpec(
                name=name,
                category="query",
                cwe="CWE-639",
                required_guarantees=("query.scoped_to_current_source", "query.scoped_to_current_user"),
                severity="high",
            )
        if lowered in {"open", "builtins.open"} or lowered.endswith(".open"):
            return _SinkSpec(
                name=name,
                category="path",
                cwe="CWE-22",
                required_guarantees=("storage.path.enforces_store_boundary", "path.is_within_store", "filename.matches_allowed_pattern"),
                severity="high",
            )
        if lowered in {"os.remove", "os.unlink", "shutil.rmtree"}:
            return _SinkSpec(
                name=name,
                category="path",
                cwe="CWE-22",
                required_guarantees=("path.is_within_store", "filename.matches_allowed_pattern"),
                severity="high",
            )
        if lowered in {"os.system", "os.popen"}:
            return _SinkSpec(name=name, category="command", cwe="CWE-78", required_guarantees=("command.shell_safe",), severity="critical")
        if lowered in {"subprocess.run", "subprocess.call", "subprocess.popen"} and _kw_is_true(call, "shell"):
            return _SinkSpec(name=name, category="command", cwe="CWE-78", required_guarantees=("command.shell_safe",), severity="critical")
        if lowered in {"requests.get", "requests.post", "requests.put", "httpx.get", "httpx.post", "urlopen", "urllib.request.urlopen"}:
            return _SinkSpec(name=name, category="network", cwe="CWE-918", required_guarantees=("url.is_allowlisted",), severity="high")
        if lowered.endswith("markup") or lowered == "markup":
            return _SinkSpec(
                name=name,
                category="template",
                cwe="CWE-79",
                required_guarantees=("html_output.user_values_escaped", "markup.has_unescaped_user_input == false"),
                severity="high",
            )
        if lowered in {"pickle.loads", "pickle.load", "yaml.load", "yaml.unsafe_load", "marshal.loads"}:
            return _SinkSpec(name=name, category="deserialization", cwe="CWE-502", required_guarantees=("deserialization.input_trusted",), severity="critical")
        return None

    def _call_guarantees(self, call: ast.Call, function: str) -> tuple[DataFlowNode, ...]:
        name = (_call_name(call) or "").lower()
        guarantees: list[DataFlowNode] = []
        if name.endswith("filter_by"):
            for kw in call.keywords:
                if kw.arg in {"source_id", "source_uuid"} and _looks_current_principal(kw.value):
                    guarantees.append(self._make_node(
                        "guarantee",
                        "query.scoped_to_current_source == true",
                        getattr(call, "lineno", None),
                        function_name=function,
                        metadata={"call_name": _call_name(call), "keyword": kw.arg},
                    ))
                if kw.arg in {"user_id", "owner_id"} and _looks_current_principal(kw.value):
                    guarantees.append(self._make_node(
                        "guarantee",
                        "query.scoped_to_current_user == true",
                        getattr(call, "lineno", None),
                        function_name=function,
                        metadata={"call_name": _call_name(call), "keyword": kw.arg},
                    ))
        return tuple(guarantees)

    def _enforced_commonpath_guards(
        self,
        statement: ast.If,
        state: dict[str, _ExpressionState],
        function: str,
    ) -> tuple[tuple[str, tuple[str, ...], DataFlowNode], ...]:
        match = _rejecting_commonpath_check(statement)
        if match is None:
            return ()
        call, checked_expressions = match
        guards: list[tuple[str, tuple[str, ...], DataFlowNode]] = []
        for checked_expression in checked_expressions:
            variable = _direct_guard_target_name(checked_expression)
            current = state.get(variable) if variable else None
            if current is None or current.source is None:
                continue
            guarantee = self._make_node(
                "guarantee",
                "path.is_within_store == true",
                getattr(call, "lineno", None),
                variable=variable,
                function_name=function,
                metadata={
                    "call_name": _call_name(call),
                    "guard_condition": _source_segment(statement.test, self.source_code),
                    "result_used": True,
                },
                column=getattr(call, "col_offset", None),
            )
            guards.append((
                variable,
                tuple(node.node_id for node in current.nodes),
                guarantee,
            ))
        return tuple(guards)

    def _select_return_argument_state(
        self,
        call: ast.Call,
        states: list[_ExpressionState],
        model: _ReturnModel,
    ) -> _ExpressionState:
        if model.argument_index is None:
            selected = _ExpressionState()
            for item in states:
                selected = _combine_states(selected, item)
            return selected

        function_name = (_call_name(call) or "").rsplit(".", 1)[-1]
        signature = self.return_signatures.get(function_name)
        if signature is None or model.argument_index >= len(signature.parameters):
            if model.argument_index < len(states):
                return states[model.argument_index]
            return _ExpressionState()

        parameter_name = signature.parameters[model.argument_index]
        positional_parameters = list(signature.positional_parameters)
        if (
            signature.implicit_receiver
            and isinstance(call.func, ast.Attribute)
            and positional_parameters
        ):
            positional_parameters = positional_parameters[1:]

        if parameter_name in positional_parameters:
            position = positional_parameters.index(parameter_name)
            if position < len(call.args):
                return states[position]

        keyword_offset = len(call.args)
        for index, keyword in enumerate(call.keywords):
            if keyword.arg == parameter_name:
                return states[keyword_offset + index]
        return _ExpressionState()

    def _combine_child_states(
        self,
        nodes: Iterable[ast.AST],
        state: dict[str, _ExpressionState],
        function: str,
        *,
        depth: int = 0,
        call_stack: tuple[str, ...] = (),
    ) -> _ExpressionState:
        combined = _ExpressionState()
        for node in nodes:
            child_state = self._eval_expr(
                node,
                state,
                function,
                depth=depth,
                call_stack=call_stack,
            )
            combined = _combine_states(combined, child_state)
        return combined

    def _resolve_return_model(
        self,
        model: _ReturnModel,
        *,
        function: str,
        line: int | None,
        depth: int,
        call_stack: tuple[str, ...],
    ) -> _ReturnModel | None:
        if self._visited_nodes >= self.max_nodes:
            self._diagnose(
                "analysis_truncated_max_nodes",
                function=function,
                line=line,
                call=model.call_name or None,
            )
            return None
        self._visited_nodes += 1
        if model.kind != "delegate":
            return model
        delegate = model.call_name.rsplit(".", 1)[-1]
        if depth + 1 > self.max_depth:
            self._diagnose(
                "analysis_truncated_max_depth",
                function=function,
                line=line,
            )
            return None
        if self.cycle_detection and delegate in call_stack:
            self._diagnose("cycle_detected", function=function, line=line, call=delegate)
            return None
        delegated = self.return_models.get(delegate)
        if delegated is None:
            return None
        resolved = self._resolve_return_model(
            delegated,
            function=function,
            line=line,
            depth=depth + 1,
            call_stack=(*call_stack, delegate),
        )
        if resolved is None:
            return None
        return replace(resolved, argument_index=model.argument_index)

    @staticmethod
    def _merge_control_flow_states(
        state: dict[str, _ExpressionState],
        branches: list[dict[str, _ExpressionState]],
    ) -> None:
        names = set(state)
        for branch in branches:
            names.update(branch)
        for name in names:
            candidates = [branch[name] for branch in branches if name in branch]
            active = [candidate for candidate in candidates if candidate.active]
            if not active:
                state.pop(name, None)
                continue
            unsanitized = [
                candidate
                for candidate in active
                if not candidate.sanitizers and not candidate.guarantees
            ]
            state[name] = (unsanitized or active)[0]

    def _walk_expression(self, node: ast.AST, function: str) -> Iterable[ast.AST]:
        stack: list[tuple[ast.AST, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > self.max_depth:
                self._diagnose(
                    "analysis_truncated_max_depth",
                    function=function,
                    line=getattr(current, "lineno", None),
                )
                continue
            if not self._visit_node(current, function):
                return
            yield current
            children = list(ast.iter_child_nodes(current))
            stack.extend((child, depth + 1) for child in reversed(children))

    def _visit_node(self, node: ast.AST, function: str) -> bool:
        if self._visited_nodes >= self.max_nodes:
            self._diagnose(
                "analysis_truncated_max_nodes",
                function=function,
                line=getattr(node, "lineno", None),
            )
            return False
        self._visited_nodes += 1
        return True

    def _diagnose(self, reason: str, **context: Any) -> None:
        payload = {"reason": reason, **{key: value for key, value in context.items() if value is not None}}
        key = (reason, tuple(sorted(payload.items())))
        if key in self._diagnostic_keys:
            return
        self._diagnostic_keys.add(key)
        self.summary.diagnostics.append(payload)

    def _source_kind(self, node: ast.AST) -> str:
        name = (_call_name(node) if isinstance(node, ast.Call) else _expr_name(node)) or ""
        lowered = name.lower()
        if isinstance(node, ast.Call) and name.rsplit(".", 1)[-1] in self.local_function_names:
            return ""
        if any(pattern == lowered or lowered.startswith(pattern + ".") for pattern in self.sources):
            if "environ" in lowered or "getenv" in lowered:
                return "environment"
            return "user_input"
        if isinstance(node, ast.Subscript):
            base = (_expr_name(node.value) or "").lower()
            if any(base == pattern or base.startswith(pattern + ".") for pattern in self.sources):
                return "environment" if "environ" in base else "user_input"
        return ""

    def _is_sanitizer_call(self, lowered_call_name: str) -> bool:
        return any(
            lowered_call_name == pattern
            or lowered_call_name.endswith("." + pattern)
            for pattern in self.sanitizers
        )

    def _is_guarantee_call(self, lowered_call_name: str) -> bool:
        return any(pattern in lowered_call_name for pattern in _PATH_GUARANTEE_BY_PATTERN)

    def _record_use(
        self,
        name: str,
        line: int | None,
        function: str,
        column: int | None = None,
    ) -> None:
        node = self._make_node(
            "use",
            name,
            line,
            variable=name,
            function_name=function,
            column=column,
        )
        self.summary.uses.setdefault(name, []).append(node)

    def _make_node(
        self,
        kind: str,
        expression: str,
        line: int | None,
        *,
        variable: str = "",
        function_name: str = "",
        metadata: dict[str, Any] | None = None,
        column: int | None = None,
    ) -> DataFlowNode:
        expression = _clean_expr(expression)
        node_metadata = dict(metadata or {})
        node_metadata.setdefault("file", self.filename)
        node_metadata.setdefault("line", line)
        node_metadata.setdefault("column", column)
        node_metadata.setdefault("function", function_name)
        node_metadata.setdefault("statement_order", self._current_statement_order)
        return DataFlowNode(
            node_id=_stable_id(
                self.filename,
                function_name,
                line,
                column,
                self._current_statement_order,
                kind,
                expression,
                variable,
            ),
            kind=kind,
            expression=expression,
            line=line,
            variable=variable,
            function_name=function_name,
            metadata=node_metadata,
            file_path=self.filename,
            column=column,
            statement_order=self._current_statement_order,
        )

    @staticmethod
    def _dedupe_paths(paths: Iterable[DataFlowPath]) -> list[DataFlowPath]:
        seen = set()
        result = []
        for path in paths:
            key = (
                path.file_path,
                path.function_name,
                path.source.expression,
                path.sink.expression,
                path.sink_line,
                tuple(node.expression for node in path.nodes),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(path)
        return result


def _path_to_hypothesis_payload(path: DataFlowPath) -> dict[str, Any]:
    return {
        "source": path.source.expression,
        "sink": path.sink.expression,
        "path": [node.expression for node in path.nodes],
        "nodes": [node.to_dict() for node in path.nodes],
        "edges": [edge.to_dict() for edge in path.edges],
        "intermediate_variables": list(path.intermediate_variables),
        "sanitizers": [node.expression for node in path.sanitizers],
        "guarantees": [node.expression for node in path.guarantees],
        "missing_sanitizers": list(path.missing_sanitizers),
        "missing_guarantees": list(path.missing_sanitizers),
        "confidence": round(float(path.confidence), 3),
        "review_priority": path.review_priority,
        "file": path.file_path,
        "function": path.function_name,
        "source_line": path.source_line,
        "sink_line": path.sink_line,
        "source_column": path.source.column,
        "sink_column": path.sink.column,
        "sink_category": path.sink_category,
        "cwe": path.cwe,
        "diagnostics": [dict(item) for item in path.diagnostics],
        "rejection_reason": path.rejection_reason,
        "truncation_reason": path.truncation_reason,
        "reason": path.rejection_reason or path.truncation_reason,
    }


def _summary_map(
    summaries: dict[str, DataFlowSummary] | Iterable[DataFlowSummary],
) -> dict[str, DataFlowSummary]:
    if isinstance(summaries, dict):
        return {_norm_path(key): value for key, value in summaries.items()}
    return {_norm_path(summary.file_path): summary for summary in summaries}


def _categories_for_finding(finding: Finding) -> set[str]:
    cwe = str(finding.cwe or "").upper()
    text = " ".join([
        str(finding.rule_id or ""),
        str(finding.title or ""),
        str(finding.description or ""),
        str(finding.evidence or ""),
    ]).lower()
    if cwe in {"CWE-22", "CWE-73"} or "path traversal" in text:
        return {"path", "CWE-22", "CWE-73"}
    if cwe == "CWE-502" or "pickle" in text or "deserial" in text:
        return {"deserialization", "CWE-502"}
    if cwe == "CWE-79" or "xss" in text or "markup" in text or "html" in text:
        return {"template", "CWE-79"}
    if cwe in {"CWE-639", "CWE-862", "CWE-863"} or any(token in text for token in ["idor", "access control", "filter_by", "source_id", "user_id"]):
        return {"query", "CWE-639", "CWE-862", "CWE-863"}
    if cwe == "CWE-78" or "command" in text or "shell" in text:
        return {"command", "CWE-78"}
    if cwe == "CWE-918" or "ssrf" in text:
        return {"network", "CWE-918"}
    return set()


def _missing_for_sink(
    spec: _SinkSpec,
    sanitizers: tuple[DataFlowNode, ...],
    guarantees: tuple[DataFlowNode, ...],
) -> tuple[str, ...]:
    guarantee_text = " ".join(node.expression.lower() for node in guarantees)
    sanitizer_text = " ".join(node.expression.lower() for node in sanitizers)
    if spec.category == "template" and ("escape" in sanitizer_text or "html_output.user_values_escaped" in guarantee_text):
        return ()
    if spec.category == "path" and any(token in guarantee_text for token in [
        "storage.path.enforces_store_boundary",
        "path.is_within_store",
        "filename.matches_allowed_pattern",
        "filename.basename_only",
    ]):
        return ()
    if spec.category == "query" and any(token in guarantee_text for token in [
        "query.scoped_to_current_source",
        "query.scoped_to_current_user",
    ]):
        return ()
    if spec.category == "command" and sanitizers:
        return ()
    return spec.required_guarantees


def _path_confidence(
    spec: _SinkSpec,
    state: _ExpressionState,
    guarantees: tuple[DataFlowNode, ...],
) -> float:
    base = 0.9 if spec.severity == "critical" else 0.82
    if guarantees or state.sanitizers:
        return min(base, 0.68)
    return base


def _review_priority(
    spec: _SinkSpec,
    missing: tuple[str, ...],
    guarantees: tuple[DataFlowNode, ...],
    sanitizers: tuple[DataFlowNode, ...],
) -> str:
    if guarantees or sanitizers:
        return "low"
    if spec.severity == "critical" and missing:
        return "high"
    return "medium" if missing else "low"


def _with_flow_node(state: _ExpressionState, node: DataFlowNode) -> _ExpressionState:
    return _ExpressionState(
        source=state.source or node,
        nodes=_append_node(state.nodes, node),
        sanitizers=_dedupe_nodes((*state.sanitizers, node)) if node.kind == "sanitizer" else state.sanitizers,
        guarantees=_dedupe_nodes((*state.guarantees, node)) if node.kind == "guarantee" else state.guarantees,
        variables=state.variables,
        confidence=state.confidence,
    )


def _combine_states(left: _ExpressionState, right: _ExpressionState) -> _ExpressionState:
    source = left.source or right.source
    return _ExpressionState(
        source=source,
        nodes=_dedupe_nodes((*left.nodes, *right.nodes)),
        sanitizers=_dedupe_nodes((*left.sanitizers, *right.sanitizers)),
        guarantees=_dedupe_nodes((*left.guarantees, *right.guarantees)),
        variables=_dedupe_strings((*left.variables, *right.variables)),
        confidence=max(left.confidence, right.confidence),
    )


def _edges_for_nodes(nodes: tuple[DataFlowNode, ...]) -> tuple[DataFlowEdge, ...]:
    return tuple(
        DataFlowEdge(
            source_id=source.node_id,
            target_id=target.node_id,
            line=target.line if target.line is not None else source.line,
            file_path=target.file_path or source.file_path,
            column=target.column if target.column is not None else source.column,
            function_name=target.function_name or source.function_name,
            statement_order=(
                target.statement_order
                if target.statement_order is not None
                else source.statement_order
            ),
        )
        for source, target in zip(nodes, nodes[1:])
    )


def _append_node(nodes: tuple[DataFlowNode, ...], node: DataFlowNode) -> tuple[DataFlowNode, ...]:
    if nodes and nodes[-1].node_id == node.node_id:
        return nodes
    return (*nodes, node)


def _dedupe_nodes(nodes: Iterable[DataFlowNode]) -> tuple[DataFlowNode, ...]:
    seen = set()
    result = []
    for node in nodes:
        if node.node_id in seen:
            continue
        seen.add(node.node_id)
        result.append(node)
    return tuple(result)


def _dedupe_strings(values: Iterable[str]) -> tuple[str, ...]:
    seen = set()
    result = []
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return tuple(result)


def _path_sort_key(path: DataFlowPath) -> tuple[Any, ...]:
    return (
        path.file_path,
        path.function_name,
        path.sink_line or 0,
        path.source_line or 0,
        path.sink.expression,
        path.source.expression,
        tuple(node.expression for node in path.nodes),
    )


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, ast.Tuple):
        return [name for item in node.elts for name in _target_names(item)]
    if isinstance(node, ast.Attribute):
        name = _expr_name(node)
        return [name] if name else []
    if isinstance(node, ast.Subscript):
        name = _expr_name(node)
        return [name] if name else []
    return []


def _function_returns(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.Return]:
    returns: list[ast.Return] = []

    class _ReturnVisitor(ast.NodeVisitor):
        def visit_FunctionDef(self, child: ast.FunctionDef) -> None:  # noqa: N802
            if child is node:
                self.generic_visit(child)

        def visit_AsyncFunctionDef(self, child: ast.AsyncFunctionDef) -> None:  # noqa: N802
            if child is node:
                self.generic_visit(child)

        def visit_Lambda(self, child: ast.Lambda) -> None:  # noqa: N802
            return

        def visit_Return(self, child: ast.Return) -> None:  # noqa: N802
            returns.append(child)

    _ReturnVisitor().visit(node)
    return returns


def _is_static_constant(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_static_constant(item) for item in node.elts)
    if isinstance(node, ast.Dict):
        return all(
            (key is None or _is_static_constant(key)) and _is_static_constant(value)
            for key, value in zip(node.keys, node.values)
        )
    if isinstance(node, ast.UnaryOp):
        return _is_static_constant(node.operand)
    if isinstance(node, ast.BinOp):
        return _is_static_constant(node.left) and _is_static_constant(node.right)
    return False


def _rejecting_commonpath_check(
    statement: ast.If,
) -> tuple[ast.Call, tuple[ast.AST, ...]] | None:
    if statement.orelse or not _suite_blocks_execution(statement.body):
        return None
    test = statement.test
    if (
        not isinstance(test, ast.Compare)
        or len(test.ops) != 1
        or not isinstance(test.ops[0], ast.NotEq)
        or len(test.comparators) != 1
    ):
        return None

    left, right = test.left, test.comparators[0]
    if isinstance(left, ast.Call) and (_call_name(left) or "").lower().endswith("commonpath"):
        call, expected_base = left, right
    elif isinstance(right, ast.Call) and (_call_name(right) or "").lower().endswith("commonpath"):
        call, expected_base = right, left
    else:
        return None

    if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
        return None
    path_items = call.args[0].elts
    if len(path_items) < 2 or ast.dump(path_items[0]) != ast.dump(expected_base):
        return None
    return call, tuple(path_items[1:])


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


def _direct_guard_target_name(node: ast.AST) -> str:
    current = node
    while isinstance(current, ast.Call):
        call_name = (_call_name(current) or "").lower()
        if call_name not in {"str", "os.fspath"} or len(current.args) != 1:
            return ""
        current = current.args[0]
    if isinstance(current, (ast.Name, ast.Attribute)):
        return _expr_name(current) or ""
    return ""


def _parameter_index_for_call(call: ast.Call, parameters: list[str]) -> int | None:
    for argument in [*call.args, *(kw.value for kw in call.keywords)]:
        if isinstance(argument, ast.Name) and argument.id in parameters:
            return parameters.index(argument.id)
    return None


def _names_in(node: ast.AST) -> list[str]:
    return sorted({
        child.id for child in ast.walk(node)
        if isinstance(child, ast.Name)
    })


def _expr_name(node: ast.AST | None) -> str | None:
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _expr_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    if isinstance(node, ast.Subscript):
        return _expr_name(node.value)
    return None


def _call_name(node: ast.Call | ast.AST) -> str | None:
    if isinstance(node, ast.Call):
        return _expr_name(node.func)
    return None


def _source_segment(node: ast.AST, source_code: str) -> str:
    segment = ast.get_source_segment(source_code, node) if source_code else None
    if segment:
        return _clean_expr(segment)
    try:
        return _clean_expr(ast.unparse(node))
    except Exception:
        return node.__class__.__name__


def _clean_expr(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _guarantee_expression(call_name: str) -> str:
    lowered = call_name.lower()
    for pattern, expression in _PATH_GUARANTEE_BY_PATTERN.items():
        if pattern in lowered:
            return expression
    return ""


def _kw_is_true(call: ast.Call, keyword: str) -> bool:
    for kw in call.keywords:
        if kw.arg == keyword and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _looks_current_principal(node: ast.AST) -> bool:
    text = _clean_expr(ast.dump(node)).lower()
    return any(token in text for token in [
        "logged_in_source",
        "current_source",
        "current_user",
        "g.user",
        "session",
        "request.user",
    ])


def _norm_path(path: str) -> str:
    return str(path or "").replace("\\", "/").lower()


def _stable_id(*parts: object) -> str:
    raw = "\x1f".join(str(part or "") for part in parts)
    return "df_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


__all__ = [
    "DataFlowNode",
    "DataFlowEdge",
    "DataFlowPath",
    "DataFlowSummary",
    "analyze_source_dataflow",
    "extract_local_def_use",
    "trace_variable_origin",
    "find_source_to_sink_paths",
    "dataflow_paths_to_beliefs",
    "dataflow_paths_to_hypotheses",
    "attach_dataflow_to_findings",
    "dataflow_for_finding",
    "dataflow_paths_for_finding",
]
