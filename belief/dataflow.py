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

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "kind": self.kind,
            "expression": self.expression,
            "line": self.line,
            "variable": self.variable,
            "function_name": self.function_name,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DataFlowEdge:
    """A stable edge between two local dataflow nodes."""

    source_id: str
    target_id: str
    kind: str = "flows_to"
    line: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "kind": self.kind,
            "line": self.line,
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
            "sink_category": self.sink_category,
            "cwe": self.cwe,
            "intermediate_variables": list(self.intermediate_variables),
            "sanitizers": [node.expression for node in self.sanitizers],
            "guarantees": [node.expression for node in self.guarantees],
            "missing_sanitizers": list(self.missing_sanitizers),
            "missing_guarantees": list(self.missing_sanitizers),
            "confidence": round(float(self.confidence), 3),
            "review_priority": self.review_priority,
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
    )


def extract_local_def_use(
    module_ast: ast.AST,
    filename: str = "",
    *,
    source_code: str = "",
    sources: Iterable[str] | None = None,
    sinks: Iterable[str] | None = None,
    sanitizers: Iterable[str] | None = None,
) -> DataFlowSummary:
    """Extract local def-use facts and source-to-sink paths from a module AST."""
    analyzer = _LocalDataFlowAnalyzer(
        filename=filename,
        source_code=source_code,
        sources=tuple(sources or DEFAULT_SOURCE_PATTERNS),
        sinks=tuple(sinks or ()),
        sanitizers=tuple(sanitizers or DEFAULT_SANITIZER_PATTERNS),
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
) -> list[DataFlowPath]:
    """Return deterministic local source/sanitizer/guarantee/sink paths."""
    return extract_local_def_use(
        module_ast,
        filename,
        source_code=source_code,
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
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
    paths: list[DataFlowPath] = []
    for summary in candidate_summaries:
        for path in summary.paths:
            if wanted and path.sink_category not in wanted and path.cwe not in wanted:
                continue
            paths.append(path)
    line = finding.line or 0
    return sorted(paths, key=lambda path: (
        abs((path.sink_line or 0) - line) if line else 0,
        0 if path.sanitized else 1,
        _path_sort_key(path),
    ))


class _LocalDataFlowAnalyzer:
    def __init__(
        self,
        *,
        filename: str,
        source_code: str,
        sources: tuple[str, ...],
        sinks: tuple[str, ...],
        sanitizers: tuple[str, ...],
    ) -> None:
        self.filename = filename
        self.source_code = source_code
        self.sources = tuple(pattern.lower() for pattern in sources)
        self.extra_sinks = tuple(pattern.lower() for pattern in sinks)
        self.sanitizers = tuple(pattern.lower() for pattern in sanitizers)
        self.summary = DataFlowSummary(file_path=filename)
        self.return_models: dict[str, _ReturnModel] = {}

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
        self.summary.paths = sorted(self._dedupe_paths(self.summary.paths), key=_path_sort_key)
        return self.summary

    def _collect_return_models(self, module_ast: ast.AST) -> dict[str, _ReturnModel]:
        models: dict[str, _ReturnModel] = {}
        for node in ast.walk(module_ast):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for child in ast.walk(node):
                if not isinstance(child, ast.Return) or child.value is None:
                    continue
                if not isinstance(child.value, ast.Call):
                    continue
                call_name = _call_name(child.value)
                if not call_name:
                    continue
                lowered = call_name.lower()
                if self._is_sanitizer_call(lowered):
                    models[node.name] = _ReturnModel("sanitizer", call_name, _source_segment(child.value, self.source_code))
                elif self._is_guarantee_call(lowered):
                    models[node.name] = _ReturnModel("guarantee", call_name, _guarantee_expression(call_name))
        return models

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
            for child in ast.iter_child_nodes(stmt):
                if isinstance(child, ast.expr):
                    self._scan_expr_for_sinks(child, state, function)
            for child in list(getattr(stmt, "body", [])) + list(getattr(stmt, "orelse", [])):
                if isinstance(child, ast.stmt):
                    self._process_stmt(child, state, function)
            return

        if isinstance(stmt, ast.Try):
            for child in (
                list(stmt.body)
                + [item for handler in stmt.handlers for item in handler.body]
                + list(stmt.orelse)
                + list(stmt.finalbody)
            ):
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
            )
            self.summary.definitions.setdefault(target_name, []).append(target_node)
            new_nodes = _append_node(expr_state.nodes, target_node)
            new_edges = _edges_for_nodes(new_nodes, line)
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
    ) -> _ExpressionState:
        if node is None:
            return _ExpressionState()

        expr = _source_segment(node, self.source_code)
        line = getattr(node, "lineno", None)

        if isinstance(node, ast.Name):
            if node.id in state:
                self._record_use(node.id, line, function)
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
            arg_state = self._combine_child_states(
                [*node.args, *(kw.value for kw in node.keywords if kw.value is not None)],
                state,
                function,
            )

            if lowered.endswith(".read") or lowered == "read":
                source = self._make_node(
                    "source",
                    expr,
                    line,
                    function_name=function,
                    metadata={"source_type": "file"},
                )
                return _ExpressionState(
                    source=source,
                    nodes=(source,),
                    variables=tuple(_names_in(node)),
                    confidence=0.68,
                )

            return_model = self.return_models.get(call_name) or self.return_models.get(call_name.rsplit(".", 1)[-1])
            if return_model and arg_state.active:
                kind = return_model.kind
                metadata = {"call_name": call_name, "source": "same_file_return_model"}
                expression = return_model.expression
                if kind == "guarantee":
                    expression = return_model.expression or _guarantee_expression(call_name)
                node_kind = "guarantee" if kind == "guarantee" else "sanitizer"
                flow_node = self._make_node(
                    node_kind,
                    expression or expr,
                    line,
                    function_name=function,
                    metadata=metadata,
                )
                return _with_flow_node(arg_state, flow_node)

            if self._is_sanitizer_call(lowered) and arg_state.active:
                sanitizer = self._make_node(
                    "sanitizer",
                    expr,
                    line,
                    function_name=function,
                    metadata={"call_name": call_name},
                )
                return _with_flow_node(arg_state, sanitizer)

            if self._is_guarantee_call(lowered):
                guarantee = self._make_node(
                    "guarantee",
                    _guarantee_expression(call_name) or expr,
                    line,
                    function_name=function,
                    metadata={"call_name": call_name},
                )
                if arg_state.active:
                    return _with_flow_node(arg_state, guarantee)
                return _ExpressionState(
                    source=guarantee,
                    nodes=(guarantee,),
                    guarantees=(guarantee,),
                    variables=tuple(_names_in(node)),
                    confidence=0.82,
                )

            return arg_state

        if isinstance(node, (ast.BinOp, ast.BoolOp, ast.Compare, ast.IfExp, ast.JoinedStr, ast.FormattedValue)):
            return self._combine_child_states(list(ast.iter_child_nodes(node)), state, function)

        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return self._combine_child_states(list(ast.iter_child_nodes(node)), state, function)

        return self._combine_child_states(list(ast.iter_child_nodes(node)), state, function)

    def _scan_expr_for_sinks(
        self,
        node: ast.AST,
        state: dict[str, _ExpressionState],
        function: str,
    ) -> None:
        for child in ast.walk(node):
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
        )

        states = self._sink_argument_states(call, spec, state, function)
        call_guarantees = self._call_guarantees(call, function)
        for expr_state in states:
            if not expr_state.active and not call_guarantees:
                continue
            guarantees = _dedupe_nodes((*expr_state.guarantees, *call_guarantees))
            source = expr_state.source or (guarantees[0] if guarantees else None)
            if source is None:
                continue
            nodes = _dedupe_nodes((*expr_state.nodes, *call_guarantees, sink))
            edges = tuple((*_edges_for_nodes(nodes, line),))
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

    def _combine_child_states(
        self,
        nodes: Iterable[ast.AST],
        state: dict[str, _ExpressionState],
        function: str,
    ) -> _ExpressionState:
        combined = _ExpressionState()
        for node in nodes:
            child_state = self._eval_expr(node, state, function)
            combined = _combine_states(combined, child_state)
        return combined

    def _source_kind(self, node: ast.AST) -> str:
        name = (_call_name(node) if isinstance(node, ast.Call) else _expr_name(node)) or ""
        lowered = name.lower()
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

    def _record_use(self, name: str, line: int | None, function: str) -> None:
        node = self._make_node("use", name, line, variable=name, function_name=function)
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
    ) -> DataFlowNode:
        expression = _clean_expr(expression)
        return DataFlowNode(
            node_id=_stable_id(self.filename, function_name, line, kind, expression, variable),
            kind=kind,
            expression=expression,
            line=line,
            variable=variable,
            function_name=function_name,
            metadata=metadata or {},
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
        "sink_category": path.sink_category,
        "cwe": path.cwe,
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


def _edges_for_nodes(nodes: tuple[DataFlowNode, ...], line: int | None) -> tuple[DataFlowEdge, ...]:
    return tuple(
        DataFlowEdge(source_id=a.node_id, target_id=b.node_id, line=line)
        for a, b in zip(nodes, nodes[1:])
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
