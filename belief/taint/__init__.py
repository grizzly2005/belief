"""
BELIEF — Taint Analysis Engine.

Tracks how untrusted data flows through a program and identifies
where tainted data crosses trust boundaries without sanitization.
Each taint path becomes a belief of type INFORMATION_FLOW.

Inspired by python-security/pyt's reaching definitions analysis,
adapted for the BELIEF sextuplet model.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from typing import Optional

from ..models import (
    Belief,
    EpistemicStatus,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)

logger = logging.getLogger("belief.taint")


# ─── Taint Sources & Sinks ───

@dataclass(frozen=True)
class TaintSource:
    """A source of untrusted data."""
    name: str
    category: str    # user_input, network, file, environment, llm_output, database
    risk_level: str  # high, medium, low

    def matches(self, call_name: str) -> bool:
        return self.name.lower() in call_name.lower()


@dataclass(frozen=True)
class TaintSink:
    """A dangerous operation that should not receive tainted data."""
    name: str
    category: str    # code_exec, sql, file_write, command, deserialization, template
    severity: str    # critical, high, medium
    cwe: str         # CWE identifier

    def matches(self, call_name: str) -> bool:
        return self.name.lower() in call_name.lower()


@dataclass(frozen=True)
class Sanitizer:
    """A function that removes taint from data."""
    name: str
    sanitizes: str   # which category of taint it removes

    def matches(self, call_name: str) -> bool:
        return self.name.lower() in call_name.lower()


# ─── Default Sources, Sinks, Sanitizers ───

DEFAULT_SOURCES = [
    # User input
    TaintSource("input", "user_input", "high"),
    TaintSource("request.form", "user_input", "high"),
    TaintSource("request.args", "user_input", "high"),
    TaintSource("request.json", "user_input", "high"),
    TaintSource("request.data", "user_input", "high"),
    TaintSource("request.headers", "user_input", "high"),
    TaintSource("request.cookies", "user_input", "high"),
    TaintSource("request.files", "user_input", "high"),
    TaintSource("request.query_params", "user_input", "high"),
    TaintSource("request.body", "user_input", "high"),
    TaintSource("sys.argv", "user_input", "high"),
    TaintSource("os.environ", "environment", "medium"),
    TaintSource("getenv", "environment", "medium"),
    # Network
    TaintSource("recv", "network", "high"),
    TaintSource("read", "network", "medium"),
    TaintSource("readline", "network", "medium"),
    TaintSource("urlopen", "network", "high"),
    TaintSource("requests.get", "network", "high"),
    TaintSource("requests.post", "network", "high"),
    TaintSource("httpx.get", "network", "high"),
    TaintSource("httpx.post", "network", "high"),
    TaintSource("fetch", "network", "high"),
    TaintSource("response.json", "network", "high"),
    TaintSource("response.text", "network", "high"),
    TaintSource("response.content", "network", "high"),
    # File
    TaintSource("open", "file", "medium"),
    TaintSource("readlines", "file", "medium"),
    # Database
    TaintSource("fetchone", "database", "medium"),
    TaintSource("fetchall", "database", "medium"),
    TaintSource("fetchmany", "database", "medium"),
    # LLM output (critical for agent frameworks)
    TaintSource("llm.invoke", "llm_output", "high"),
    TaintSource("llm.predict", "llm_output", "high"),
    TaintSource("chain.invoke", "llm_output", "high"),
    TaintSource("completion", "llm_output", "high"),
    TaintSource("chat.completions", "llm_output", "high"),
    TaintSource("generate", "llm_output", "medium"),
]

DEFAULT_SINKS = [
    # Code execution
    TaintSink("eval", "code_exec", "critical", "CWE-95"),
    TaintSink("exec", "code_exec", "critical", "CWE-95"),
    TaintSink("compile", "code_exec", "critical", "CWE-95"),
    TaintSink("__import__", "code_exec", "critical", "CWE-95"),
    TaintSink("subprocess.call", "command", "critical", "CWE-78"),
    TaintSink("subprocess.run", "command", "critical", "CWE-78"),
    TaintSink("subprocess.Popen", "command", "critical", "CWE-78"),
    TaintSink("os.system", "command", "critical", "CWE-78"),
    TaintSink("os.popen", "command", "critical", "CWE-78"),
    # SQL
    TaintSink("execute", "sql", "high", "CWE-89"),
    TaintSink("executemany", "sql", "high", "CWE-89"),
    TaintSink("raw_sql", "sql", "high", "CWE-89"),
    # Deserialization
    TaintSink("pickle.loads", "deserialization", "critical", "CWE-502"),
    TaintSink("pickle.load", "deserialization", "critical", "CWE-502"),
    TaintSink("yaml.load", "deserialization", "high", "CWE-502"),
    TaintSink("yaml.unsafe_load", "deserialization", "critical", "CWE-502"),
    TaintSink("json.loads", "deserialization", "medium", "CWE-502"),
    TaintSink("marshal.loads", "deserialization", "critical", "CWE-502"),
    # File operations
    TaintSink("open", "file_write", "high", "CWE-73"),
    TaintSink("write", "file_write", "high", "CWE-73"),
    TaintSink("writelines", "file_write", "high", "CWE-73"),
    # Template injection
    TaintSink("render_template_string", "template", "high", "CWE-94"),
    TaintSink("Markup", "template", "medium", "CWE-79"),
    TaintSink("format_html", "template", "medium", "CWE-79"),
    # LLM-specific sinks (prompt injection)
    TaintSink("SystemMessage", "prompt_injection", "high", "CWE-74"),
    TaintSink("HumanMessage", "prompt_injection", "medium", "CWE-74"),
]

DEFAULT_SANITIZERS = [
    Sanitizer("escape", "template"),
    Sanitizer("html.escape", "template"),
    Sanitizer("markupsafe.escape", "template"),
    Sanitizer("bleach.clean", "template"),
    Sanitizer("quote", "sql"),
    Sanitizer("parameterize", "sql"),
    Sanitizer("sanitize", "all"),
    Sanitizer("validate", "all"),
    Sanitizer("clean", "all"),
    Sanitizer("strip_tags", "template"),
    Sanitizer("shlex.quote", "command"),
    Sanitizer("shlex.split", "command"),
    Sanitizer("int(", "sql"),
    Sanitizer("float(", "sql"),
    Sanitizer("bool(", "sql"),
]


# ─── Taint Flow Node ───

@dataclass
class TaintNode:
    """A node in the taint flow graph."""
    variable: str
    line: int
    tainted: bool = False
    source: Optional[TaintSource] = None
    sanitized: bool = False
    sanitizer: Optional[Sanitizer] = None


@dataclass(frozen=True)
class _TaintState:
    source: TaintSource
    source_line: int
    source_variable: str
    sanitized: bool = False
    sanitizer: Sanitizer | None = None
    intermediate_vars: tuple[str, ...] = ()
    source_column: int | None = None
    source_statement_order: int | None = None


@dataclass(frozen=True)
class _TaintReturnModel:
    kind: str
    call_name: str = ""
    argument_index: int | None = None


@dataclass(frozen=True)
class _TaintFunctionSignature:
    parameters: tuple[str, ...]
    positional_parameters: tuple[str, ...]
    implicit_receiver: bool = False


@dataclass
class TaintPath:
    """A complete taint flow path from source to sink."""
    source: TaintSource
    source_line: int
    source_variable: str
    sink: TaintSink
    sink_line: int
    sink_variable: str
    intermediate_vars: list[str] = field(default_factory=list)
    sanitized: bool = False
    confidence: float = 0.8
    file_path: str = ""
    function_name: str = ""
    source_column: int | None = None
    sink_column: int | None = None
    source_statement_order: int | None = None
    sink_statement_order: int | None = None

    def to_belief(self, file_path: str, function_name: str = "",
                  module: str = "") -> Belief:
        """Convert this taint path to a BELIEF information flow belief."""
        if self.sanitized:
            expr = (
                f"{self.source_variable} is sanitized before reaching "
                f"{self.sink.name}"
            )
            justification = JustificationCategory.C3_EXPLICIT_RUNTIME_GUARD
            epistemic = EpistemicStatus.BELIEF
        else:
            expr = (
                f"taint({self.source_variable}, source={self.source.category}) "
                f"reaches {self.sink.name}({self.sink_variable}) without sanitization"
            )
            justification = JustificationCategory.C6_UNSUPPORTED_ASSUMPTION
            epistemic = EpistemicStatus.HOPE

        return Belief(
            predicate=Predicate(
                expression=expr,
                variables=(self.source_variable, self.sink_variable),
                anchor_lines=(self.source_line, self.sink_line),
                natural_language=(
                    f"Data from {self.source.category} source "
                    f"'{self.source.name}' (line {self.source_line}) "
                    f"flows to {self.sink.category} sink "
                    f"'{self.sink.name}' (line {self.sink_line}) "
                    f"{'after sanitization' if self.sanitized else 'without sanitization'}. "
                    f"CWE: {self.sink.cwe}"
                ),
            ),
            scope=Scope(
                file_path=file_path,
                function_name=function_name,
                module=module,
                line_start=self.source_line,
                line_end=self.sink_line,
            ),
            justification=justification,
            epistemic_status=epistemic,
            logic_type=LogicType.INFORMATION_FLOW,
            confidence_score=self.confidence,
        )


# ─── Taint Engine ───

class TaintEngine:
    """
    Intra-procedural taint analysis for Python source code.

    Tracks data flow from sources to sinks using AST-based reaching
    definitions. Each unsanitized taint path becomes a BELIEF.
    """

    def __init__(
        self,
        sources: list[TaintSource] | None = None,
        sinks: list[TaintSink] | None = None,
        sanitizers: list[Sanitizer] | None = None,
        *,
        max_depth: int = 32,
        max_nodes: int = 10_000,
        cycle_detection: bool = True,
    ):
        self.sources = sources or DEFAULT_SOURCES
        self.sinks = sinks or DEFAULT_SINKS
        self.sanitizers = sanitizers or DEFAULT_SANITIZERS
        self.max_depth = max(0, int(max_depth))
        self.max_nodes = max(0, int(max_nodes))
        self.cycle_detection = bool(cycle_detection)
        self.diagnostics: list[dict[str, object]] = []
        self._diagnostic_keys: set[tuple[object, ...]] = set()
        self._visited_nodes = 0
        self._statement_order = 0
        self._current_statement_order = 0
        self._return_models: dict[str, _TaintReturnModel] = {}
        self._return_signatures: dict[str, _TaintFunctionSignature] = {}
        self._local_functions: set[str] = set()

    def analyze(
        self,
        source_code: str,
        file_path: str = "",
        module: str = "",
    ) -> list[TaintPath]:
        """Analyze source code for taint flows."""
        try:
            tree = ast.parse(source_code)
        except SyntaxError:
            return []

        self.diagnostics = []
        self._diagnostic_keys = set()
        self._visited_nodes = 0
        self._statement_order = 0
        self._return_models = self._collect_return_models(tree)
        all_paths: list[TaintPath] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                paths = self._analyze_function(node, source_code, file_path, module)
                all_paths.extend(paths)

        return all_paths

    def analyze_to_beliefs(
        self,
        source_code: str,
        file_path: str = "",
        module: str = "",
    ) -> list[Belief]:
        """Analyze and return beliefs directly."""
        paths = self.analyze(source_code, file_path, module)
        return [
            p.to_belief(file_path, function_name=p.function_name, module=module)
            for p in paths
        ]

    def _analyze_function(
        self,
        func_node: ast.FunctionDef | ast.AsyncFunctionDef,
        source: str,
        file_path: str,
        module: str,
    ) -> list[TaintPath]:
        """Analyze a single function for taint flows."""
        state: dict[str, _TaintState] = {}
        function_name = func_node.name
        untrusted_parameters = {
            "request", "req", "data", "input", "body", "payload",
            "query", "params", "headers", "user_input",
        }
        parameters = (
            list(func_node.args.posonlyargs)
            + list(func_node.args.args)
            + list(func_node.args.kwonlyargs)
        )
        for arg in parameters:
            if arg.arg not in untrusted_parameters:
                continue
            taint_source = TaintSource(arg.arg, "user_input", "high")
            state[arg.arg] = _TaintState(
                source=taint_source,
                source_line=func_node.lineno,
                source_variable=arg.arg,
                intermediate_vars=(arg.arg,),
                source_column=getattr(arg, "col_offset", None),
                source_statement_order=0,
            )

        paths: list[TaintPath] = []
        self._process_statements(
            func_node.body,
            state,
            paths,
            function_name=function_name,
            file_path=file_path,
        )
        return paths

    def _process_statements(
        self,
        statements: list[ast.stmt],
        state: dict[str, _TaintState],
        paths: list[TaintPath],
        *,
        function_name: str,
        file_path: str,
    ) -> None:
        for statement in statements:
            self._statement_order += 1
            self._current_statement_order = self._statement_order

            if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            if isinstance(statement, ast.Assign):
                self._record_sinks(statement.value, state, paths, function_name, file_path)
                value_state = self._eval_taint_expr(statement.value, state, function_name)
                for target in statement.targets:
                    self._assign_taint(target, value_state, state)
                continue
            if isinstance(statement, ast.AnnAssign):
                value_state = None
                if statement.value is not None:
                    self._record_sinks(
                        statement.value, state, paths, function_name, file_path
                    )
                    value_state = self._eval_taint_expr(
                        statement.value, state, function_name
                    )
                self._assign_taint(statement.target, value_state, state)
                continue
            if isinstance(statement, ast.AugAssign):
                self._record_sinks(statement.value, state, paths, function_name, file_path)
                value_state = self._eval_taint_expr(statement.value, state, function_name)
                target_state = self._state_for_name(statement.target, state)
                self._assign_taint(statement.target, target_state or value_state, state)
                continue
            if isinstance(statement, ast.Expr):
                self._record_sinks(statement.value, state, paths, function_name, file_path)
                continue
            if isinstance(statement, ast.Return):
                if statement.value is not None:
                    self._record_sinks(
                        statement.value, state, paths, function_name, file_path
                    )
                continue
            if isinstance(statement, ast.With):
                for item in statement.items:
                    self._record_sinks(
                        item.context_expr, state, paths, function_name, file_path
                    )
                    value_state = self._eval_taint_expr(
                        item.context_expr, state, function_name
                    )
                    if item.optional_vars is not None:
                        self._assign_taint(item.optional_vars, value_state, state)
                self._process_statements(
                    statement.body,
                    state,
                    paths,
                    function_name=function_name,
                    file_path=file_path,
                )
                continue
            if isinstance(statement, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                test = getattr(statement, "test", None) or getattr(statement, "iter", None)
                if test is not None:
                    self._record_sinks(test, state, paths, function_name, file_path)
                branch_states: list[dict[str, _TaintState]] = []
                for branch in (statement.body, statement.orelse):
                    branch_state = dict(state)
                    self._process_statements(
                        branch,
                        branch_state,
                        paths,
                        function_name=function_name,
                        file_path=file_path,
                    )
                    branch_states.append(branch_state)
                self._merge_branch_states(state, branch_states)
                continue
            if isinstance(statement, ast.Try):
                branches = [statement.body, *(handler.body for handler in statement.handlers)]
                if statement.orelse:
                    branches.append(statement.orelse)
                branch_states = []
                for branch in branches:
                    branch_state = dict(state)
                    self._process_statements(
                        branch,
                        branch_state,
                        paths,
                        function_name=function_name,
                        file_path=file_path,
                    )
                    branch_states.append(branch_state)
                self._merge_branch_states(state, branch_states)
                self._process_statements(
                    statement.finalbody,
                    state,
                    paths,
                    function_name=function_name,
                    file_path=file_path,
                )
                continue
            for child in ast.iter_child_nodes(statement):
                if isinstance(child, ast.expr):
                    self._record_sinks(child, state, paths, function_name, file_path)

    def _record_sinks(
        self,
        expression: ast.AST,
        state: dict[str, _TaintState],
        paths: list[TaintPath],
        function_name: str,
        file_path: str,
    ) -> None:
        for node in self._walk_expression(expression, function_name):
            if not isinstance(node, ast.Call):
                continue
            call_name = self._get_call_name(node)
            if not call_name:
                continue
            argument_nodes = [
                *node.args,
                *(keyword.value for keyword in node.keywords if keyword.value is not None),
            ]
            argument_states = [
                (argument, self._eval_taint_expr(argument, state, function_name))
                for argument in argument_nodes
            ]
            for sink in self.sinks:
                if not sink.matches(call_name):
                    continue
                for argument, argument_state in argument_states:
                    if argument_state is None:
                        continue
                    sanitizer_applies = bool(
                        argument_state.sanitized
                        and argument_state.sanitizer is not None
                        and argument_state.sanitizer.sanitizes in {"all", sink.category}
                    )
                    sink_variable = self._get_name(argument) or argument_state.source_variable
                    paths.append(TaintPath(
                        source=argument_state.source,
                        source_line=argument_state.source_line,
                        source_variable=argument_state.source_variable,
                        sink=sink,
                        sink_line=getattr(node, "lineno", 0),
                        sink_variable=sink_variable,
                        intermediate_vars=list(argument_state.intermediate_vars),
                        sanitized=sanitizer_applies,
                        confidence=0.4 if sanitizer_applies else 0.85,
                        file_path=file_path,
                        function_name=function_name,
                        source_column=argument_state.source_column,
                        sink_column=getattr(node, "col_offset", None),
                        source_statement_order=argument_state.source_statement_order,
                        sink_statement_order=self._current_statement_order,
                    ))

    def _eval_taint_expr(
        self,
        node: ast.AST | None,
        state: dict[str, _TaintState],
        function_name: str,
        *,
        depth: int = 0,
        call_stack: tuple[str, ...] = (),
    ) -> _TaintState | None:
        if node is None:
            return None
        if depth > self.max_depth:
            self._diagnose(
                "analysis_truncated_max_depth",
                function=function_name,
                line=getattr(node, "lineno", None),
            )
            return None
        if not self._visit_node(node, function_name):
            return None
        if isinstance(node, ast.Name):
            return state.get(node.id)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            exact = self._state_for_name(node, state)
            if exact is not None:
                return exact
        if isinstance(node, ast.Call):
            call_name = self._get_call_name(node) or ""
            argument_nodes = [
                *node.args,
                *(keyword.value for keyword in node.keywords if keyword.value is not None),
            ]
            argument_states = [
                self._eval_taint_expr(
                    argument,
                    state,
                    function_name,
                    depth=depth + 1,
                    call_stack=call_stack,
                )
                for argument in argument_nodes
            ]
            source_match = next(
                (source for source in self.sources if source.matches(call_name)),
                None,
            )
            is_local_call = call_name.rsplit(".", 1)[-1] in self._local_functions
            if source_match is not None and not is_local_call:
                return _TaintState(
                    source=source_match,
                    source_line=getattr(node, "lineno", 0),
                    source_variable=call_name,
                    source_column=getattr(node, "col_offset", None),
                    source_statement_order=self._current_statement_order,
                )
            model = self._return_models.get(call_name.rsplit(".", 1)[-1])
            receiver_state = None
            if model is None and isinstance(node.func, ast.Attribute):
                receiver_state = self._eval_taint_expr(
                    node.func.value,
                    state,
                    function_name,
                    depth=depth + 1,
                    call_stack=call_stack,
                )
            sanitizer = next(
                (item for item in self.sanitizers if item.matches(call_name)),
                None,
            )
            selected_argument = self._first_state(argument_states)
            transformed_state = self._first_state([receiver_state, *argument_states])
            if sanitizer is not None and transformed_state is not None:
                return _TaintState(
                    source=transformed_state.source,
                    source_line=transformed_state.source_line,
                    source_variable=transformed_state.source_variable,
                    sanitized=True,
                    sanitizer=sanitizer,
                    intermediate_vars=transformed_state.intermediate_vars,
                    source_column=transformed_state.source_column,
                    source_statement_order=transformed_state.source_statement_order,
                )
            if model is not None:
                resolved = self._resolve_return_model(
                    model,
                    function_name=function_name,
                    line=getattr(node, "lineno", None),
                    depth=depth,
                    call_stack=call_stack,
                )
                if resolved is None:
                    # Do not reinterpret an unresolved same-file return model
                    # as generic argument propagation.  A cutoff or cycle is
                    # incomplete analysis, never positive flow evidence.
                    return None
                if resolved is not None and resolved.kind == "constant":
                    return None
                if resolved is not None:
                    selected = self._select_argument_state(
                        node,
                        argument_states,
                        resolved,
                    )
                    if selected is None:
                        return None
                    if resolved.kind == "sanitizer":
                        model_sanitizer = next(
                            (
                                item for item in self.sanitizers
                                if item.matches(resolved.call_name)
                            ),
                            Sanitizer(resolved.call_name or call_name, "all"),
                        )
                        return _TaintState(
                            source=selected.source,
                            source_line=selected.source_line,
                            source_variable=selected.source_variable,
                            sanitized=True,
                            sanitizer=model_sanitizer,
                            intermediate_vars=selected.intermediate_vars,
                            source_column=selected.source_column,
                            source_statement_order=selected.source_statement_order,
                        )
                    return selected
            if any(sink.matches(call_name) for sink in self.sinks):
                return selected_argument
            return transformed_state
        child_states = [
            self._eval_taint_expr(
                child,
                state,
                function_name,
                depth=depth + 1,
                call_stack=call_stack,
            )
            for child in ast.iter_child_nodes(node)
        ]
        return self._first_state(child_states)

    def _assign_taint(
        self,
        target: ast.AST,
        value_state: _TaintState | None,
        state: dict[str, _TaintState],
    ) -> None:
        for target_name in self._target_names(target):
            if value_state is None:
                state.pop(target_name, None)
                continue
            intermediate = tuple(dict.fromkeys((*value_state.intermediate_vars, target_name)))
            state[target_name] = _TaintState(
                source=value_state.source,
                source_line=value_state.source_line,
                source_variable=target_name,
                sanitized=value_state.sanitized,
                sanitizer=value_state.sanitizer,
                intermediate_vars=intermediate,
                source_column=value_state.source_column,
                source_statement_order=value_state.source_statement_order,
            )

    def _state_for_name(
        self,
        node: ast.AST,
        state: dict[str, _TaintState],
    ) -> _TaintState | None:
        name = self._get_name(node)
        if not name:
            return None
        if name in state:
            return state[name]
        root = name.split(".", 1)[0]
        return state.get(root)

    @staticmethod
    def _target_names(node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            return [name for item in node.elts for name in TaintEngine._target_names(item)]
        name = TaintEngine._static_name(node)
        return [name] if name else []

    @staticmethod
    def _static_name(node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = TaintEngine._static_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Subscript):
            return TaintEngine._static_name(node.value)
        return None

    @staticmethod
    def _first_state(states: list[_TaintState | None]) -> _TaintState | None:
        return next((state for state in states if state is not None), None)

    def _select_argument_state(
        self,
        call: ast.Call,
        states: list[_TaintState | None],
        model: _TaintReturnModel,
    ) -> _TaintState | None:
        if model.argument_index is None:
            return self._first_state(states)

        function_name = (self._get_call_name(call) or "").rsplit(".", 1)[-1]
        signature = self._return_signatures.get(function_name)
        if signature is None or model.argument_index >= len(signature.parameters):
            if model.argument_index < len(states):
                return states[model.argument_index]
            return None

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
        return None

    @staticmethod
    def _merge_branch_states(
        state: dict[str, _TaintState],
        branches: list[dict[str, _TaintState]],
    ) -> None:
        for branch in branches:
            for name, branch_state in branch.items():
                current = state.get(name)
                if current is None or (current.sanitized and not branch_state.sanitized):
                    state[name] = branch_state

    def _collect_return_models(self, tree: ast.AST) -> dict[str, _TaintReturnModel]:
        functions = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]
        self._local_functions = {node.name for node in functions}
        self._return_signatures = {}
        models: dict[str, _TaintReturnModel] = {}
        for function in functions:
            positional_parameters = [
                arg.arg
                for arg in (
                    list(function.args.posonlyargs)
                    + list(function.args.args)
                )
            ]
            parameters = [
                *positional_parameters,
                *(arg.arg for arg in function.args.kwonlyargs),
            ]
            decorators = {
                (self._get_name(decorator) or "").lower()
                for decorator in function.decorator_list
            }
            implicit_receiver = bool(
                positional_parameters
                and positional_parameters[0] in {"self", "cls"}
                and "staticmethod" not in decorators
            )
            self._return_signatures[function.name] = _TaintFunctionSignature(
                parameters=tuple(parameters),
                positional_parameters=tuple(positional_parameters),
                implicit_receiver=implicit_receiver,
            )
            returns = self._function_returns(function)
            inferred = [
                self._infer_return_model(statement.value, parameters)
                for statement in returns
            ]
            if not returns:
                inferred = [_TaintReturnModel("constant")]
            if inferred and all(item is not None for item in inferred):
                first = inferred[0]
                if first is not None and all(item == first for item in inferred[1:]):
                    models[function.name] = first
        return models

    def _infer_return_model(
        self,
        value: ast.AST | None,
        parameters: list[str],
    ) -> _TaintReturnModel | None:
        if value is None or self._is_static_constant(value):
            return _TaintReturnModel("constant")
        if isinstance(value, ast.Name) and value.id in parameters:
            return _TaintReturnModel("identity", argument_index=parameters.index(value.id))
        if not isinstance(value, ast.Call):
            return None
        call_name = self._get_call_name(value) or ""
        argument_index = self._parameter_index_for_call(value, parameters)
        if argument_index is None:
            return None
        sanitizer = next(
            (item for item in self.sanitizers if item.matches(call_name)),
            None,
        )
        if sanitizer is not None:
            return _TaintReturnModel("sanitizer", call_name, argument_index)
        if call_name.rsplit(".", 1)[-1] in self._local_functions:
            return _TaintReturnModel("delegate", call_name, argument_index)
        return None

    def _resolve_return_model(
        self,
        model: _TaintReturnModel,
        *,
        function_name: str,
        line: int | None,
        depth: int,
        call_stack: tuple[str, ...],
    ) -> _TaintReturnModel | None:
        if self._visited_nodes >= self.max_nodes:
            self._diagnose(
                "analysis_truncated_max_nodes",
                function=function_name,
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
                function=function_name,
                line=line,
            )
            return None
        if self.cycle_detection and delegate in call_stack:
            self._diagnose(
                "cycle_detected",
                function=function_name,
                line=line,
                call=delegate,
            )
            return None
        delegated = self._return_models.get(delegate)
        if delegated is None:
            return None
        resolved = self._resolve_return_model(
            delegated,
            function_name=function_name,
            line=line,
            depth=depth + 1,
            call_stack=(*call_stack, delegate),
        )
        if resolved is None:
            return None
        return _TaintReturnModel(
            resolved.kind,
            resolved.call_name,
            model.argument_index,
        )

    def _walk_expression(
        self,
        node: ast.AST,
        function_name: str,
    ):
        stack: list[tuple[ast.AST, int]] = [(node, 0)]
        while stack:
            current, depth = stack.pop()
            if depth > self.max_depth:
                self._diagnose(
                    "analysis_truncated_max_depth",
                    function=function_name,
                    line=getattr(current, "lineno", None),
                )
                continue
            if not self._visit_node(current, function_name):
                return
            yield current
            children = list(ast.iter_child_nodes(current))
            stack.extend((child, depth + 1) for child in reversed(children))

    def _visit_node(self, node: ast.AST, function_name: str) -> bool:
        if self._visited_nodes >= self.max_nodes:
            self._diagnose(
                "analysis_truncated_max_nodes",
                function=function_name,
                line=getattr(node, "lineno", None),
            )
            return False
        self._visited_nodes += 1
        return True

    def _diagnose(self, reason: str, **context: object) -> None:
        payload = {
            "reason": reason,
            **{key: value for key, value in context.items() if value is not None},
        }
        key = (reason, tuple(sorted(payload.items())))
        if key in self._diagnostic_keys:
            return
        self._diagnostic_keys.add(key)
        self.diagnostics.append(payload)

    @staticmethod
    def _function_returns(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[ast.Return]:
        returns: list[ast.Return] = []

        class _ReturnVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
                if node is function:
                    self.generic_visit(node)

            def visit_AsyncFunctionDef(  # noqa: N802
                self,
                node: ast.AsyncFunctionDef,
            ) -> None:
                if node is function:
                    self.generic_visit(node)

            def visit_Lambda(self, node: ast.Lambda) -> None:  # noqa: N802
                return

            def visit_Return(self, node: ast.Return) -> None:  # noqa: N802
                returns.append(node)

        _ReturnVisitor().visit(function)
        return returns

    @classmethod
    def _is_static_constant(cls, node: ast.AST) -> bool:
        if isinstance(node, ast.Constant):
            return True
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            return all(cls._is_static_constant(item) for item in node.elts)
        if isinstance(node, ast.Dict):
            return all(
                (key is None or cls._is_static_constant(key))
                and cls._is_static_constant(value)
                for key, value in zip(node.keys, node.values)
            )
        if isinstance(node, ast.UnaryOp):
            return cls._is_static_constant(node.operand)
        if isinstance(node, ast.BinOp):
            return cls._is_static_constant(node.left) and cls._is_static_constant(node.right)
        return False

    @staticmethod
    def _parameter_index_for_call(call: ast.Call, parameters: list[str]) -> int | None:
        for argument in [*call.args, *(keyword.value for keyword in call.keywords)]:
            if isinstance(argument, ast.Name) and argument.id in parameters:
                return parameters.index(argument.id)
        return None

    def _check_assignment_source(
        self,
        node: ast.Assign,
        tainted_vars: dict[str, tuple[TaintSource, int]],
    ):
        """Check if the right side of an assignment is a taint source."""
        if not isinstance(node.value, ast.Call):
            return

        call_name = self._get_call_name(node.value)
        if not call_name:
            return

        for source in self.sources:
            if source.matches(call_name):
                for target in node.targets:
                    target_name = self._get_name(target)
                    if target_name:
                        tainted_vars[target_name] = (source, node.lineno)

    def _propagate_taint(
        self,
        node: ast.Assign,
        tainted_vars: dict[str, tuple[TaintSource, int]],
    ):
        """Propagate taint through assignments."""
        # Check if any variable on the right side is tainted
        rhs_vars = set()
        for child in ast.walk(node.value):
            name = self._get_name(child)
            if name:
                rhs_vars.add(name)

        for rhs_var in rhs_vars:
            if rhs_var in tainted_vars:
                # Propagate taint to left side
                for target in node.targets:
                    target_name = self._get_name(target)
                    if target_name and target_name not in tainted_vars:
                        tainted_vars[target_name] = tainted_vars[rhs_var]
                break

    def _is_sanitized(
        self,
        func_node: ast.FunctionDef,
        var_name: str,
        source_line: int,
        sink_line: int,
    ) -> bool:
        """Check if a variable is sanitized between source and sink lines."""
        for node in ast.walk(func_node):
            if not hasattr(node, "lineno"):
                continue
            if node.lineno <= source_line or node.lineno >= sink_line:
                continue

            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name:
                    for sanitizer in self.sanitizers:
                        if sanitizer.matches(call_name):
                            # Check if this sanitizer processes our variable
                            for arg in node.args:
                                if self._get_name(arg) == var_name:
                                    return True
        return False

    def _get_name(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._get_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    def _get_call_name(self, node: ast.Call) -> str | None:
        return self._get_name(node.func)
