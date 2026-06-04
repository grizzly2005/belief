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

    def to_belief(self, file_path: str, function_name: str = "",
                  module: str = "") -> Belief:
        """Convert this taint path to a BELIEF information flow belief."""
        if self.sanitized:
            expr = (
                f"{self.source_variable} is sanitized before reaching "
                f"{self.sink.name}"
            )
            justification = JustificationCategory.C2_CALLER_VERIFICATION
            epistemic = EpistemicStatus.BELIEF
        else:
            expr = (
                f"taint({self.source_variable}, source={self.source.category}) "
                f"reaches {self.sink.name}({self.sink_variable}) without sanitization"
            )
            justification = JustificationCategory.C5_NO_JUSTIFICATION
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
    ):
        self.sources = sources or DEFAULT_SOURCES
        self.sinks = sinks or DEFAULT_SINKS
        self.sanitizers = sanitizers or DEFAULT_SANITIZERS

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

        all_paths = []
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
            p.to_belief(file_path, module=module)
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
        # Step 1: Find taint sources in this function
        tainted_vars: dict[str, tuple[TaintSource, int]] = {}  # var → (source, line)

        # Parameters from untrusted sources
        for arg in func_node.args.args:
            if arg.arg in ("request", "req", "data", "input", "body", "payload",
                           "query", "params", "headers", "user_input"):
                source = TaintSource(arg.arg, "user_input", "high")
                tainted_vars[arg.arg] = (source, func_node.lineno)

        # Walk function body
        for node in ast.walk(func_node):
            # Assignment from taint source
            if isinstance(node, ast.Assign):
                self._check_assignment_source(node, tainted_vars)

            # Augmented assignment
            if isinstance(node, ast.AugAssign):
                target_name = self._get_name(node.target)
                if target_name and target_name in tainted_vars:
                    pass  # stays tainted

            # Taint propagation through assignment
            if isinstance(node, ast.Assign):
                self._propagate_taint(node, tainted_vars)

        # Step 2: Find sinks and check if tainted data reaches them
        paths = []
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if not call_name:
                    continue

                # Check if this call is a sink
                for sink in self.sinks:
                    if sink.matches(call_name):
                        # Check if any argument is tainted
                        for arg in node.args:
                            arg_name = self._get_name(arg)
                            if arg_name and arg_name in tainted_vars:
                                source, source_line = tainted_vars[arg_name]
                                # Check for sanitization between source and sink
                                sanitized = self._is_sanitized(
                                    func_node, arg_name, source_line, node.lineno
                                )
                                paths.append(TaintPath(
                                    source=source,
                                    source_line=source_line,
                                    source_variable=arg_name,
                                    sink=sink,
                                    sink_line=node.lineno,
                                    sink_variable=arg_name,
                                    sanitized=sanitized,
                                    confidence=0.85 if not sanitized else 0.4,
                                ))

                        # Check keyword args too
                        for kw in node.keywords:
                            if kw.arg:
                                val_name = self._get_name(kw.value)
                                if val_name and val_name in tainted_vars:
                                    source, source_line = tainted_vars[val_name]
                                    sanitized = self._is_sanitized(
                                        func_node, val_name, source_line, node.lineno
                                    )
                                    paths.append(TaintPath(
                                        source=source,
                                        source_line=source_line,
                                        source_variable=val_name,
                                        sink=sink,
                                        sink_line=node.lineno,
                                        sink_variable=val_name,
                                        sanitized=sanitized,
                                        confidence=0.85 if not sanitized else 0.4,
                                    ))

        return paths

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
