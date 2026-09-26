"""
path_traversal_bridge.py — native CWE-22 detector (AST-based).

Fills the gap left by Bandit + DLint, which don't target path traversal.
No external dependencies. Detects these common anti-patterns:

  1. open(os.path.join(FIXED, user_var))  — when user_var reaches a function
     parameter without passing through a basename-style sanitizer or an
     ordered same-root rejection guard.

  2. open(x) where x is a string formed by f"{base}/{user_var}" or
     base + user_var or base % user_var.

  3. Path(base) / user_var  without prior sanitization.

  4. shutil.copy/move, Path.open, codecs.open with the same patterns.

  5. a helper returning a path built from an externally controlled component;
     the return boundary is reported unless a prior fail-closed containment
     check covers that exact value.

Rationale: equivalent to Semgrep rules python.lang.security.audit.path-traversal-*
but runs inline and doesn't need semgrep installed.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Set

from .belief_adapter import BridgeResult

# Callables that read/write paths (name form or attribute form)
SINK_NAMES: Set[str] = {
    "open",
}
SINK_ATTRS: Set[str] = {
    # os
    "open", "remove", "unlink", "rmdir", "makedirs", "mkdir",
    # shutil
    "copy", "copy2", "copyfile", "move", "rmtree",
    # pathlib.Path methods are detected via attr name too
    # codecs.open
}

# Sanitizers: if user data passes through any of these before the sink, clear.
SANITIZERS: Set[str] = {
    "basename",
    "secure_filename",          # werkzeug
    "safe_join",                # flask / werkzeug
    "sanitize_filename",
}

PATH_JOIN_FUNCS = {"join"}      # os.path.join, posixpath.join
# Plus operator on strings and f-strings are path construction too.


@dataclass
class Finding:
    file: str
    line: int
    col: int
    rule_id: str
    message: str
    severity: str = "high"
    cwe: str = "CWE-22"
    confidence: float = 0.9
    source_line: int | None = None
    sink: str = ""
    variables: tuple[str, ...] = ()

    def to_dict(self):
        description = self.message
        return {
            "file": self.file, "line": self.line, "col": self.col,
            "rule_id": self.rule_id, "message": self.message,
            "title": "Potentially external path component reaches a trusted boundary",
            "description": description,
            "evidence": description,
            "severity": self.severity, "confidence": self.confidence,
            "cwe": self.cwe,
            "source_line": self.source_line,
            "sink": self.sink,
            "variables": list(self.variables),
        }


class _PathTraversalVisitor(ast.NodeVisitor):
    """Collects findings for a single file. Context: knows which variables are
    function parameters (potentially user-controlled) and which are sanitized."""

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Finding] = []
        # Stack of {param_name: {"sanitized": bool}} per enclosing function scope
        self._scopes: List[dict] = []
        self._contexts: List[str] = []

    # ---- scope management -------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        self._contexts.append("class")
        try:
            self.generic_visit(node)
        finally:
            self._contexts.pop()

    def _visit_func(self, node):
        scope = {}
        # All positional / keyword-only args count as untrusted inputs
        args = node.args
        positional = list(args.posonlyargs) + list(args.args)
        is_static_method = any(
            _qualified_name(decorator) == "staticmethod"
            for decorator in node.decorator_list
        )
        receiver = (
            positional[0]
            if positional
            and self._contexts[-1:] == ["class"]
            and not is_static_method
            and positional[0].arg in {"self", "cls"}
            else None
        )
        for a in positional + list(args.kwonlyargs):
            is_receiver = a is receiver
            scope[a.arg] = {
                "sanitized": is_receiver,
                "tainted": not is_receiver,
                "origin_line": None if is_receiver else a.lineno,
            }
        if args.vararg:
            scope[args.vararg.arg] = {
                "sanitized": False,
                "tainted": True,
                "origin_line": args.vararg.lineno,
            }
        if args.kwarg:
            scope[args.kwarg.arg] = {
                "sanitized": False,
                "tainted": True,
                "origin_line": args.kwarg.lineno,
            }
        self._scopes.append(scope)
        self._contexts.append("function")
        try:
            self.generic_visit(node)
        finally:
            self._contexts.pop()
            self._scopes.pop()

    def _current_scope(self) -> dict:
        return self._scopes[-1] if self._scopes else {}

    # ---- sanitization & taint tracking ------------------------------------

    def visit_Assign(self, node: ast.Assign):
        """Taint propagation through assignments:
          - x = sanitizer(y)  -> x sanitized (clean)
          - x = <expr with tainted var>  -> x tainted
          - x = os.path.join(LITERAL, y) or LITERAL+y  -> x flagged from_join
        """
        scope = self._current_scope()
        if len(node.targets) == 1 and isinstance(node.targets[0], (ast.Tuple, ast.List)):
            rhs_tainted = self._expr_references_tainted(node.value)
            origin_line = self._tainted_origin_line(node.value)
            for target in node.targets[0].elts:
                if isinstance(target, ast.Name):
                    scope[target.id] = {
                        "sanitized": False,
                        "tainted": rhs_tainted,
                        "from_join": False,
                        "origin_line": origin_line,
                    }
        elif len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            tgt = node.targets[0].id
            root_name = self._path_root_name(node.value)
            if self._is_sanitizer_call(node.value):
                scope[tgt] = {
                    "sanitized": True,
                    "tainted": False,
                    "from_join": False,
                    "origin_line": None,
                    "root_name": None,
                }
            else:
                rhs_join = self._is_path_expression(node.value)
                rhs_tainted = bool(
                    self._find_tainted_path_components(node.value)
                    if rhs_join
                    else self._find_tainted(node.value)
                )
                if rhs_tainted:
                    scope[tgt] = {
                        "sanitized": False,
                        "tainted": True,
                        "from_join": bool(rhs_join),
                        "resolved": self._is_resolved_path(node.value),
                        "origin_line": self._tainted_origin_line(node.value),
                        "root_name": root_name,
                    }
                else:
                    scope[tgt] = {
                        "sanitized": False,
                        "tainted": False,
                        "from_join": False,
                        "origin_line": None,
                        "root_name": root_name,
                    }
        self.generic_visit(node)

    def visit_If(self, node: ast.If):
        """Apply a fail-closed containment guard only after its rejecting body.

        ``if not candidate.is_relative_to(root): raise`` after resolution protects
        ``candidate``.  A check of another value, a non-terminating body, or a
        check that occurs after a sink/return does not clear the flow.
        """

        # Module-level conditionals have no function-local taint scope.  They
        # may still contain function definitions, so descend normally without
        # attempting the branch-state merge used inside functions.
        if not self._scopes:
            self.generic_visit(node)
            return

        guarded_name = self._fail_closed_containment_name(node)
        self.visit(node.test)
        before = self._clone_scope(self._current_scope())

        self._scopes[-1] = self._clone_scope(before)
        for statement in node.body:
            self.visit(statement)
        body_scope = self._clone_scope(self._current_scope())

        self._scopes[-1] = self._clone_scope(before)
        for statement in node.orelse:
            self.visit(statement)
        else_scope = self._clone_scope(self._current_scope())

        self._scopes[-1] = self._merge_scopes(body_scope, else_scope)
        if guarded_name is None:
            return
        info = self._current_scope().get(guarded_name)
        if info is not None:
            info["sanitized"] = True
            info["tainted"] = False
            info["contained"] = True

    @staticmethod
    def _clone_scope(scope: dict) -> dict:
        return {name: dict(info) for name, info in scope.items()}

    @staticmethod
    def _merge_scopes(*scopes: dict) -> dict:
        merged: dict = {}
        names = set().union(*(scope.keys() for scope in scopes))
        for name in names:
            infos = [scope.get(name) for scope in scopes]
            present = [info for info in infos if info is not None]
            if not present:
                continue
            tainted = any(bool(info.get("tainted")) for info in present)
            sanitized = len(present) == len(scopes) and all(
                bool(info.get("sanitized")) for info in present
            )
            origin_lines = [
                int(info["origin_line"])
                for info in present
                if info.get("origin_line") is not None
            ]
            merged[name] = {
                "sanitized": sanitized,
                "tainted": tainted and not sanitized,
                "from_join": any(bool(info.get("from_join")) for info in present),
                "resolved": len(present) == len(scopes) and all(
                    bool(info.get("resolved")) for info in present
                ),
                "origin_line": min(origin_lines, default=None),
                "root_name": (
                    present[0].get("root_name")
                    if len(present) == len(scopes)
                    and all(
                        info.get("root_name") == present[0].get("root_name")
                        for info in present
                    )
                    else None
                ),
            }
        return merged

    def visit_Return(self, node: ast.Return):
        if (
            node.value is not None
            and self._has_sandbox_illusion(node.value)
            and not self._is_relative_path_label(node.value)
        ):
            self._record_path_risk(node.value, node, boundary="helper return")
        self.generic_visit(node)

    @staticmethod
    def _is_relative_path_label(expression: ast.AST) -> bool:
        """A relative label rendering alone does not establish a filesystem sink.

        Do not mark its underlying value sanitized: the same expression at an
        actual file sink still needs containment analysis.
        """
        if not (
            isinstance(expression, ast.BinOp)
            and isinstance(expression.op, ast.Add)
            and isinstance(expression.left, ast.Constant)
            and isinstance(expression.left.value, str)
            and not expression.left.value.startswith(("/", "\\"))
            and ":" not in expression.left.value
        ):
            return False
        rendered = expression.right
        if not (
            isinstance(rendered, ast.Call)
            and not rendered.args and not rendered.keywords
            and isinstance(rendered.func, ast.Attribute)
            and rendered.func.attr == "as_posix"
        ):
            return False
        relative = rendered.func.value
        return (
            isinstance(relative, ast.Call)
            and isinstance(relative.func, ast.Attribute)
            and relative.func.attr == "relative_to"
            and len(relative.args) == 1
            and not relative.keywords
        )

    def _is_resolved_path(self, expression: ast.AST) -> bool:
        if isinstance(expression, ast.Name):
            return bool(self._current_scope().get(expression.id, {}).get("resolved"))
        if not isinstance(expression, ast.Call):
            return False
        return (
            _qualified_name(expression.func) == "os.path.realpath"
            or (
                isinstance(expression.func, ast.Attribute)
                and expression.func.attr == "resolve"
                and not expression.args
            )
        )

    def _expr_references_tainted(self, expr) -> bool:
        """True if expr reads a currently-tainted name (parameters or
        variables previously assigned from a tainted expression)."""
        scope = self._current_scope()
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name):
                info = scope.get(sub.id)
                if info and info.get("tainted") and not info.get("sanitized"):
                    return True
        return False

    def _is_sanitizer_call(self, expr) -> bool:
        """True if expr is a call to a sanitizer function we recognize."""
        if not isinstance(expr, ast.Call):
            return False
        f = expr.func
        if isinstance(f, ast.Name) and f.id in SANITIZERS:
            return True
        if isinstance(f, ast.Attribute) and f.attr in SANITIZERS:
            return True
        return False

    # ---- sinks ------------------------------------------------------------

    def visit_Call(self, node: ast.Call):
        if self._is_path_sink(node):
            risky_args = self._risky_path_args(node)
            for risky_arg in risky_args:
                if self._has_sandbox_illusion(risky_arg):
                    if self._record_path_risk(risky_arg, node, boundary="file sink"):
                        break  # one finding per sink call is enough
        self.generic_visit(node)

    def _record_path_risk(
        self,
        expression: ast.AST,
        anchor: ast.AST,
        *,
        boundary: str,
    ) -> bool:
        tainted_names = self._find_tainted_path_components(expression)
        if not tainted_names:
            return False
        msg = (
            f"Potentially external value {sorted(tainted_names)} is joined to a base "
            f"path and reaches a {boundary} at line {anchor.lineno} without "
            "basename-style sanitization or an ordered same-root rejection guard."
        )
        self.findings.append(Finding(
            file=self.filename,
            line=anchor.lineno,
            col=anchor.col_offset,
            rule_id="path_traversal_user_input_to_boundary",
            message=msg,
            # Parameters are conservatively modeled as potentially external,
            # but this local AST pass has no caller or framework-boundary
            # evidence. Keep impact high while expressing that uncertainty in
            # the independent confidence field.
            confidence=0.75 if boundary == "file sink" else 0.65,
            source_line=min(
                (
                    int(self._current_scope().get(name, {}).get("origin_line"))
                    for name in tainted_names
                    if self._current_scope().get(name, {}).get("origin_line") is not None
                ),
                default=None,
            ),
            sink=boundary,
            variables=tuple(sorted(tainted_names)),
        ))
        return True

    def _fail_closed_containment_name(self, node: ast.If) -> str | None:
        if node.orelse or not self._statements_terminate(node.body):
            return None
        test = node.test
        if not isinstance(test, ast.UnaryOp) or not isinstance(test.op, ast.Not):
            return None
        call = test.operand
        if not isinstance(call, ast.Call) or call.keywords or len(call.args) != 1:
            return None
        function = call.func
        if not isinstance(function, ast.Attribute) or function.attr != "is_relative_to":
            return None
        if not isinstance(function.value, ast.Name):
            return None
        guarded_name = function.value.id
        info = self._current_scope().get(guarded_name)
        if (
            not info or not info.get("from_join")
            or not info.get("root_name") or not info.get("resolved")
        ):
            return None
        if self._guard_root_name(call.args[0]) != info["root_name"]:
            return None
        return guarded_name

    def _path_root_name(self, expression: ast.AST) -> str | None:
        if isinstance(expression, ast.Name):
            info = self._current_scope().get(expression.id, {})
            return info.get("root_name")
        if isinstance(expression, ast.Call):
            qualified = _qualified_name(expression.func)
            if isinstance(expression.func, ast.Attribute) and expression.func.attr == "resolve":
                return self._path_root_name(expression.func.value)
            if qualified in {
                "os.path.abspath",
                "os.path.normpath",
                "os.path.realpath",
            } and expression.args:
                return self._path_root_name(expression.args[0])
            if (
                qualified in {"ntpath.join", "os.path.join", "posixpath.join"}
                and expression.args
            ):
                return self._guard_root_name(expression.args[0])
            if (
                isinstance(expression.func, ast.Name)
                and expression.func.id == "Path"
                and expression.args
            ):
                return self._guard_root_name(expression.args[0])
        if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
            return self._guard_root_name(expression.left)
        return None

    @staticmethod
    def _guard_root_name(expression: ast.AST) -> str | None:
        if isinstance(expression, ast.Name):
            return expression.id
        if (
            isinstance(expression, ast.Call)
            and len(expression.args) == 1
            and isinstance(expression.args[0], ast.Name)
            and (
                isinstance(expression.func, ast.Name)
                and expression.func.id in {"Path", "str"}
            )
        ):
            return expression.args[0].id
        return None

    @staticmethod
    def _statements_terminate(statements: List[ast.stmt]) -> bool:
        return bool(statements) and isinstance(
            statements[-1],
            (ast.Raise, ast.Return, ast.Break, ast.Continue),
        )

    def _has_sandbox_illusion(self, expr) -> bool:
        """True if expr (or any variable it references) was built by
        concatenating a fixed base path with other values.

        Patterns caught:
          - os.path.join(anything, X)  with 2+ args
          - BASE + user_var  (where at least one side is tainted and the
            other is either a str literal or a non-tainted Name)
          - f"{BASE}/{user_var}"  with any literal containing '/'
          - Path(BASE) / user_var
          - Variable x that was previously assigned from any of the above.
        """
        return self._is_path_expression(expr)

    def _is_path_expression(self, expression: ast.AST) -> bool:
        """Return whether *the expression's value* is a constructed path.

        Deliberately do not walk arbitrary nested calls: the result of
        ``open(os.path.join(...))`` is a handle, and the result of
        ``exists(os.path.join(...))`` is a boolean, not a path.
        """

        if isinstance(expression, ast.Name):
            info = self._current_scope().get(expression.id)
            return bool(info and info.get("from_join"))
        if self._is_join_with_literal(expression):
            return True
        if isinstance(expression, ast.Call):
            qualified = _qualified_name(expression.func)
            if qualified in {
                "os.path.abspath",
                "os.path.normpath",
                "os.path.realpath",
            } and expression.args:
                return self._is_path_expression(expression.args[0])
            if (
                isinstance(expression.func, ast.Attribute)
                and expression.func.attr == "resolve"
            ):
                return self._is_path_expression(expression.func.value)
        return False

    @staticmethod
    def _is_join_with_literal(node) -> bool:
        """True if node is a path construction where a 'base' component is
        joined with other components. For os.path.join, we consider any call
        with 2+ args — the sandbox-illusion pattern is 'join(base, user_var)'.
        For +/% operators and f-strings, we require a string literal base so
        we don't flag pure-variable concatenation in non-path contexts.
        """
        if isinstance(node, ast.Call):
            f = node.func
            if (
                isinstance(f, ast.Attribute)
                and _qualified_name(f)
                in {"ntpath.join", "os.path.join", "posixpath.join"}
            ):
                # os.path.join(a, b, ...) with 2+ args — classic sandbox pattern
                if len(node.args) >= 2:
                    return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            # The division operator only constructs a path when its left-most
            # operand is explicitly Path-like.  Treating every numeric divide
            # with one parameter operand as a path caused pervasive FPs.
            left = node.left
            while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Div):
                left = left.left
            if isinstance(left, ast.Call) and _qualified_name(left.func) in {
                "Path",
                "pathlib.Path",
            }:
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # A literal prefix must actually look like a directory boundary;
            # ordinary string assembly is not a filesystem operation.
            if isinstance(node.left, ast.Constant) and isinstance(
                node.left.value, str
            ):
                return _looks_like_path_literal(node.left.value)
        if isinstance(node, ast.JoinedStr):
            # f"{base}/{var}" — a path-looking f-string (contains '/' or ends with var)
            for v in node.values:
                if (
                    isinstance(v, ast.Constant)
                    and isinstance(v.value, str)
                    and _looks_like_path_literal(v.value)
                ):
                    return True
        return False

    # ---- helpers ----------------------------------------------------------

    def _is_path_sink(self, call: ast.Call) -> bool:
        f = call.func
        if isinstance(f, ast.Name):
            return f.id in SINK_NAMES
        if isinstance(f, ast.Attribute):
            qualified = _qualified_name(f)
            if qualified in {"codecs.open", "io.open", "os.open", "tokenize.open"}:
                return True
            if qualified.startswith("os.") and f.attr in SINK_ATTRS:
                return True
            if qualified.startswith("shutil.") and f.attr in SINK_ATTRS:
                return True
            if f.attr in {
                "open",
                "read_bytes",
                "read_text",
                "write_bytes",
                "write_text",
                "mkdir",
                "rmdir",
                "unlink",
            }:
                return self._is_path_expression(f.value)
        return False

    def _risky_path_args(self, call: ast.Call) -> List[ast.AST]:
        """Returns all AST nodes that could represent paths being read/written.

        - For `open(path)`, `shutil.copy(src, dst)`, `os.remove(path)`:
          all positional args.
        - For `something.read_text()` / `.open()` / `.unlink()` (zero-arg
          attribute methods on a Path-like): the receiver only.
        """
        if (
            isinstance(call.func, ast.Attribute)
            and call.func.attr in {
                "open",
                "read_bytes",
                "read_text",
                "write_bytes",
                "write_text",
                "mkdir",
                "rmdir",
                "unlink",
            }
            and self._is_path_expression(call.func.value)
        ):
            return [call.func.value]
        if call.args:
            return list(call.args)
        # Zero-arg attribute call: return the receiver
        if isinstance(call.func, ast.Attribute):
            return [call.func.value]
        return []

    def _find_tainted(self, expr) -> Set[str]:
        """Walk expr. Return set of names it reads that are currently tainted
        and not sanitized in the current scope."""
        tainted: Set[str] = set()
        scope = self._current_scope()
        # Exception: if the whole expr IS a sanitizer call, clear taint.
        if isinstance(expr, ast.Call) and self._is_sanitizer_call(expr):
            return set()
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name):
                info = scope.get(sub.id)
                if info and info.get("tainted") and not info.get("sanitized"):
                    tainted.add(sub.id)
        return tainted

    def _tainted_origin_line(self, expr: ast.AST) -> int | None:
        scope = self._current_scope()
        lines = [
            int(scope[name]["origin_line"])
            for name in self._find_tainted(expr)
            if scope.get(name, {}).get("origin_line") is not None
        ]
        return min(lines, default=None)

    def _find_tainted_path_components(self, expr: ast.AST) -> Set[str]:
        """Return tainted leaf components, excluding a join's trusted base.

        A base/root argument may itself be a function parameter.  Treating it
        as the controlled filename would flag every safe
        ``join(root, basename(value))`` helper.  For path constructions we
        therefore inspect only the components appended to that base.
        """

        if isinstance(expr, ast.Call):
            function = expr.func
            if (
                isinstance(function, ast.Attribute)
                and function.attr in PATH_JOIN_FUNCS
                and len(expr.args) >= 2
            ):
                result: Set[str] = set()
                for component in expr.args[1:]:
                    result.update(self._find_tainted(component))
                return result
        if isinstance(expr, ast.BinOp) and isinstance(expr.op, (ast.Add, ast.Div)):
            return self._find_tainted(expr.right)
        return self._find_tainted(expr)


def _scan_file(path: Path) -> List[Finding]:
    try:
        source = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError):
        return []
    return [Finding(**item) for item in scan_source(source, str(path), _raw=True)]


def scan_source(
    source: str,
    filename: str,
    *,
    _raw: bool = False,
) -> List[Dict[str, Any]]:
    """Analyze captured Python source without filesystem or network access."""

    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, TypeError, ValueError):
        return []
    visitor = _PathTraversalVisitor(filename or "<unknown>")
    visitor.visit(tree)
    ordered = sorted(
        visitor.findings,
        key=lambda item: (item.line, item.col, item.rule_id, item.message),
    )
    if _raw:
        return [
            {
                "file": item.file,
                "line": item.line,
                "col": item.col,
                "rule_id": item.rule_id,
                "message": item.message,
                "severity": item.severity,
                "cwe": item.cwe,
                "confidence": item.confidence,
                "source_line": item.source_line,
                "sink": item.sink,
                "variables": item.variables,
            }
            for item in ordered
        ]
    return [item.to_dict() for item in ordered]


def run(project_path: str, **kwargs) -> BridgeResult:
    """Scan all *.py files in project_path for path traversal patterns."""
    import time
    t0 = time.time()
    root = Path(project_path)
    if not root.exists():
        return BridgeResult(
            source="path_traversal",
            findings=[],
            errors=[f"Path does not exist: {project_path}"],
            elapsed_s=time.time() - t0,
        )

    files: List[Path] = []
    if root.is_file() and root.suffix == ".py":
        files = [root]
    else:
        files = list(root.rglob("*.py"))

    # Skip common vendored/bundled trees
    SKIP_PARTS = {
        "tools_bundled", "security_rules", "node_modules",
        ".venv", "venv", "__pycache__", ".git",
    }
    files = [
        f for f in files
        if not any(part in SKIP_PARTS for part in f.parts)
    ]

    all_findings: List[Finding] = []
    errors: List[str] = []
    for f in files:
        try:
            all_findings.extend(_scan_file(f))
        except Exception as e:
            errors.append(f"{f}: {type(e).__name__}: {e}")

    return BridgeResult(
        source="path_traversal",
        findings=[f.to_dict() for f in all_findings],
        errors=errors,
        elapsed_s=time.time() - t0,
    )


def to_belief(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a path_traversal finding dict to the belief-adapter shape.

    The belief_adapter looks up `to_belief` via importlib on each bridge
    module; if absent, it passes the finding through as-is. The raw finding
    dict here only has {file, line, col, rule_id, message, severity, cwe}
    and lacks the `assumption` key the adapter historically required, so
    path_traversal findings were silently dropped before this was added.
    """
    return {
        "assumption": f"path_traversal {finding.get('rule_id','')}: "
                      f"{finding.get('message', '')}",
        "anchor_file": finding.get("file", ""),
        "anchor_line": finding.get("line", 0),
        "anchor_line_end": finding.get("line", 0),
        "justification_type": "C2_STATICALLY_VERIFIED_PROPERTY",
        "contextual_constraint": f"severity={finding.get('severity','high')}",
        "trust_domain": Path(finding.get("file", "")).stem if finding.get("file") else "",
        "logic_type": "info_flow",
        "source": "path_traversal",
        "cwe": finding.get("cwe", "CWE-22"),
        "raw": finding,
    }


def register(registry) -> None:
    """Called by bridges.__init__ auto-register."""
    registry.register("path_traversal", run)


__all__ = ["Finding", "scan_source", "run", "to_belief"]


def _qualified_name(expression: ast.AST) -> str:
    parts: list[str] = []
    current = expression
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return ".".join(reversed(parts))


def _looks_like_path_literal(value: str) -> bool:
    """Recognize a filesystem-looking separator without treating URLs as paths."""

    return "://" not in value and any(separator in value for separator in ("/", "\\"))
