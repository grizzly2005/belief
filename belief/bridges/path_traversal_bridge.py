"""
path_traversal_bridge.py — native CWE-22 detector (AST-based).

Fills the gap left by Bandit + DLint, which don't target path traversal.
No external dependencies. Detects these common anti-patterns:

  1. open(os.path.join(FIXED, user_var))  — when user_var reaches a function
     parameter without passing through os.path.basename / abspath / realpath /
     a secure_filename-style call.

  2. open(x) where x is a string formed by f"{base}/{user_var}" or
     base + user_var or base % user_var.

  3. Path(base) / user_var  without prior sanitization.

  4. shutil.copy/move, Path.open, codecs.open with the same patterns.

Rationale: equivalent to Semgrep rules python.lang.security.audit.path-traversal-*
but runs inline and doesn't need semgrep installed.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Union

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
    "basename", "abspath", "realpath", "normpath",
    "secure_filename",          # werkzeug
    "safe_join",                # flask / werkzeug
    "sanitize_filename",
    "resolve",                  # Path().resolve() — still dangerous but reduces risk
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

    def to_dict(self):
        return {
            "file": self.file, "line": self.line, "col": self.col,
            "rule_id": self.rule_id, "message": self.message,
            "severity": self.severity, "cwe": self.cwe,
        }


class _PathTraversalVisitor(ast.NodeVisitor):
    """Collects findings for a single file. Context: knows which variables are
    function parameters (potentially user-controlled) and which are sanitized."""

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Finding] = []
        # Stack of {param_name: {"sanitized": bool}} per enclosing function scope
        self._scopes: List[dict] = []

    # ---- scope management -------------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._visit_func(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._visit_func(node)

    def _visit_func(self, node):
        scope = {}
        # All positional / keyword-only args count as untrusted inputs
        args = node.args
        for a in list(args.args) + list(args.kwonlyargs):
            scope[a.arg] = {"sanitized": False, "tainted": True}
        if args.vararg:
            scope[args.vararg.arg] = {"sanitized": False, "tainted": True}
        if args.kwarg:
            scope[args.kwarg.arg] = {"sanitized": False, "tainted": True}
        self._scopes.append(scope)
        self.generic_visit(node)
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
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            tgt = node.targets[0].id
            if self._is_sanitizer_call(node.value):
                scope[tgt] = {"sanitized": True, "tainted": False, "from_join": False}
            else:
                rhs_tainted = self._expr_references_tainted(node.value)
                rhs_join = self._is_join_with_literal(node.value) or \
                           any(self._is_join_with_literal(n) for n in ast.walk(node.value))
                if rhs_tainted:
                    scope[tgt] = {
                        "sanitized": False,
                        "tainted": True,
                        "from_join": bool(rhs_join),
                    }
        self.generic_visit(node)

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
                    tainted_names = self._find_tainted(risky_arg)
                    if tainted_names:
                        rule_id = "path_traversal_user_input_to_sink"
                        msg = (
                            f"User-derived value {sorted(tainted_names)} joined "
                            f"to a base path and passed to a file sink (line "
                            f"{node.lineno}) without sanitization "
                            f"(basename/abspath/realpath/secure_filename). "
                            f"Classic CWE-22 sandbox illusion."
                        )
                        self.findings.append(Finding(
                            file=self.filename,
                            line=node.lineno,
                            col=node.col_offset,
                            rule_id=rule_id,
                            message=msg,
                        ))
                        break  # one finding per sink call is enough
        self.generic_visit(node)

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
        scope = self._current_scope()
        for sub in ast.walk(expr):
            if self._is_join_with_literal(sub):
                return True
            # BinOp(Add) or BinOp(Div): tainted on one side, stable on other
            if isinstance(sub, ast.BinOp) and isinstance(sub.op, (ast.Add, ast.Div)):
                left_tainted = self._expr_references_tainted(sub.left)
                right_tainted = self._expr_references_tainted(sub.right)
                # One side tainted, the other not → likely base+user or Path/user
                if left_tainted != right_tainted:
                    return True
        # Variables one hop back
        for sub in ast.walk(expr):
            if isinstance(sub, ast.Name):
                info = scope.get(sub.id)
                if info and info.get("from_join"):
                    return True
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
            if isinstance(f, ast.Attribute) and f.attr in PATH_JOIN_FUNCS:
                # os.path.join(a, b, ...) with 2+ args — classic sandbox pattern
                if len(node.args) >= 2:
                    return True
            # Path("/var/www/...") / something
            if isinstance(f, ast.Name) and f.id == "Path":
                return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # literal + user_var  (requires literal to avoid matching arbitrary adds)
            if isinstance(node.left, (ast.Constant, ast.Str)):
                val = node.left.value if isinstance(node.left, ast.Constant) else node.left.s
                if isinstance(val, str):
                    return True
        if isinstance(node, ast.JoinedStr):
            # f"{base}/{var}" — a path-looking f-string (contains '/' or ends with var)
            for v in node.values:
                if isinstance(v, (ast.Constant, ast.Str)):
                    s = v.value if isinstance(v, ast.Constant) else v.s
                    if isinstance(s, str) and "/" in s:
                        return True
        return False

    # ---- helpers ----------------------------------------------------------

    def _is_path_sink(self, call: ast.Call) -> bool:
        f = call.func
        if isinstance(f, ast.Name):
            return f.id in SINK_NAMES
        if isinstance(f, ast.Attribute):
            # open/read_text/write_text/etc on a path-like
            if f.attr in SINK_ATTRS or f.attr in {"read_text", "write_text",
                                                  "read_bytes", "write_bytes"}:
                return True
        return False

    def _risky_path_args(self, call: ast.Call) -> List[ast.AST]:
        """Returns all AST nodes that could represent paths being read/written.

        - For `open(path)`, `shutil.copy(src, dst)`, `os.remove(path)`:
          all positional args.
        - For `something.read_text()` / `.open()` / `.unlink()` (zero-arg
          attribute methods on a Path-like): the receiver only.
        """
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


def _scan_file(path: Path) -> List[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"),
                         filename=str(path))
    except SyntaxError:
        return []
    v = _PathTraversalVisitor(str(path))
    v.visit(tree)
    return v.findings


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
        "justification_type": "C4",  # AST-based check, conventional pattern
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
