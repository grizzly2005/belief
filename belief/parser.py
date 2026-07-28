"""
BELIEF — Code parser and frontier detector.

Uses Python AST (stdlib) for Python codebases. Identifies inter-component
boundaries, call graphs, and trust asymmetry scores without any LLM calls.

This is the Perception layer — lightweight, CPU-only, processes entire
codebases in seconds.
"""

from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .models import Frontier, Scope, TrustProfile


# ─────────────────────────────────────────────
#  Parsed Function
# ─────────────────────────────────────────────

@dataclass
class ParsedFunction:
    """A function extracted from source code with metadata."""

    name: str
    class_name: Optional[str]
    module: str
    file_path: str
    line_start: int
    line_end: int
    source_code: str
    decorators: list[str] = field(default_factory=list)
    parameters: list[str] = field(default_factory=list)
    return_annotation: Optional[str] = None
    docstring: Optional[str] = None
    calls: list[str] = field(default_factory=list)       # functions this calls
    called_by: list[str] = field(default_factory=list)    # functions that call this
    imports_used: list[str] = field(default_factory=list)
    has_try_except: bool = False
    has_assertions: bool = False
    accesses_external: bool = False   # network, file, subprocess, DB
    is_public: bool = True

    @property
    def qualified_name(self) -> str:
        parts = [self.module]
        if self.class_name:
            parts.append(self.class_name)
        parts.append(self.name)
        return ".".join(parts)

    def to_scope(self) -> Scope:
        return Scope(
            file_path=self.file_path,
            function_name=self.name,
            class_name=self.class_name,
            module=self.module,
            line_start=self.line_start,
            line_end=self.line_end,
        )


# ─────────────────────────────────────────────
#  External interaction markers
# ─────────────────────────────────────────────

EXTERNAL_MARKERS = {
    # Network
    "requests", "urllib", "http", "socket", "aiohttp", "httpx",
    "urlopen", "fetch", "get", "post", "put", "delete",
    # File system
    "open", "read", "write", "Path", "os.path", "shutil",
    "makedirs", "remove", "rename",
    # Subprocess
    "subprocess", "Popen", "call", "run", "system", "exec",
    "eval", "compile",
    # Database
    "execute", "cursor", "connect", "query", "session",
    "sqlalchemy", "sqlite3", "psycopg",
    # Serialization (trust boundary)
    "pickle", "yaml.load", "json.loads", "marshal",
    "deserialize", "fromstring",
}

UNTRUSTED_SOURCES = {
    "request", "input", "argv", "stdin", "environ",
    "form", "args", "params", "query", "body",
    "headers", "cookies", "files", "upload",
    "recv", "read", "readline",
}


DEFAULT_EXCLUDE_DIRS = {
    ".cache",
    ".eggs",
    ".git",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "adapted",
    "archive",
    "archives",
    "benchmark_susvibes",
    "benchmark_suite",
    "build",
    "cache",
    "caches",
    "dist",
    "docs",
    "doc",
    "eggs",
    "env",
    "examples",
    "generated",
    "migrations",
    "node_modules",
    "security_rules",
    "symbolic",
    "target_flaskjwt",
    "third_party",
    "tools_bundled",
    "test",
    "tests",
    "vendor",
    "vendors",
    "vendored",
    "venv",
    "venv_belief",
}

GENERATED_FILE_NAMES = {
    "_pb2.py",
    "_pb2_grpc.py",
}


@dataclass
class ScanRoots:
    """Explicit scan-root configuration.

    source_roots and corpus_roots are scanned when provided. rule_roots are
    tracked as configuration but intentionally not scanned by the parser.
    """

    source_roots: list[str] = field(default_factory=list)
    corpus_roots: list[str] = field(default_factory=list)
    rule_roots: list[str] = field(default_factory=list)
    excluded_roots: list[str] = field(default_factory=list)
    include_docs: bool = False


# ─────────────────────────────────────────────
#  AST Visitor
# ─────────────────────────────────────────────

class _FunctionVisitor(ast.NodeVisitor):
    """Extract functions, calls, and external interactions from an AST."""

    def __init__(self, source_lines: list[str], file_path: str, module: str):
        self.source_lines = source_lines
        self.file_path = file_path
        self.module = module
        self.functions: list[ParsedFunction] = []
        self._current_class: Optional[str] = None

    def visit_ClassDef(self, node: ast.ClassDef):
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self._extract_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self._extract_function(node)

    def _extract_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef):
        # Extract source
        start = node.lineno - 1
        end = node.end_lineno if node.end_lineno else start + 1
        source = "\n".join(self.source_lines[start:end])

        # Decorators
        decorators = []
        for d in node.decorator_list:
            if isinstance(d, ast.Name):
                decorators.append(d.id)
            elif isinstance(d, ast.Attribute):
                decorators.append(d.attr)

        # Parameters
        params = [a.arg for a in node.args.args if a.arg != "self"]

        # Return annotation
        ret_ann = None
        if node.returns:
            ret_ann = ast.dump(node.returns)

        # Docstring
        docstring = ast.get_docstring(node)

        # Walk body for calls and patterns
        calls = []
        has_try = False
        has_assert = False
        accesses_external = False

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    calls.append(call_name)
                    if any(m in call_name.lower() for m in EXTERNAL_MARKERS):
                        accesses_external = True
            elif isinstance(child, ast.Try):
                has_try = True
            elif isinstance(child, ast.Assert):
                has_assert = True
            elif isinstance(child, ast.Name):
                if child.id.lower() in UNTRUSTED_SOURCES:
                    accesses_external = True

        pf = ParsedFunction(
            name=node.name,
            class_name=self._current_class,
            module=self.module,
            file_path=self.file_path,
            line_start=node.lineno,
            line_end=end,
            source_code=source,
            decorators=decorators,
            parameters=params,
            return_annotation=ret_ann,
            docstring=docstring,
            calls=calls,
            has_try_except=has_try,
            has_assertions=has_assert,
            accesses_external=accesses_external,
            is_public=not node.name.startswith("_"),
        )
        self.functions.append(pf)

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return None


# ─────────────────────────────────────────────
#  Code Parser
# ─────────────────────────────────────────────

class CodeParser:
    """
    Parse a Python codebase and extract functions, call graphs, and frontiers.

    This is the Perception layer of BELIEF — no LLM, pure CPU, fast.
    """

    def __init__(
        self,
        root_path: str,
        exclude_dirs: set[str] | None = None,
        *,
        source_roots: list[str] | None = None,
        corpus_roots: list[str] | None = None,
        rule_roots: list[str] | None = None,
        excluded_roots: list[str] | None = None,
        include_docs: bool = False,
        scan_roots: ScanRoots | None = None,
    ):
        self.root_path = Path(root_path)
        self.exclude_dirs = set(DEFAULT_EXCLUDE_DIRS)
        self.scan_roots = scan_roots or ScanRoots(
            source_roots=list(source_roots or []),
            corpus_roots=list(corpus_roots or []),
            rule_roots=list(rule_roots or []),
            excluded_roots=list(excluded_roots or []),
            include_docs=include_docs,
        )
        if self.scan_roots.include_docs:
            self.exclude_dirs.discard("docs")
            self.exclude_dirs.discard("doc")
        if exclude_dirs:
            self.exclude_dirs.update(d.lower() for d in exclude_dirs)
        self.excluded_root_paths = [
            self._resolve_configured_path(path)
            for path in self.scan_roots.excluded_roots
        ]
        self.functions: dict[str, ParsedFunction] = {}  # qualified_name → func
        self.call_graph: dict[str, set[str]] = {}        # caller → {callees}

    def parse(self) -> list[ParsedFunction]:
        """Parse all Python files in the project."""
        py_files = self._collect_python_files()

        for fpath in py_files:
            try:
                self._parse_file(fpath)
            except (SyntaxError, UnicodeDecodeError) as e:
                if hasattr(self, '_verbose') and self._verbose:
                    print(f"  [SKIP] {fpath}: {e}")
                continue

        self._build_call_graph()
        return list(self.functions.values())

    def detect_frontiers(self, trust_threshold: float = 0.3) -> list[Frontier]:
        """
        Identify frontiers — boundaries between components where trust
        changes or external interactions occur.
        """
        frontiers = []

        for qname, func in self.functions.items():
            for call_name in func.calls:
                # Find the called function
                callee = self._resolve_call(call_name, func)
                if callee is None:
                    continue

                # Calculate trust asymmetry
                asymmetry = self._calculate_trust_asymmetry(func, callee)
                if asymmetry < trust_threshold:
                    continue

                # Build trust profile (inspired by Claude Code Tool.ts)
                profile = TrustProfile(
                    is_read_only=not callee.accesses_external,
                    validates_input=callee.has_assertions,
                    has_timeout=False,  # would need deeper analysis
                    has_sandbox=False,  # would need context about execution env
                    crosses_network=any(
                        kw in " ".join(callee.calls).lower()
                        for kw in ["request", "http", "url", "socket", "fetch"]
                    ),
                    crosses_process=any(
                        kw in " ".join(callee.calls).lower()
                        for kw in ["subprocess", "popen", "exec", "system"]
                    ),
                    handles_untrusted=func.accesses_external,
                    error_handling=(
                        "comprehensive" if callee.has_try_except and callee.has_assertions
                        else "partial" if callee.has_try_except
                        else "none"
                    ),
                )

                frontier = Frontier(
                    caller_scope=func.to_scope(),
                    callee_scope=callee.to_scope(),
                    call_site_line=None,
                    trust_asymmetry=asymmetry,
                    trust_profile=profile,
                    description=self._describe_frontier(func, callee, asymmetry),
                )
                frontiers.append(frontier)

        # Deduplicate
        seen = set()
        unique = []
        for f in frontiers:
            key = f"{f.caller_scope.qualified_name}->{f.callee_scope.qualified_name}"
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return sorted(unique, key=lambda f: f.trust_asymmetry, reverse=True)

    # ── Internal ──

    def _collect_python_files(self) -> list[Path]:
        files = []
        for base_root in self._scan_base_paths():
            if base_root.is_file():
                if base_root.suffix == ".py" and not self._is_generated_file(base_root):
                    files.append(base_root)
                continue
            if not base_root.exists():
                continue
            for current_dir, dirnames, filenames in os.walk(base_root, followlinks=False):
                current_path = Path(current_dir)
                dirnames[:] = [
                    name for name in dirnames
                    if not (current_path / name).is_symlink()
                    and not self._is_excluded_dir(current_path / name, base_root=base_root)
                ]
                for filename in filenames:
                    if not filename.endswith(".py"):
                        continue
                    py_file = current_path / filename
                    if (
                        not py_file.is_symlink()
                        and not self._is_generated_file(py_file)
                        and not self._is_excluded_path(py_file, base_root=base_root)
                    ):
                        files.append(py_file)
        return sorted(set(files))

    def _scan_base_paths(self) -> list[Path]:
        configured = list(self.scan_roots.source_roots) + list(self.scan_roots.corpus_roots)
        if not configured:
            return [self.root_path]

        paths = []
        for item in configured:
            path = self._resolve_configured_path(item)
            if not self._is_under_excluded_root(path):
                paths.append(path)
        return paths

    def _resolve_configured_path(self, value: str) -> Path:
        path = Path(value)
        if path.is_absolute():
            return path
        return self.root_path / path

    def _is_generated_file(self, py_file: Path) -> bool:
        name = py_file.name.lower()
        if any(name.endswith(suffix) for suffix in GENERATED_FILE_NAMES):
            return True
        if name.endswith("_generated.py") or name.endswith(".generated.py"):
            return True
        try:
            with py_file.open(encoding="utf-8", errors="ignore") as f:
                head = "".join(f.readline() for _ in range(5)).lower()
        except OSError:
            return False
        return "code generated" in head or "@generated" in head

    def _is_under_excluded_root(self, path: Path) -> bool:
        if not self.excluded_root_paths:
            return False
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path.absolute()
        for root in self.excluded_root_paths:
            try:
                excluded = root.resolve()
            except OSError:
                excluded = root.absolute()
            if resolved == excluded or excluded in resolved.parents:
                return True
        return False

    def _is_excluded_path(self, py_file: Path, base_root: Path | None = None) -> bool:
        if self._is_under_excluded_root(py_file):
            return True
        base = base_root or self.root_path
        try:
            rel = py_file.relative_to(base)
        except ValueError:
            try:
                rel = py_file.relative_to(self.root_path)
            except ValueError:
                rel = py_file

        return self._has_excluded_part(rel.parts[:-1])

    def _is_excluded_dir(self, dir_path: Path, base_root: Path | None = None) -> bool:
        if self._is_under_excluded_root(dir_path):
            return True
        base = base_root or self.root_path
        try:
            rel = dir_path.relative_to(base)
        except ValueError:
            try:
                rel = dir_path.relative_to(self.root_path)
            except ValueError:
                rel = dir_path

        return self._has_excluded_part(rel.parts)

    def _has_excluded_part(self, parts: tuple[str, ...]) -> bool:
        for part in parts:
            name = part.lower()
            if name in self.exclude_dirs:
                return True
            if name.endswith(".egg-info") or name.endswith("_adapted"):
                return True
        return False

    def _parse_file(self, file_path: Path):
        source = file_path.read_text(encoding="utf-8", errors="replace")
        lines = source.split("\n")
        module = self._path_to_module(file_path)

        tree = ast.parse(source, filename=str(file_path))
        visitor = _FunctionVisitor(lines, str(file_path), module)
        visitor.visit(tree)

        for func in visitor.functions:
            self.functions[func.qualified_name] = func

    def _path_to_module(self, path: Path) -> str:
        try:
            rel = path.relative_to(self.root_path)
        except ValueError:
            rel = path
        parts = list(rel.parts)
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        elif parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        return ".".join(parts)

    def _build_call_graph(self):
        for qname, func in self.functions.items():
            resolved = set()
            for call in func.calls:
                callee = self._resolve_call(call, func)
                if callee:
                    resolved.add(callee.qualified_name)
                    callee.called_by.append(qname)
            self.call_graph[qname] = resolved

    def _resolve_call(self, call_name: str, caller: ParsedFunction) -> Optional[ParsedFunction]:
        """Try to resolve a call name to a known function."""
        # Direct match
        if call_name in self.functions:
            return self.functions[call_name]

        # Try within same module
        module_name = f"{caller.module}.{call_name}"
        if module_name in self.functions:
            return self.functions[module_name]

        # Try within same class
        if caller.class_name:
            class_name = f"{caller.module}.{caller.class_name}.{call_name}"
            if class_name in self.functions:
                return self.functions[class_name]

        # Try self.method() pattern
        if "self." in call_name:
            method = call_name.replace("self.", "")
            if caller.class_name:
                full = f"{caller.module}.{caller.class_name}.{method}"
                if full in self.functions:
                    return self.functions[full]

        # Partial match (last segment) — only if unambiguous
        matches = [
            func for qname, func in self.functions.items()
            if qname.endswith(f".{call_name}")
        ]
        if len(matches) == 1:
            return matches[0]

        return None

    def _calculate_trust_asymmetry(self, caller: ParsedFunction,
                                    callee: ParsedFunction) -> float:
        """
        Score how asymmetric the trust is at this boundary.
        High score = caller trusts callee more than warranted.
        """
        score = 0.0

        # External access in callee → higher risk
        if callee.accesses_external:
            score += 0.3

        # Caller handles untrusted data
        if caller.accesses_external:
            score += 0.2

        # Callee lacks error handling
        if not callee.has_try_except and callee.accesses_external:
            score += 0.15

        # Callee lacks assertions
        if not callee.has_assertions:
            score += 0.1

        # Cross-module call (different trust domains)
        if caller.module != callee.module:
            score += 0.15

        # Public callee called with potentially untrusted data
        if callee.is_public and caller.accesses_external:
            score += 0.1

        return min(score, 1.0)

    def _describe_frontier(self, caller: ParsedFunction,
                           callee: ParsedFunction, asymmetry: float) -> str:
        parts = []
        if callee.accesses_external:
            parts.append("callee accesses external resources")
        if caller.accesses_external:
            parts.append("caller handles untrusted data")
        if not callee.has_try_except:
            parts.append("callee lacks error handling")
        if caller.module != callee.module:
            parts.append("cross-module boundary")
        detail = "; ".join(parts) if parts else "moderate trust boundary"
        return f"Trust asymmetry {asymmetry:.2f}: {detail}"

    def get_function_with_context(self, qname: str) -> dict:
        """Get a function with all context needed for LLM analysis."""
        func = self.functions.get(qname)
        if not func:
            return {}

        callers_info = []
        for caller_name in func.called_by[:10]:
            caller = self.functions.get(caller_name)
            if caller:
                callers_info.append({
                    "name": caller.qualified_name,
                    "accesses_external": caller.accesses_external,
                })

        return {
            "code": func.source_code,
            "file_path": func.file_path,
            "function_name": func.qualified_name,
            "module_name": func.module,
            "callers": callers_info,
            "documentation": func.docstring or "(none)",
            "test_info": "has assertions" if func.has_assertions else "no assertions found",
            "parameters": func.parameters,
            "decorators": func.decorators,
        }
