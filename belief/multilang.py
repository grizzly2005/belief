"""
BELIEF — Multi-language parser using tree-sitter.

Extends the Python-only AST parser with support for JavaScript, TypeScript,
Go, Java, and Rust via tree-sitter grammars. Falls back gracefully when
a grammar is unavailable.

Each language has its own query patterns for extracting functions, calls,
and external interaction markers.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .models import Frontier, TrustProfile
from .parser import ParsedFunction, EXTERNAL_MARKERS

logger = logging.getLogger("belief.multilang")

# ─── Tree-sitter language registry ───

_GRAMMARS: dict[str, object] = {}  # lang_name → Language object
_TS_AVAILABLE = False

try:
    from tree_sitter import Language, Parser as TSParser
    _TS_AVAILABLE = True
except ImportError:
    logger.info("tree-sitter not installed. Multi-language support disabled.")

# Language module loaders — each may fail independently
_LANG_LOADERS = {
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "go": ("tree_sitter_go", "language"),
    "java": ("tree_sitter_java", "language"),
    "rust": ("tree_sitter_rust", "language"),
    "c": ("tree_sitter_c", "language"),
}

# File extension → language mapping
_EXT_MAP = {
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript",
    ".go": "go",
    ".java": "java",
    ".rs": "rust",
    ".c": "c", ".h": "c",
}

# Tree-sitter node types for function definitions per language
_FUNC_NODE_TYPES = {
    "javascript": {"function_declaration", "method_definition", "arrow_function",
                    "function_expression"},
    "typescript": {"function_declaration", "method_definition", "arrow_function",
                    "function_expression"},
    "go": {"function_declaration", "method_declaration"},
    "java": {"method_declaration", "constructor_declaration"},
    "rust": {"function_item"},
    "c": {"function_definition"},
}

# Tree-sitter node types for function calls
_CALL_NODE_TYPES = {
    "javascript": {"call_expression"},
    "typescript": {"call_expression"},
    "go": {"call_expression"},
    "java": {"method_invocation"},
    "rust": {"call_expression"},
    "c": {"call_expression"},
}


def _init_grammars():
    """Initialize available grammars. Called once on first use."""
    if not _TS_AVAILABLE or _GRAMMARS:
        return

    for lang_name, (module_name, func_name) in _LANG_LOADERS.items():
        try:
            mod = __import__(module_name)
            lang_fn = getattr(mod, func_name)
            lang = Language(lang_fn())
            # Verify it works with a minimal parse
            p = TSParser(lang)
            p.parse(b"x")
            _GRAMMARS[lang_name] = lang
            logger.debug(f"Loaded grammar: {lang_name}")
        except Exception as e:
            logger.debug(f"Grammar {lang_name} unavailable: {e}")


def get_supported_languages() -> list[str]:
    """Return list of available tree-sitter languages."""
    _init_grammars()
    return list(_GRAMMARS.keys())


def get_language_for_file(file_path: str) -> str | None:
    """Determine language from file extension."""
    ext = Path(file_path).suffix.lower()
    return _EXT_MAP.get(ext)


# ─── Tree-sitter function extractor ───

def _get_node_text(node, source_bytes: bytes) -> str:
    """Extract text from a tree-sitter node."""
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _find_function_name(node, source_bytes: bytes, lang: str) -> str:
    """Extract function name from a function definition node."""
    # Most languages have a 'name' or 'identifier' child
    for child in node.children:
        if child.type in ("identifier", "property_identifier", "field_identifier"):
            return _get_node_text(child, source_bytes)
        if child.type == "name":
            return _get_node_text(child, source_bytes)
    # Go methods: func (receiver) name(...)
    if lang == "go":
        for child in node.children:
            if child.type == "identifier":
                return _get_node_text(child, source_bytes)
    return "<anonymous>"


def _find_class_name(node) -> str | None:
    """Walk up the tree to find enclosing class/struct name."""
    current = node.parent
    while current:
        if current.type in ("class_declaration", "class_definition",
                            "struct_item", "impl_item", "interface_declaration"):
            for child in current.children:
                if child.type in ("identifier", "type_identifier", "name"):
                    return child.text.decode("utf-8", errors="replace") if hasattr(child, 'text') else None
        current = current.parent
    return None


def _extract_calls(node, source_bytes: bytes, lang: str) -> list[str]:
    """Extract all function call names from a subtree."""
    calls = []
    call_types = _CALL_NODE_TYPES.get(lang, set())

    def walk(n):
        if n.type in call_types:
            # Get the function being called
            if n.children:
                func_node = n.children[0]
                call_name = _get_node_text(func_node, source_bytes)
                if call_name:
                    calls.append(call_name)
        for child in n.children:
            walk(child)

    walk(node)
    return calls


def _has_error_handling(node, lang: str) -> bool:
    """Check if the function body contains error handling."""
    error_types = {
        "javascript": {"try_statement", "catch_clause"},
        "typescript": {"try_statement", "catch_clause"},
        "go": {"if_statement"},  # Go uses if err != nil
        "java": {"try_statement", "catch_clause"},
        "rust": {"match_expression"},  # Rust uses Result/Option match
        "c": {"if_statement"},  # C uses if (ret < 0) style
    }
    targets = error_types.get(lang, set())

    def walk(n):
        if n.type in targets:
            # For Go, check if it's an error check
            if lang == "go" and n.type == "if_statement":
                if "err" not in str(n):
                    return False
            return True
        for child in n.children:
            if walk(child):
                return True
        return False

    return walk(node)


def _accesses_external(calls: list[str]) -> bool:
    """Check if any call involves external resources."""
    return any(
        any(marker in call.lower() for marker in EXTERNAL_MARKERS)
        for call in calls
    )


# ─── Multi-language parser ───

class MultiLangParser:
    """
    Parse non-Python codebases using tree-sitter.

    Usage:
        parser = MultiLangParser("/path/to/project")
        functions = parser.parse()
        frontiers = parser.detect_frontiers()

    Supports: JavaScript, TypeScript, Go, Java, Rust.
    Falls back gracefully when grammars are unavailable.
    """

    def __init__(self, root_path: str, languages: list[str] | None = None,
                 exclude_dirs: set[str] | None = None):
        _init_grammars()
        self.root_path = Path(root_path)
        self.languages = languages or list(_GRAMMARS.keys())
        self.exclude_dirs = exclude_dirs or {
            "node_modules", ".git", "vendor", "target", "build", "dist",
            "__pycache__", ".venv", "bin", "obj",
        }
        self.functions: dict[str, ParsedFunction] = {}
        self.call_graph: dict[str, set[str]] = {}

    @property
    def available_languages(self) -> list[str]:
        return [lang for lang in self.languages if lang in _GRAMMARS]

    def parse(self) -> list[ParsedFunction]:
        """Parse all supported source files in the project."""
        if not _TS_AVAILABLE:
            logger.warning("tree-sitter not available. No multi-lang parsing.")
            return []

        files = self._collect_files()
        logger.info(f"Multi-lang: found {len(files)} files to parse")

        for file_path, lang in files:
            try:
                self._parse_file(file_path, lang)
            except Exception as e:
                logger.debug(f"Failed to parse {file_path}: {e}")
                continue

        self._build_call_graph()
        logger.info(f"Multi-lang: extracted {len(self.functions)} functions")
        return list(self.functions.values())

    def detect_frontiers(self, trust_threshold: float = 0.3) -> list[Frontier]:
        """Detect trust boundary frontiers between functions."""
        frontiers = []
        seen = set()

        for qname, func in self.functions.items():
            for call_name in func.calls:
                callee = self._resolve_call(call_name)
                if callee is None:
                    continue

                key = f"{qname}->{callee.qualified_name}"
                if key in seen:
                    continue
                seen.add(key)

                asymmetry = self._calculate_trust_asymmetry(func, callee)
                if asymmetry < trust_threshold:
                    continue

                profile = TrustProfile(
                    is_read_only=not callee.accesses_external,
                    validates_input=callee.has_assertions,
                    crosses_network=any(
                        kw in " ".join(callee.calls).lower()
                        for kw in ["request", "http", "fetch", "url"]
                    ),
                    handles_untrusted=func.accesses_external,
                    error_handling=(
                        "partial" if callee.has_try_except else "none"
                    ),
                )

                frontiers.append(Frontier(
                    caller_scope=func.to_scope(),
                    callee_scope=callee.to_scope(),
                    trust_asymmetry=asymmetry,
                    trust_profile=profile,
                ))

        return sorted(frontiers, key=lambda f: f.trust_asymmetry, reverse=True)

    def get_function_with_context(self, qname: str) -> dict:
        """Get function code + context for LLM analysis."""
        func = self.functions.get(qname)
        if not func:
            return {}
        return {
            "code": func.source_code,
            "file_path": func.file_path,
            "function_name": func.qualified_name,
            "module_name": func.module,
            "callers": [
                {"name": c, "accesses_external": False}
                for c in func.called_by[:10]
            ],
            "documentation": func.docstring or "(none)",
            "test_info": "has assertions" if func.has_assertions else "no assertions found",
        }

    # ── Internal ──

    def _collect_files(self) -> list[tuple[Path, str]]:
        """Collect all parseable source files with their language."""
        files = []
        for path in self.root_path.rglob("*"):
            if any(ex in path.parts for ex in self.exclude_dirs):
                continue
            if not path.is_file():
                continue
            lang = get_language_for_file(str(path))
            if lang and lang in _GRAMMARS and lang in self.languages:
                files.append((path, lang))
        return sorted(files)

    def _parse_file(self, file_path: Path, lang: str):
        """Parse a single file and extract functions."""
        grammar = _GRAMMARS.get(lang)
        if not grammar:
            return

        source = file_path.read_bytes()
        parser = TSParser(grammar)
        tree = parser.parse(source)
        module = self._path_to_module(file_path)

        func_types = _FUNC_NODE_TYPES.get(lang, set())

        def walk(node):
            if node.type in func_types:
                self._extract_function(node, source, file_path, module, lang)
            for child in node.children:
                walk(child)

        walk(tree.root_node)

    def _extract_function(self, node, source_bytes: bytes, file_path: Path,
                          module: str, lang: str):
        """Extract a function from a tree-sitter node."""
        name = _find_function_name(node, source_bytes, lang)
        class_name = _find_class_name(node)
        code = _get_node_text(node, source_bytes)
        calls = _extract_calls(node, source_bytes, lang)

        pf = ParsedFunction(
            name=name,
            class_name=class_name,
            module=module,
            file_path=str(file_path),
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            source_code=code,
            calls=calls,
            has_try_except=_has_error_handling(node, lang),
            accesses_external=_accesses_external(calls),
            is_public=not name.startswith("_"),
        )
        self.functions[pf.qualified_name] = pf

    def _path_to_module(self, path: Path) -> str:
        try:
            rel = path.relative_to(self.root_path)
        except ValueError:
            rel = path
        parts = list(rel.parts)
        if parts[-1].rsplit(".", 1)[0] == "index":
            parts = parts[:-1]
        else:
            parts[-1] = parts[-1].rsplit(".", 1)[0]
        return ".".join(parts)

    def _build_call_graph(self):
        for qname, func in self.functions.items():
            resolved = set()
            for call in func.calls:
                callee = self._resolve_call(call)
                if callee and callee.qualified_name != qname:
                    resolved.add(callee.qualified_name)
                    callee.called_by.append(qname)
            self.call_graph[qname] = resolved

    def _resolve_call(self, call_name: str) -> ParsedFunction | None:
        if call_name in self.functions:
            return self.functions[call_name]
        # Partial match — unambiguous only
        matches = [
            f for qn, f in self.functions.items()
            if qn.endswith(f".{call_name}") or qn.endswith(f":{call_name}")
        ]
        return matches[0] if len(matches) == 1 else None

    def _calculate_trust_asymmetry(self, caller: ParsedFunction,
                                    callee: ParsedFunction) -> float:
        score = 0.0
        if callee.accesses_external:
            score += 0.3
        if caller.accesses_external:
            score += 0.2
        if not callee.has_try_except and callee.accesses_external:
            score += 0.15
        if caller.module != callee.module:
            score += 0.15
        if callee.is_public and caller.accesses_external:
            score += 0.1
        return min(score, 1.0)
