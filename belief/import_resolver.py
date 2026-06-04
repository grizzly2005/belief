"""Pure-AST import resolver for BELIEF v4.

This is a small, v4-adapted migration of the legacy import resolver. It
classifies import edges without importing or executing target code and uses
CodeParser's root/exclusion policy for directory scans.
"""

from __future__ import annotations

import ast
import logging
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .parser import CodeParser, ScanRoots

logger = logging.getLogger("belief.import_resolver")


class ImportKind(str, Enum):
    STDLIB = "stdlib"
    THIRD_PARTY = "third_party"
    PROJECT = "project"
    RELATIVE = "relative"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class ImportEdge:
    source_module: str
    source_file: str
    target: str
    kind: ImportKind
    line: int
    is_conditional: bool = False
    aliases: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        return {
            "source_module": self.source_module,
            "source_file": self.source_file,
            "target": self.target,
            "kind": self.kind.value,
            "line": self.line,
            "is_conditional": self.is_conditional,
            "aliases": list(self.aliases),
        }


try:
    _STDLIB_NAMES = set(sys.stdlib_module_names)  # type: ignore[attr-defined]
except AttributeError:
    _STDLIB_NAMES = {
        "argparse", "ast", "collections", "dataclasses", "datetime", "enum",
        "functools", "hashlib", "io", "json", "logging", "math", "os",
        "pathlib", "re", "subprocess", "sys", "typing", "urllib",
    }


class ImportResolver:
    """Extract and classify Python import edges for a project."""

    def __init__(
        self,
        project_root: str,
        *,
        project_packages: set[str] | None = None,
        exclude_dirs: set[str] | None = None,
        source_roots: list[str] | None = None,
        corpus_roots: list[str] | None = None,
        excluded_roots: list[str] | None = None,
        include_docs: bool = False,
    ):
        self.project_root = Path(project_root)
        self.scan_roots = ScanRoots(
            source_roots=list(source_roots or []),
            corpus_roots=list(corpus_roots or []),
            excluded_roots=list(excluded_roots or []),
            include_docs=include_docs,
        )
        self.exclude_dirs = exclude_dirs
        self.project_packages = (
            set(project_packages)
            if project_packages is not None
            else self._discover_project_packages()
        )

    def scan_directory(self) -> list[ImportEdge]:
        parser = CodeParser(
            str(self.project_root),
            exclude_dirs=self.exclude_dirs,
            scan_roots=self.scan_roots,
        )
        edges: list[ImportEdge] = []
        for py_file in parser._collect_python_files():
            edges.extend(self.scan_file(py_file))
        return sorted(
            edges,
            key=lambda edge: (
                edge.source_module,
                edge.line,
                edge.target,
                edge.kind.value,
                edge.aliases,
            ),
        )

    def scan_file(self, file_path: str | Path) -> list[ImportEdge]:
        path = Path(file_path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.debug("cannot read %s: %s", path, exc)
            return []

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            logger.debug("syntax error in %s: %s", path, exc)
            return []

        source_module = self._file_to_module(path)
        edges: list[ImportEdge] = []
        for node, is_conditional in self._walk_imports(tree):
            edges.extend(self._build_edges(node, source_module, path, is_conditional))
        return edges

    def classify(self, target: str) -> ImportKind:
        if not target:
            return ImportKind.UNRESOLVED
        if target.startswith("."):
            return ImportKind.RELATIVE
        top_level = target.split(".", 1)[0]
        if top_level in self.project_packages:
            return ImportKind.PROJECT
        if top_level in _STDLIB_NAMES:
            return ImportKind.STDLIB
        return ImportKind.THIRD_PARTY

    def _discover_project_packages(self) -> set[str]:
        packages: set[str] = set()
        try:
            for entry in self.project_root.iterdir():
                if (
                    entry.is_dir()
                    and not entry.name.startswith(".")
                    and (entry / "__init__.py").exists()
                ):
                    packages.add(entry.name)
        except OSError:
            pass
        return packages

    def _file_to_module(self, file_path: Path) -> str:
        try:
            rel = file_path.relative_to(self.project_root)
        except ValueError:
            rel = Path(file_path.name)
        parts = list(rel.parts)
        if not parts:
            return file_path.stem
        if parts[-1] == "__init__.py":
            parts = parts[:-1]
        elif parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]
        return ".".join(part for part in parts if part)

    def _walk_imports(self, tree: ast.AST):
        parents: dict[ast.AST, ast.AST] = {}
        for parent in ast.walk(tree):
            for child in ast.iter_child_nodes(parent):
                parents[child] = parent

        for node in ast.walk(tree):
            if not isinstance(node, (ast.Import, ast.ImportFrom)):
                continue
            current = node
            conditional = False
            while current in parents:
                parent = parents[current]
                if isinstance(parent, (ast.Try, ast.If)):
                    conditional = True
                    break
                current = parent
            yield node, conditional

    def _build_edges(
        self,
        node: ast.AST,
        source_module: str,
        source_file: Path,
        is_conditional: bool,
    ) -> list[ImportEdge]:
        edges: list[ImportEdge] = []
        source_file_text = str(source_file)

        if isinstance(node, ast.Import):
            for alias in node.names:
                target = alias.name
                edges.append(ImportEdge(
                    source_module=source_module,
                    source_file=source_file_text,
                    target=target,
                    kind=self.classify(target),
                    line=node.lineno,
                    is_conditional=is_conditional,
                    aliases=(alias.asname or alias.name,),
                ))
            return edges

        if isinstance(node, ast.ImportFrom):
            target = f"{'.' * node.level}{node.module or ''}"
            aliases = tuple(alias.asname or alias.name for alias in node.names)
            edges.append(ImportEdge(
                source_module=source_module,
                source_file=source_file_text,
                target=target,
                kind=self.classify(target),
                line=node.lineno,
                is_conditional=is_conditional,
                aliases=aliases,
            ))

        return edges


def scan_imports(project_root: str, **kwargs) -> list[ImportEdge]:
    return ImportResolver(project_root, **kwargs).scan_directory()

