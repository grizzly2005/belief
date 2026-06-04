"""Cross-file guarantee index for hypothesis enrichment.

The index is deliberately small. It records guarantees mined for functions and
methods, resolves a narrow class of nearby imports, and can connect file-sink
findings back to protective helper calls such as ``Storage.get_default().path``.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

from .invariant_miner import InvariantMiner
from .models import Belief, Finding


@dataclass
class GuaranteeIndex:
    """Index mined guarantees by function/method qualname."""

    by_function: dict[str, list[Belief]] = field(default_factory=dict)
    by_method: dict[str, set[str]] = field(default_factory=dict)
    sources: dict[str, str] = field(default_factory=dict)
    all_guarantees: list[Belief] = field(default_factory=list)

    def register_function_guarantees(
        self,
        function_qualname: str,
        guarantees: Iterable[Belief],
    ) -> None:
        qualname = _normalize_qualname(function_qualname)
        if not qualname:
            return
        bucket = self.by_function.setdefault(qualname, [])
        for belief in guarantees:
            if belief.id not in {existing.id for existing in bucket}:
                bucket.append(belief)
            if belief.id not in {existing.id for existing in self.all_guarantees}:
                self.all_guarantees.append(belief)
        method = qualname.rsplit(".", 1)[-1]
        self.by_method.setdefault(method, set()).add(qualname)

    def lookup_guarantees_for_call(self, call_expr_or_function_name: str) -> list[Belief]:
        """Lookup guarantees for a call expression or function qualname."""
        candidates = _candidate_qualnames(call_expr_or_function_name)
        matches: list[tuple[str, Belief]] = []
        for candidate in candidates:
            normalized = _normalize_qualname(candidate)
            if normalized in self.by_function:
                matches.extend((normalized, belief) for belief in self.by_function[normalized])
            method_matches = self.by_method.get(normalized)
            if method_matches:
                for qualname in sorted(method_matches):
                    matches.extend((qualname, belief) for belief in self.by_function.get(qualname, []))

        expanded: list[tuple[str, Belief]] = []
        seen = set()
        for qualname, belief in matches:
            key = (qualname, belief.id)
            if key in seen:
                continue
            seen.add(key)
            expanded.append((qualname, belief))

        expanded.extend(self._related_storage_path_guarantees(expanded))
        return [
            _propagated_copy(belief, via=call_expr_or_function_name, registered_function=qualname)
            for qualname, belief in _dedupe_qualname_beliefs(expanded)
        ]

    def _related_storage_path_guarantees(
        self,
        matches: list[tuple[str, Belief]],
    ) -> list[tuple[str, Belief]]:
        """Attach verify/store_contains/file regex guarantees to Storage.path."""
        related: list[tuple[str, Belief]] = []
        for qualname, belief in matches:
            if not qualname.endswith(".path"):
                continue
            class_name = qualname.rsplit(".", 1)[0]
            file_path = belief.scope.file_path
            for suffix in ("verify", "store_contains"):
                related_qualname = f"{class_name}.{suffix}"
                for candidate in self.by_function.get(related_qualname, []):
                    if _is_path_guarantee(candidate):
                        related.append((related_qualname, candidate))
            for candidate in self.all_guarantees:
                if candidate.scope.file_path == file_path and _is_filename_guarantee(candidate):
                    related.append((qualname, candidate))
        return related


def build_guarantee_index(
    parsed_files_or_project_context,
    *,
    target_root: str | Path | None = None,
    max_extra_files: int = 50,
) -> GuaranteeIndex:
    """Build an index from Paths, a directory, or a mapping of path to source."""
    target = Path(target_root).resolve() if target_root is not None else None
    sources = _source_map(parsed_files_or_project_context, target_root=target)
    sources.update(_resolve_imported_sources(sources, target, max_extra_files=max_extra_files))

    index = GuaranteeIndex()
    miner = InvariantMiner()
    for display_path, source in sorted(sources.items()):
        index.sources[display_path] = source
        beliefs = miner.extract(source, display_path)
        _register_beliefs(index, beliefs)
    index.all_guarantees = _dedupe_beliefs(index.all_guarantees)
    return index


def register_function_guarantees(
    function_qualname: str,
    guarantees: Iterable[Belief],
    index: GuaranteeIndex | None = None,
) -> GuaranteeIndex:
    target = index or GuaranteeIndex()
    target.register_function_guarantees(function_qualname, guarantees)
    return target


def lookup_guarantees_for_call(
    call_expr_or_function_name: str,
    index: GuaranteeIndex,
) -> list[Belief]:
    return index.lookup_guarantees_for_call(call_expr_or_function_name)


def attach_called_function_guarantees(
    finding: Finding,
    local_context: str | Mapping[str, str] | None,
    guarantee_index: GuaranteeIndex | None,
) -> list[Belief]:
    """Return guarantees from protective functions feeding the finding sink."""
    if guarantee_index is None:
        return []
    source = _source_for_finding(finding, local_context, guarantee_index)
    if not source:
        return []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    guarantees: list[Belief] = []
    for root in _candidate_roots(tree, finding.line):
        assignments = _assignment_calls_by_name(root)
        for sink in _file_sink_calls(root):
            for arg in sink.args[:1]:
                call_exprs = _call_exprs_feeding_arg(arg, assignments, getattr(sink, "lineno", 0))
                for call_expr in call_exprs:
                    for belief in guarantee_index.lookup_guarantees_for_call(call_expr):
                        metadata = dict(belief.source_metadata or {})
                        metadata["propagated"] = True
                        metadata["propagated_to_finding_id"] = finding.id
                        metadata["propagated_to_file"] = finding.file
                        metadata["propagated_sink_line"] = getattr(sink, "lineno", None)
                        belief.source_metadata = metadata
                        guarantees.append(belief)
    return _dedupe_beliefs(guarantees)


def _register_beliefs(index: GuaranteeIndex, beliefs: list[Belief]) -> None:
    module_beliefs: list[Belief] = []
    function_buckets: dict[str, list[Belief]] = {}
    for belief in beliefs:
        metadata = belief.source_metadata or {}
        qualname = str(metadata.get("function_qualname") or "")
        if qualname:
            function_buckets.setdefault(qualname, []).append(belief)
        else:
            module_beliefs.append(belief)
            if belief.id not in {existing.id for existing in index.all_guarantees}:
                index.all_guarantees.append(belief)

    for qualname, bucket in function_buckets.items():
        index.register_function_guarantees(qualname, bucket)
    for qualname in list(function_buckets):
        if qualname.endswith(".path"):
            index.register_function_guarantees(qualname, module_beliefs)


def _source_map(context, *, target_root: Path | None) -> dict[str, str]:
    if isinstance(context, Mapping):
        return {str(path).replace("\\", "/"): str(source) for path, source in context.items()}

    if isinstance(context, (str, Path)):
        path = Path(context)
        if path.is_dir():
            return _source_map(sorted(path.rglob("*.py")), target_root=path)
        if path.is_file():
            return {_display_path(path, target_root): path.read_text(encoding="utf-8", errors="replace")}
        return {}

    sources: dict[str, str] = {}
    for item in context or []:
        if isinstance(item, tuple) and len(item) == 2:
            sources[str(item[0]).replace("\\", "/")] = str(item[1])
            continue
        path = Path(item)
        if path.is_file():
            sources[_display_path(path, target_root)] = path.read_text(
                encoding="utf-8",
                errors="replace",
            )
    return sources


def _resolve_imported_sources(
    sources: dict[str, str],
    target_root: Path | None,
    *,
    max_extra_files: int,
) -> dict[str, str]:
    if target_root is None:
        return {}
    resolved: dict[str, str] = {}
    source_to_disk = _disk_paths_for_sources(sources, target_root)
    for display_path, source in sorted(sources.items()):
        if len(resolved) >= max_extra_files:
            break
        try:
            tree = ast.parse(source)
        except SyntaxError:
            continue
        file_path = source_to_disk.get(display_path)
        for module in _imported_modules(tree):
            imported = _find_imported_module_file(module, file_path, target_root)
            if imported is None:
                continue
            display = _display_path(imported, target_root)
            if display in sources or display in resolved:
                continue
            resolved[display] = imported.read_text(encoding="utf-8", errors="replace")
            if len(resolved) >= max_extra_files:
                break
    return resolved


def _disk_paths_for_sources(sources: dict[str, str], target_root: Path) -> dict[str, Path]:
    mapped: dict[str, Path] = {}
    for display in sources:
        direct = Path(display)
        if direct.is_absolute() and direct.exists():
            mapped[display] = direct
            continue
        candidate = target_root / display
        if candidate.exists():
            mapped[display] = candidate
    return mapped


def _imported_modules(tree: ast.Module) -> list[str]:
    modules: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            modules.append(node.module)
    return sorted(set(modules))


def _find_imported_module_file(
    module: str,
    source_file: Path | None,
    target_root: Path,
) -> Path | None:
    module_parts = [part for part in module.split(".") if part]
    if not module_parts:
        return None
    relative = Path(*module_parts).with_suffix(".py")
    search_roots: list[Path] = []
    if source_file is not None:
        search_roots.extend(source_file.parent.parents[:6])
        search_roots.insert(0, source_file.parent)
    search_roots.extend([target_root, *target_root.parents[:6]])

    seen: set[Path] = set()
    for root in search_roots:
        if root in seen:
            continue
        seen.add(root)
        candidates = [root / relative]
        if len(module_parts) == 1:
            candidates.append(root / f"{module_parts[0]}.py")
        for candidate in candidates:
            if candidate.is_file():
                return candidate
    return None


def _source_for_finding(
    finding: Finding,
    local_context: str | Mapping[str, str] | None,
    index: GuaranteeIndex,
) -> str:
    if isinstance(local_context, str):
        return local_context
    file_name = str(finding.file or "").replace("\\", "/")
    if isinstance(local_context, Mapping):
        if file_name in local_context:
            return str(local_context[file_name])
        for key, value in local_context.items():
            if str(key).replace("\\", "/").endswith(file_name):
                return str(value)
    if file_name in index.sources:
        return index.sources[file_name]
    for key, value in index.sources.items():
        if key.endswith(file_name):
            return value
    return ""


def _candidate_roots(tree: ast.Module, finding_line: int | None) -> list[ast.AST]:
    if not finding_line:
        return [tree]
    roots: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= finding_line <= end or node.lineno == finding_line:
                roots.append(node)
    return roots or [tree]


def _assignment_calls_by_name(root: ast.AST) -> dict[str, list[tuple[int, ast.Call]]]:
    assignments: dict[str, list[tuple[int, ast.Call]]] = {}
    for node in ast.walk(root):
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        value = node.value
        if not isinstance(value, ast.Call):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for target in targets:
            for name in _target_names(target):
                assignments.setdefault(name, []).append((getattr(node, "lineno", 0), value))
    for values in assignments.values():
        values.sort(key=lambda item: item[0])
    return assignments


def _file_sink_calls(root: ast.AST) -> list[ast.Call]:
    calls: list[ast.Call] = []
    for node in ast.walk(root):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name and (name == "open" or name.endswith(".open") or name.endswith(".join") or name.endswith("Path")):
            calls.append(node)
    return sorted(calls, key=lambda call: getattr(call, "lineno", 0))


def _call_exprs_feeding_arg(
    arg: ast.AST,
    assignments: dict[str, list[tuple[int, ast.Call]]],
    sink_lineno: int,
) -> list[str]:
    if isinstance(arg, ast.Call):
        return [_call_expr(arg)]
    if isinstance(arg, ast.Name):
        values = [
            call for lineno, call in assignments.get(arg.id, [])
            if not sink_lineno or lineno <= sink_lineno
        ]
        if values:
            return [_call_expr(values[-1])]
    return []


def _candidate_qualnames(call_expr_or_function_name: str) -> list[str]:
    text = str(call_expr_or_function_name or "").strip()
    tokens = _identifier_tokens(text)
    candidates: list[str] = []
    if text:
        candidates.append(text.replace("()", ""))
    if len(tokens) >= 2:
        candidates.append(f"{tokens[0]}.{tokens[-1]}")
        candidates.append(f"{tokens[-2]}.{tokens[-1]}")
    if len(tokens) >= 3 and tokens[1] in {"get_default", "get_instance", "instance"}:
        candidates.append(f"{tokens[0]}.{tokens[-1]}")
    if tokens:
        candidates.append(tokens[-1])
    return _dedupe_strings(candidates)


def _call_expr(node: ast.Call) -> str:
    try:
        return ast.unparse(node.func)
    except Exception:
        return _call_name(node) or ""


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        base = _name(node.func.value)
        return f"{base}.{node.func.attr}" if base else node.func.attr
    return None


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return None


def _target_names(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        return [name for item in node.elts for name in _target_names(item)]
    return []


def _identifier_tokens(value: str) -> list[str]:
    return [
        token for token in value.replace("()", "").replace("(", ".").replace(")", "").split(".")
        if token.isidentifier()
    ]


def _normalize_qualname(value: str) -> str:
    tokens = _identifier_tokens(value)
    return ".".join(tokens).lower()


def _propagated_copy(belief: Belief, *, via: str, registered_function: str) -> Belief:
    clone = Belief.from_dict(belief.to_dict())
    metadata = dict(clone.source_metadata or {})
    metadata["propagated"] = True
    metadata["propagated_via"] = via
    metadata["registered_function"] = registered_function
    clone.source_metadata = metadata
    return clone


def _is_path_guarantee(belief: Belief) -> bool:
    metadata = belief.source_metadata or {}
    return metadata.get("invariant_type") == "path_safety"


def _is_filename_guarantee(belief: Belief) -> bool:
    expr = belief.predicate.expression.lower()
    return expr.startswith("filename.") and (
        "matches_allowed_pattern" in expr
        or "server_generated" in expr
        or "user_controlled == false" in expr
    )


def _display_path(path: Path, target_root: Path | None) -> str:
    resolved = path.resolve()
    roots = []
    if target_root is not None:
        roots.extend([target_root.resolve(), *target_root.resolve().parents[:1]])
    for root in roots:
        try:
            return str(resolved.relative_to(root)).replace("\\", "/")
        except ValueError:
            continue
    return str(resolved).replace("\\", "/")


def _dedupe_qualname_beliefs(items: Iterable[tuple[str, Belief]]) -> list[tuple[str, Belief]]:
    seen = set()
    deduped: list[tuple[str, Belief]] = []
    for qualname, belief in items:
        key = (qualname, belief.id)
        if key in seen:
            continue
        seen.add(key)
        deduped.append((qualname, belief))
    return sorted(
        deduped,
        key=lambda item: (
            item[1].scope.file_path,
            item[1].scope.line_start or 0,
            item[0],
            item[1].predicate.expression,
        ),
    )


def _dedupe_beliefs(beliefs: Iterable[Belief]) -> list[Belief]:
    seen = set()
    deduped: list[Belief] = []
    for belief in beliefs:
        key = (
            belief.id,
            (belief.source_metadata or {}).get("propagated_via", ""),
            (belief.source_metadata or {}).get("propagated_to_finding_id", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(belief)
    return sorted(
        deduped,
        key=lambda belief: (
            belief.scope.file_path,
            belief.scope.line_start or 0,
            (belief.source_metadata or {}).get("registered_function", ""),
            belief.predicate.expression,
        ),
    )


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen = set()
    deduped: list[str] = []
    for value in values:
        normalized = _normalize_qualname(value)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


__all__ = [
    "GuaranteeIndex",
    "build_guarantee_index",
    "register_function_guarantees",
    "lookup_guarantees_for_call",
    "attach_called_function_guarantees",
]
