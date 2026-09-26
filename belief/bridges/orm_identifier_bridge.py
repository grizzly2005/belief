"""Detect unvalidated dynamic ORM identifiers used in structural operations.

This native detector is deliberately narrow.  It follows an externally
supplied field/column collection into descriptor objects and reports a later
aggregate/select transformation only when no prior fail-closed membership
check validates each descriptor against its own target model.

The implementation is stdlib-only and ``scan_source`` performs no I/O,
imports of analyzed code, subprocess execution, or network access.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any


RULE_ID = "BELIEF-ORM-STRUCTURAL-IDENTIFIER-001"

_STRUCTURAL_KEYWORDS = {
    "attribute",
    "attribute_name",
    "column",
    "column_name",
    "field",
    "field_name",
    "select_field",
    "select_str",
}
_STRUCTURAL_SINKS = {
    "aggregate",
    "apply_aggregate",
    "apply_func",
    "group_by",
    "order_by",
    "select",
    "select_from",
}
_MODEL_FIELD_COLLECTIONS = {
    "columns",
    "declared_fields",
    "field_names",
    "fields",
    "model_fields",
}
_DESCRIPTOR_NAME_ATTRIBUTES = {
    "column_name",
    "field_name",
    "name",
}


@dataclass
class _State:
    external: dict[str, int] = field(default_factory=dict)
    unsafe_collections: dict[str, int] = field(default_factory=dict)
    validated_collections: set[str] = field(default_factory=set)


def scan_source(source: str, filename: str) -> list[dict[str, Any]]:
    """Return deterministic CWE-89 findings for captured Python source."""

    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, TypeError, ValueError):
        return []
    scanner = _ModuleScanner(filename or "<unknown>")
    scanner.visit(tree)
    return sorted(
        scanner.findings,
        key=lambda item: (
            int(item["line"]),
            int(item["col"]),
            str(item["rule_id"]),
        ),
    )


class _ModuleScanner(ast.NodeVisitor):
    def __init__(self, filename: str) -> None:
        self.filename = filename
        self.findings: list[dict[str, Any]] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        _FunctionScanner(self.filename, self.findings).scan(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        _FunctionScanner(self.filename, self.findings).scan(node)
        self.generic_visit(node)


class _FunctionScanner:
    def __init__(self, filename: str, findings: list[dict[str, Any]]) -> None:
        self.filename = filename
        self.findings = findings

    def scan(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        state = _State()
        parameters = [
            *node.args.posonlyargs,
            *node.args.args,
            *node.args.kwonlyargs,
        ]
        if node.args.vararg is not None:
            parameters.append(node.args.vararg)
        if node.args.kwarg is not None:
            parameters.append(node.args.kwarg)
        state.external = {
            parameter.arg: parameter.lineno
            for parameter in parameters
            if parameter.arg not in {"self", "cls"}
        }
        self._process_statements(node.body, state)

    def _process_statements(self, statements: list[ast.stmt], state: _State) -> None:
        for statement in statements:
            self._process_statement(statement, state)

    def _process_statement(self, statement: ast.stmt, state: _State) -> None:
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            value = statement.value
            if value is None:
                return
            self._record_sinks(value, state)
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            source_line = _descriptor_collection_source(value, state.external)
            external_line = _external_source_line(value, state.external)
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                if external_line is None:
                    state.external.pop(target.id, None)
                else:
                    state.external[target.id] = external_line
                if source_line is None:
                    state.unsafe_collections.pop(target.id, None)
                    state.validated_collections.discard(target.id)
                else:
                    state.unsafe_collections[target.id] = source_line
                    state.validated_collections.discard(target.id)
            return

        if isinstance(statement, ast.Expr):
            self._record_sinks(statement.value, state)
            return

        if isinstance(statement, ast.Return):
            if statement.value is not None:
                self._record_sinks(statement.value, state)
            return

        if isinstance(statement, ast.If):
            self._record_sinks(statement.test, state)
            validated = _fail_closed_membership_collection(statement)
            if validated in state.unsafe_collections:
                self._process_statements(statement.body, _clone_state(state))
                state.validated_collections.add(validated)
                return
            # A conditional branch cannot establish a guarantee for code after
            # the branch.  Still inspect branch-local sinks with cloned state.
            body_state = _clone_state(state)
            else_state = _clone_state(state)
            self._process_statements(statement.body, body_state)
            self._process_statements(statement.orelse, else_state)
            return

        if isinstance(statement, (ast.For, ast.AsyncFor, ast.While)):
            body_state = _clone_state(state)
            self._process_statements(statement.body, body_state)
            self._process_statements(statement.orelse, _clone_state(state))
            return

        if isinstance(statement, (ast.With, ast.AsyncWith)):
            self._process_statements(statement.body, state)
            return

        if isinstance(statement, ast.Try):
            self._process_statements(statement.body, _clone_state(state))
            self._process_statements(statement.orelse, _clone_state(state))
            for handler in statement.handlers:
                self._process_statements(handler.body, _clone_state(state))
            self._process_statements(statement.finalbody, _clone_state(state))
            return

        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return

        for child in ast.iter_child_nodes(statement):
            if isinstance(child, ast.expr):
                self._record_sinks(child, state)

    def _record_sinks(self, expression: ast.AST, state: _State) -> None:
        for comprehension in (
            node
            for node in ast.walk(expression)
            if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp))
        ):
            for generator in comprehension.generators:
                if not isinstance(generator.iter, ast.Name):
                    continue
                collection = generator.iter.id
                if (
                    collection not in state.unsafe_collections
                    or collection in state.validated_collections
                ):
                    continue
                sink = _first_structural_sink(comprehension.elt)
                if sink is not None:
                    self._append_finding(
                        sink,
                        collection,
                        state.unsafe_collections[collection],
                    )

    def _append_finding(
        self,
        sink: ast.Call,
        collection: str,
        source_line: int,
    ) -> None:
        sink_name = _call_name(sink) or "ORM structural operation"
        description = (
            "Externally supplied field or column identifiers reach an ORM "
            "structural operation without membership validation against each "
            "descriptor's target model."
        )
        self.findings.append({
            "rule_id": RULE_ID,
            "cwe": "CWE-89",
            "severity": "high",
            "confidence": 0.9,
            "file": self.filename,
            "line": sink.lineno,
            "col": sink.col_offset,
            "title": "Unvalidated dynamic ORM structural identifier",
            "description": description,
            "message": description,
            "evidence": (
                f"descriptor collection {collection} from line {source_line} "
                f"reaches {sink_name}"
            ),
            "source_line": source_line,
            "sink": sink_name,
            "variables": [collection],
        })


def _descriptor_collection_source(
    expression: ast.AST,
    external: dict[str, int],
) -> int | None:
    if not isinstance(expression, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return None
    for generator in expression.generators:
        if not isinstance(generator.iter, ast.Name):
            continue
        source = generator.iter.id
        if source not in external:
            continue
        target_names = _target_names(generator.target)
        if not target_names:
            continue
        for call in (node for node in ast.walk(expression.elt) if isinstance(node, ast.Call)):
            for keyword in call.keywords:
                if keyword.arg is None or _snake_case(keyword.arg) not in _STRUCTURAL_KEYWORDS:
                    continue
                if _reads_any(keyword.value, target_names):
                    return external[source]
    return None


def _external_source_line(
    expression: ast.AST,
    external: dict[str, int],
) -> int | None:
    lines = [
        external[node.id]
        for node in ast.walk(expression)
        if isinstance(node, ast.Name) and node.id in external
    ]
    return min(lines, default=None)


def _fail_closed_membership_collection(statement: ast.If) -> str | None:
    if statement.orelse or not statement.body or not isinstance(
        statement.body[-1],
        (ast.Raise, ast.Return, ast.Break, ast.Continue),
    ):
        return None
    candidates = [statement.test]
    if isinstance(statement.test, ast.Call) and _call_name(statement.test) == "any":
        candidates.extend(statement.test.args)
    for candidate in candidates:
        for generator in (
            node
            for node in ast.walk(candidate)
            if isinstance(node, (ast.GeneratorExp, ast.ListComp, ast.SetComp))
        ):
            if not isinstance(generator.generators[0].iter, ast.Name):
                continue
            collection = generator.generators[0].iter.id
            item_names = _target_names(generator.generators[0].target)
            if not item_names:
                continue
            for comparison in (
                node for node in ast.walk(generator.elt) if isinstance(node, ast.Compare)
            ):
                if len(comparison.ops) != 1 or not isinstance(comparison.ops[0], ast.NotIn):
                    continue
                if len(comparison.comparators) != 1:
                    continue
                if _same_descriptor_membership(
                    comparison.left,
                    comparison.comparators[0],
                    item_names,
                ):
                    return collection
    return None


def _same_descriptor_membership(
    left: ast.AST,
    right: ast.AST,
    item_names: set[str],
) -> bool:
    left_chain = _attribute_chain(left)
    right_chain = _attribute_chain(right)
    return bool(
        len(left_chain) >= 2
        and left_chain[0] in item_names
        and left_chain[-1] in _DESCRIPTOR_NAME_ATTRIBUTES
        and len(right_chain) >= 3
        and right_chain[0] == left_chain[0]
        and right_chain[-1] in _MODEL_FIELD_COLLECTIONS
    )


def _first_structural_sink(expression: ast.AST) -> ast.Call | None:
    calls = sorted(
        (node for node in ast.walk(expression) if isinstance(node, ast.Call)),
        key=lambda node: (node.lineno, node.col_offset),
    )
    for call in calls:
        normalized = _snake_case(_call_name(call))
        if normalized in _STRUCTURAL_SINKS:
            return call
    return None


def _clone_state(state: _State) -> _State:
    return _State(
        external=dict(state.external),
        unsafe_collections=dict(state.unsafe_collections),
        validated_collections=set(state.validated_collections),
    )


def _target_names(target: ast.AST) -> set[str]:
    return {
        node.id
        for node in ast.walk(target)
        if isinstance(node, ast.Name)
    }


def _reads_any(expression: ast.AST, names: set[str]) -> bool:
    return any(
        isinstance(node, ast.Name) and node.id in names
        for node in ast.walk(expression)
    )


def _attribute_chain(expression: ast.AST) -> list[str]:
    parts: list[str] = []
    current = expression
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name):
        parts.append(current.id)
    return list(reversed(parts))


def _call_name(call: ast.Call) -> str:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return ""


def _snake_case(value: str) -> str:
    with_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-zA-Z0-9]+", "_", with_boundaries).strip("_").lower()


__all__ = ["RULE_ID", "scan_source"]
