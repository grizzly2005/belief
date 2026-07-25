"""Shared AST helpers for semantic contract families."""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable

from ..models import (
    FlowState,
    FunctionEffect,
    GuardEffect,
    ResourceIdentity,
    RootCauseIdentity,
    SecurityTransition,
    SummaryKind,
)
from ..observations import SemanticConcern


@dataclass(frozen=True)
class FunctionContractContext:
    file: str
    qualified_name: str
    class_name: str
    parameters: tuple[str, ...]
    node: ast.FunctionDef | ast.AsyncFunctionDef
    source: str
    summary_effects: tuple[FunctionEffect, ...]


@dataclass(frozen=True)
class ClassContractContext:
    file: str
    qualified_name: str
    node: ast.ClassDef
    source: str


@dataclass(frozen=True)
class ContractObservations:
    concerns: tuple[SemanticConcern, ...] = ()
    guards: tuple[GuardEffect, ...] = ()
    transitions: tuple[SecurityTransition, ...] = ()

    @classmethod
    def merge(
        cls,
        values: Iterable["ContractObservations"],
    ) -> "ContractObservations":
        concerns = {}
        guards = {}
        transitions = {}
        for value in values:
            for concern in value.concerns:
                concerns[concern.deterministic_digest] = concern
            for guard in value.guards:
                guards[guard.guard_id] = guard
            for transition in value.transitions:
                transitions[transition.transition_id] = transition
        return cls(
            concerns=tuple(
                sorted(
                    concerns.values(),
                    key=lambda item: item.sort_key,
                )
            ),
            guards=tuple(
                sorted(
                    guards.values(),
                    key=lambda item: (
                        item.guard_id,
                        item.resource.canonical,
                        item.line or 0,
                    ),
                )
            ),
            transitions=tuple(
                sorted(
                    transitions.values(),
                    key=lambda item: (
                        item.transition_id,
                        item.resource.canonical,
                        item.line or 0,
                    ),
                )
            ),
        )


def make_concern(
    context: FunctionContractContext | ClassContractContext,
    *,
    contract_id: str,
    category: str,
    cwe: str,
    title: str,
    description: str,
    line: int,
    function: str,
    class_name: str,
    resource: ResourceIdentity,
    source: str,
    sink: str,
    missing_states: tuple[str, ...],
    evidence: str,
    confidence: float,
    security_property: str,
) -> SemanticConcern:
    root_cause = RootCauseIdentity(
        category=category,
        source_kind=source,
        sink_kind=sink,
        resource=resource,
        security_property=security_property,
        context=function,
    )
    return SemanticConcern(
        contract_id=contract_id,
        category=category,
        cwe=cwe,
        title=title,
        description=description,
        file=context.file,
        line=line,
        end_line=line,
        function=function,
        class_name=class_name,
        resource=resource,
        source=source,
        sink=sink,
        missing_states=missing_states,
        evidence=evidence,
        confidence=confidence,
        root_cause=root_cause,
    )


def make_guard_transition(
    *,
    context: FunctionContractContext,
    resource: ResourceIdentity,
    property_name: str,
    safe_value: str,
    effect: str,
    line: int,
    condition: str,
    abortive: bool,
    branch: str = "false",
    result_used: bool = True,
    dominates_sink: bool | None = None,
) -> tuple[GuardEffect, SecurityTransition]:
    material = {
        "file": context.file,
        "function": context.qualified_name,
        "line": line,
        "resource": resource.canonical,
        "property": property_name,
        "value": safe_value,
        "condition": condition,
    }
    identity = semantic_digest(material)
    guard = GuardEffect(
        guard_id=f"guard:{identity}",
        effect=effect,
        resource=resource,
        state_property=property_name,
        state_value=safe_value,
        branch=branch,
        abortive=abortive,
        dominates_sink=(abortive if dominates_sink is None else dominates_sink),
        result_used=result_used,
        line=line,
    )
    before = FlowState(
        property=property_name,
        value="unknown",
        resource=resource,
        context=context.qualified_name,
        provenance=(condition,),
    )
    after = FlowState(
        property=property_name,
        value=safe_value,
        resource=resource,
        context=context.qualified_name,
        provenance=(condition,),
    )
    transition = SecurityTransition(
        transition_id=f"transition:{identity}",
        kind=effect,
        resource=resource,
        before=before,
        after=after,
        line=line,
        control_path=(condition,),
        result_used=result_used,
    )
    return guard, transition


def walk_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> Iterable[ast.AST]:
    stack = list(reversed(node.body))
    while stack:
        current = stack.pop()
        if isinstance(
            current,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda),
        ):
            continue
        yield current
        stack.extend(reversed(list(ast.iter_child_nodes(current))))


def call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def expression(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return type(node).__name__


def resource_for(
    node: ast.AST,
    parameters: tuple[str, ...],
    *,
    fallback: str = "value",
) -> ResourceIdentity:
    if isinstance(node, ast.Name):
        kind = "parameter" if node.id in parameters else "local"
        return ResourceIdentity(kind=kind, symbol=node.id)
    if isinstance(node, ast.Attribute):
        path = []
        current: ast.AST = node
        while isinstance(current, ast.Attribute):
            path.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            return ResourceIdentity(
                kind=("parameter" if current.id in parameters else "receiver"),
                symbol=current.id,
                path=tuple(reversed(path)),
            )
    return ResourceIdentity(
        kind="expression",
        symbol=expression(node) or fallback,
    )


def referenced_names(node: ast.AST) -> set[str]:
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name)}


def string_constants(node: ast.AST) -> set[str]:
    return {
        item.value
        for item in ast.walk(node)
        if isinstance(item, ast.Constant) and isinstance(item.value, str)
    }


def aborts(statements: list[ast.stmt]) -> bool:
    return any(
        isinstance(item, (ast.Raise, ast.Return, ast.Break, ast.Continue))
        for statement in statements
        for item in ast.walk(statement)
    )


def enclosing_nodes(
    root: ast.AST,
) -> dict[ast.AST, ast.AST]:
    parents = {}
    for parent in ast.walk(root):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    return parents


def has_ancestor(
    node: ast.AST,
    parents: dict[ast.AST, ast.AST],
    predicate,
) -> bool:
    current = node
    while current in parents:
        current = parents[current]
        if predicate(current):
            return True
    return False


def statement_before(
    node: ast.AST,
    line: int,
) -> bool:
    selected = getattr(node, "lineno", None)
    return isinstance(selected, int) and selected < line


def is_top_level_statement(
    context: FunctionContractContext,
    node: ast.AST,
) -> bool:
    """Return whether *node* is a direct function-body statement."""

    return node in context.node.body


def lineage_names(
    context: FunctionContractContext,
    node: ast.AST,
    *,
    before_line: int,
) -> frozenset[str]:
    """Resolve bounded, unconditional local aliases for one expression."""

    names = set(referenced_names(node))
    assignments: list[tuple[int, str, set[str]]] = []
    for statement in context.node.body:
        if (
            not isinstance(statement, (ast.Assign, ast.AnnAssign))
            or getattr(statement, "lineno", before_line) >= before_line
        ):
            continue
        target, value = _single_name_assignment(statement)
        if target and value is not None:
            assignments.append(
                (
                    statement.lineno,
                    target,
                    referenced_names(value),
                )
            )
    for _, target, sources in sorted(assignments, reverse=True):
        if target in names:
            names.update(sources)
    return frozenset(names)


def has_effective_abortive_summary(
    context: FunctionContractContext,
    resource_name: str,
    *,
    before_line: int,
) -> bool:
    """Recognize a same-parameter helper that aborts on invalid input."""

    try:
        parameter_index = context.parameters.index(resource_name)
    except ValueError:
        return False
    return any(
        effect.kind == SummaryKind.ABORTIVE_GUARD
        and effect.parameter_index == parameter_index
        and effect.line is not None
        and effect.line < before_line
        and not effect.direct
        and _line_is_top_level_call(context, effect.line)
        for effect in context.summary_effects
    )


def has_effective_sanitizer_reassignment(
    context: FunctionContractContext,
    resource_name: str,
    *,
    before_line: int,
) -> bool:
    """Require a sanitizer result to replace the same value before use."""

    try:
        parameter_index = context.parameters.index(resource_name)
    except ValueError:
        return False
    sanitizer_lines = {
        effect.line
        for effect in context.summary_effects
        if effect.kind == SummaryKind.SANITIZER
        and effect.parameter_index == parameter_index
        and effect.result_used
        and effect.line is not None
        and effect.line < before_line
    }
    for statement in context.node.body:
        if (
            not isinstance(statement, (ast.Assign, ast.AnnAssign))
            or statement.lineno not in sanitizer_lines
        ):
            continue
        target, value = _single_name_assignment(statement)
        if (
            target == resource_name
            and isinstance(value, ast.Call)
            and resource_name in referenced_names(value)
        ):
            return True
    return False


def _line_is_top_level_call(
    context: FunctionContractContext,
    line: int,
) -> bool:
    for statement in context.node.body:
        if getattr(statement, "lineno", None) != line:
            continue
        return any(
            isinstance(item, ast.Call) and getattr(item, "lineno", None) == line
            for item in ast.walk(statement)
        )
    return False


def _single_name_assignment(
    node: ast.Assign | ast.AnnAssign,
) -> tuple[str, ast.AST | None]:
    if isinstance(node, ast.Assign):
        if len(node.targets) != 1 or not isinstance(
            node.targets[0],
            ast.Name,
        ):
            return "", node.value
        return node.targets[0].id, node.value
    if not isinstance(node.target, ast.Name):
        return "", node.value
    return node.target.id, node.value


def semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "ClassContractContext",
    "ContractObservations",
    "FunctionContractContext",
    "aborts",
    "call_name",
    "enclosing_nodes",
    "expression",
    "has_ancestor",
    "has_effective_abortive_summary",
    "has_effective_sanitizer_reassignment",
    "is_top_level_statement",
    "lineage_names",
    "make_concern",
    "make_guard_transition",
    "referenced_names",
    "resource_for",
    "semantic_digest",
    "statement_before",
    "string_constants",
    "walk_function",
]
