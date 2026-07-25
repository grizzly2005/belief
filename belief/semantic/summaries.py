"""Bounded, deterministic Python function-summary inference."""

from __future__ import annotations

import ast
import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import (
    AnalysisGap,
    FunctionEffect,
    FunctionSummary,
    ResourceIdentity,
    SummaryKind,
)


FUNCTION_SUMMARY_ANALYSIS_SCHEMA_VERSION = (
    "belief.function_summary_analysis.v1"
)


@dataclass(frozen=True)
class FunctionSummaryLimits:
    """Explicit resource bounds for one summary analysis."""

    max_files: int = 100
    max_functions: int = 2_000
    max_call_edges: int = 10_000
    max_scc_iterations: int = 8
    max_summaries_per_function: int = 32
    max_call_depth: int = 8

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_functions": self.max_functions,
            "max_call_edges": self.max_call_edges,
            "max_scc_iterations": self.max_scc_iterations,
            "max_summaries_per_function": (
                self.max_summaries_per_function
            ),
            "max_call_depth": self.max_call_depth,
        }


@dataclass(frozen=True)
class FunctionSummaryAnalysis:
    """Complete summary output, including all explicit analysis gaps."""

    target: str
    summaries: tuple[FunctionSummary, ...]
    gaps: tuple[AnalysisGap, ...]
    limits: FunctionSummaryLimits
    metrics: tuple[tuple[str, int], ...]
    schema_version: str = field(
        default=FUNCTION_SUMMARY_ANALYSIS_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("summary analysis target must not be empty")
        if tuple(
            sorted(
                self.summaries,
                key=lambda item: (item.file, item.qualified_name),
            )
        ) != self.summaries:
            raise ValueError(
                "function summaries must be deterministically sorted"
            )
        if tuple(
            sorted(
                set(self.gaps),
                key=lambda gap: gap.sort_key,
            )
        ) != self.gaps:
            raise ValueError("analysis gaps must be unique and sorted")
        if tuple(sorted(set(self.metrics))) != self.metrics:
            raise ValueError("analysis metrics must be unique and sorted")
        if any(value < 0 for _, value in self.metrics):
            raise ValueError("analysis metrics must be non-negative")

    @property
    def deterministic_digest(self) -> str:
        return _semantic_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "summaries": [summary.to_dict() for summary in self.summaries],
            "gaps": [gap.to_dict() for gap in self.gaps],
            "limits": self.limits.to_dict(),
            "metrics": dict(self.metrics),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._semantic_dict()
        payload["deterministic_digest"] = self.deterministic_digest
        return payload


@dataclass(frozen=True)
class _CallSite:
    raw_name: str
    line: int
    argument_parameters: tuple[int | None, ...]


@dataclass(frozen=True)
class _FunctionRecord:
    file: str
    qualified_name: str
    class_name: str
    parameters: tuple[str, ...]
    node: ast.FunctionDef | ast.AsyncFunctionDef
    direct_effects: tuple[FunctionEffect, ...]
    call_sites: tuple[_CallSite, ...]


class _FunctionCollector(ast.NodeVisitor):
    def __init__(self, file: str) -> None:
        self.file = file
        self.scope: list[str] = []
        self.class_scope: list[str] = []
        self.records: list[
            tuple[
                str,
                str,
                tuple[str, ...],
                ast.FunctionDef | ast.AsyncFunctionDef,
            ]
        ] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.scope.append(node.name)
        self.class_scope.append(node.name)
        self.generic_visit(node)
        self.class_scope.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._record_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._record_function(node)

    def _record_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualified_name = ".".join([*self.scope, node.name])
        parameters = _parameters(node)
        class_name = ".".join(self.class_scope)
        self.records.append(
            (
                qualified_name,
                class_name,
                parameters,
                node,
            )
        )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()


def analyze_function_summaries(
    target: str | Path,
    limits: FunctionSummaryLimits | None = None,
) -> FunctionSummaryAnalysis:
    """Infer summaries using a bounded call graph and SCC fixed point."""

    configured = limits or FunctionSummaryLimits()
    target_path = Path(target).resolve()
    files = _python_files(target_path)
    gaps: set[AnalysisGap] = set()
    if len(files) > configured.max_files:
        gaps.add(
            AnalysisGap(
                code="function_summary_file_limit_reached",
                stage="function_collection",
                reason=(
                    "Python files beyond the configured limit were not "
                    "summarized"
                ),
                limit_name="max_files",
                limit_value=configured.max_files,
                observed_value=len(files),
            )
        )
    selected_files = files[: configured.max_files]
    raw_records: list[
        tuple[
            str,
            str,
            str,
            tuple[str, ...],
            ast.FunctionDef | ast.AsyncFunctionDef,
        ]
    ] = []
    total_function_count = 0
    parsed_file_count = 0
    for path in selected_files:
        relative = _relative_path(path, target_path)
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError, UnicodeError) as exc:
            line = getattr(exc, "lineno", None)
            gaps.add(
                AnalysisGap(
                    code="function_summary_parse_failure",
                    stage="function_collection",
                    reason=f"{type(exc).__name__}: {exc}",
                    file=relative,
                    limit_name="",
                    line=line,
                )
            )
            continue
        parsed_file_count += 1
        collector = _FunctionCollector(relative)
        collector.visit(tree)
        total_function_count += len(collector.records)
        for qualified_name, class_name, parameters, node in collector.records:
            if len(raw_records) >= configured.max_functions:
                continue
            raw_records.append(
                (
                    relative,
                    qualified_name,
                    class_name,
                    parameters,
                    node,
                )
            )
    if total_function_count > configured.max_functions:
        gaps.add(
            AnalysisGap(
                code="function_summary_function_limit_reached",
                stage="function_collection",
                reason=(
                    "Functions beyond the configured limit were not "
                    "summarized"
                ),
                limit_name="max_functions",
                limit_value=configured.max_functions,
                observed_value=total_function_count,
            )
        )

    records: dict[str, _FunctionRecord] = {}
    duplicate_names: Counter[str] = Counter(
        qualified_name
        for _, qualified_name, _, _, _ in raw_records
    )
    for file, qualified_name, class_name, parameters, node in raw_records:
        stable_name = (
            f"{file}::{qualified_name}"
            if duplicate_names[qualified_name] > 1
            else qualified_name
        )
        parameter_indices = {
            name: index
            for index, name in enumerate(parameters)
        }
        effects = _direct_effects(
            node,
            parameters=parameter_indices,
        )
        call_sites = _call_sites(node, parameter_indices)
        records[stable_name] = _FunctionRecord(
            file=file,
            qualified_name=stable_name,
            class_name=class_name,
            parameters=parameters,
            node=node,
            direct_effects=effects,
            call_sites=call_sites,
        )

    resolved_edges, call_bindings, edge_observed = _resolve_call_graph(
        records,
        max_edges=configured.max_call_edges,
    )
    if edge_observed > configured.max_call_edges:
        gaps.add(
            AnalysisGap(
                code="function_summary_call_edge_limit_reached",
                stage="call_graph",
                reason=(
                    "Call edges beyond the configured limit were not "
                    "propagated"
                ),
                limit_name="max_call_edges",
                limit_value=configured.max_call_edges,
                observed_value=edge_observed,
            )
        )

    components = _strongly_connected_components(
        tuple(sorted(records)),
        resolved_edges,
    )
    components = sorted(
        components,
        key=lambda component: min(component) if component else "",
    )
    scc_ids = {
        function: index
        for index, component in enumerate(components)
        for function in component
    }
    effects_by_function = {
        name: set(record.direct_effects)
        for name, record in records.items()
    }
    function_gaps: dict[str, set[AnalysisGap]] = defaultdict(set)
    stable = False
    executed_iterations = 0
    for iteration in range(1, configured.max_scc_iterations + 1):
        executed_iterations = iteration
        changed = False
        for caller in sorted(records):
            additions: set[FunctionEffect] = set()
            for callee, argument_parameters, line in call_bindings.get(
                caller,
                (),
            ):
                additions.add(
                    FunctionEffect(
                        kind=SummaryKind.WRAPPER,
                        value=callee,
                        line=line,
                        via=(callee,),
                        direct=False,
                    )
                )
                for effect in sorted(
                    effects_by_function.get(callee, ()),
                    key=lambda item: item.sort_key,
                ):
                    if effect.kind in {
                        SummaryKind.UNKNOWN,
                        SummaryKind.WRAPPER,
                    }:
                        continue
                    observed_depth = len(effect.via) + 1
                    if observed_depth > configured.max_call_depth:
                        function_gaps[caller].add(
                            AnalysisGap(
                                code=(
                                    "function_summary_call_depth_limit_reached"
                                ),
                                stage="summary_propagation",
                                reason=(
                                    "A propagated effect exceeded the "
                                    "configured call depth"
                                ),
                                file=records[caller].file,
                                function=caller,
                                limit_name="max_call_depth",
                                limit_value=configured.max_call_depth,
                                observed_value=observed_depth,
                            )
                        )
                        continue
                    propagated = _propagated_effect(
                        effect,
                        callee=callee,
                        argument_parameters=argument_parameters,
                        line=line,
                        max_depth=configured.max_call_depth,
                    )
                    if propagated is None:
                        continue
                    additions.add(propagated)
            current = effects_by_function[caller]
            combined = current | additions
            if len(combined) > configured.max_summaries_per_function:
                ordered = sorted(
                    combined,
                    key=lambda item: item.sort_key,
                )
                combined = set(
                    ordered[: configured.max_summaries_per_function]
                )
                function_gaps[caller].add(
                    AnalysisGap(
                        code=(
                            "function_summary_per_function_limit_reached"
                        ),
                        stage="summary_propagation",
                        reason=(
                            "Effects beyond the per-function limit were "
                            "discarded explicitly"
                        ),
                        file=records[caller].file,
                        function=caller,
                        limit_name="max_summaries_per_function",
                        limit_value=(
                            configured.max_summaries_per_function
                        ),
                        observed_value=len(ordered),
                    )
                )
            if combined != current:
                effects_by_function[caller] = combined
                changed = True
        if not changed:
            stable = True
            break
    if records and not stable:
        gaps.add(
            AnalysisGap(
                code="function_summary_fixpoint_limit_reached",
                stage="summary_propagation",
                reason=(
                    "Function summaries did not stabilize within the "
                    "configured SCC iteration limit"
                ),
                limit_name="max_scc_iterations",
                limit_value=configured.max_scc_iterations,
                observed_value=executed_iterations,
            )
        )

    summaries = []
    for name, record in sorted(
        records.items(),
        key=lambda item: (item[1].file, item[0]),
    ):
        local_gaps = tuple(
            sorted(
                function_gaps.get(name, ()),
                key=lambda gap: gap.sort_key,
            )
        )
        effects = effects_by_function[name]
        if not effects:
            effects = {
                FunctionEffect(
                    kind=SummaryKind.UNKNOWN,
                    value="no_supported_effect_inferred",
                    line=getattr(record.node, "lineno", None),
                )
            }
        summaries.append(
            FunctionSummary(
                file=record.file,
                qualified_name=name,
                parameters=record.parameters,
                effects=tuple(
                    sorted(
                        effects,
                        key=lambda effect: effect.sort_key,
                    )
                ),
                callees=tuple(sorted(resolved_edges.get(name, ()))),
                scc_id=scc_ids.get(name, 0),
                iterations=max(1, executed_iterations),
                complete=not local_gaps and stable,
                gaps=local_gaps,
            )
        )
        gaps.update(local_gaps)

    recursive_scc_count = sum(
        len(component) > 1
        or (
            len(component) == 1
            and component[0] in resolved_edges.get(component[0], ())
        )
        for component in components
    )
    effect_count = sum(len(summary.effects) for summary in summaries)
    limit_hits = Counter(
        gap.limit_name
        for gap in gaps
        if gap.limit_name
    )
    metrics = {
        "call_edge_count": sum(len(value) for value in resolved_edges.values()),
        "discovered_file_count": len(files),
        "effect_count": effect_count,
        "file_count": len(selected_files),
        "fixpoint_iterations": executed_iterations,
        "function_count": len(records),
        "gap_count": len(gaps),
        "limit_hit_count": sum(limit_hits.values()),
        "parsed_file_count": parsed_file_count,
        "recursive_scc_count": recursive_scc_count,
        "scc_count": len(components),
    }
    for name, count in sorted(limit_hits.items()):
        metrics[f"limit_hits_{name}"] = count
    return FunctionSummaryAnalysis(
        target=_normalized_target(target_path),
        summaries=tuple(summaries),
        gaps=tuple(sorted(gaps, key=lambda gap: gap.sort_key)),
        limits=configured,
        metrics=tuple(sorted(metrics.items())),
    )


def _parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    positional = [
        *getattr(node.args, "posonlyargs", ()),
        *node.args.args,
    ]
    values = [argument.arg for argument in positional]
    if node.args.vararg is not None:
        values.append(node.args.vararg.arg)
    values.extend(argument.arg for argument in node.args.kwonlyargs)
    if node.args.kwarg is not None:
        values.append(node.args.kwarg.arg)
    return tuple(values)


def _direct_effects(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    *,
    parameters: dict[str, int],
) -> tuple[FunctionEffect, ...]:
    effects: set[FunctionEffect] = set()
    function_name = node.name.lower()
    if any(
        token in function_name
        for token in ("validate", "validator", "is_safe", "is_valid")
    ):
        effects.add(
            FunctionEffect(
                kind=SummaryKind.VALIDATOR,
                value=node.name,
                line=node.lineno,
            )
        )
    if any(
        token in function_name
        for token in ("sanitize", "escape", "redact", "mask_secret")
    ):
        effects.add(
            FunctionEffect(
                kind=SummaryKind.SANITIZER,
                value=node.name,
                line=node.lineno,
            )
        )

    for item in _walk_function_body(node):
        if isinstance(item, ast.Return):
            effects.update(_return_effects(item, parameters))
        elif isinstance(item, ast.If):
            effects.update(_if_effects(item, parameters))
        elif isinstance(item, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            effects.update(_assignment_effects(item, parameters))
        elif isinstance(item, ast.Subscript) and isinstance(
            item.ctx,
            ast.Load,
        ):
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.COLLECTION_EXTRACT,
                    value=_expression(item.value),
                    resource=_resource(item.value, parameters),
                    line=getattr(item, "lineno", None),
                )
            )
        elif isinstance(item, ast.Call):
            effects.update(_call_effects(item, parameters))
        elif isinstance(item, ast.Attribute) and isinstance(
            item.ctx,
            ast.Load,
        ):
            if _receiver_path(item):
                effects.add(
                    FunctionEffect(
                        kind=SummaryKind.RECEIVER_OR_FIELD_READ,
                        value=_expression(item),
                        resource=_resource(item, parameters),
                        line=getattr(item, "lineno", None),
                    )
                )
            if _source_attribute(item):
                effects.add(
                    FunctionEffect(
                        kind=SummaryKind.SOURCE,
                        value=_expression(item),
                        resource=_resource(item, parameters),
                        line=getattr(item, "lineno", None),
                    )
                )
    return tuple(
        sorted(
            effects,
            key=lambda effect: effect.sort_key,
        )
    )


def _return_effects(
    node: ast.Return,
    parameters: dict[str, int],
) -> set[FunctionEffect]:
    value = node.value
    if value is None:
        return {
            FunctionEffect(
                kind=SummaryKind.CONSTANT,
                value="None",
                line=node.lineno,
            )
        }
    effects: set[FunctionEffect] = set()
    if isinstance(value, ast.Constant):
        effects.add(
            FunctionEffect(
                kind=SummaryKind.CONSTANT,
                value=repr(value.value),
                line=node.lineno,
            )
        )
    if isinstance(value, ast.Name) and value.id in parameters:
        index = parameters[value.id]
        for kind in (
            SummaryKind.IDENTITY,
            SummaryKind.PASSTHROUGH_ARGUMENT,
            SummaryKind.RETURN_FROM_PARAMETER,
        ):
            effects.add(
                FunctionEffect(
                    kind=kind,
                    value=value.id,
                    parameter_index=index,
                    resource=_resource(value, parameters),
                    line=node.lineno,
                )
            )
    referenced = _referenced_parameter_indices(value, parameters)
    if referenced and not isinstance(value, ast.Name):
        for index in referenced:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.TRANSFORMED_ARGUMENT,
                    value=_expression(value),
                    parameter_index=index,
                    line=node.lineno,
                )
            )
    receiver = _receiver_path(value)
    if receiver:
        effects.add(
            FunctionEffect(
                kind=SummaryKind.RETURN_FROM_RECEIVER,
                value=".".join(receiver),
                resource=_resource(value, parameters),
                line=node.lineno,
            )
        )
    if isinstance(value, (ast.Compare, ast.BoolOp, ast.UnaryOp)):
        for index in referenced:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.PREDICATE_GUARD,
                    value=_expression(value),
                    parameter_index=index,
                    line=node.lineno,
                )
            )
    if isinstance(value, ast.Call):
        name = _call_name(value.func)
        effects.add(
            FunctionEffect(
                kind=SummaryKind.WRAPPER,
                value=name or "<dynamic-call>",
                line=node.lineno,
            )
        )
        if _sanitizer_name(name):
            for index in referenced:
                effects.add(
                    FunctionEffect(
                        kind=SummaryKind.SANITIZER,
                        value=name,
                        parameter_index=index,
                        line=node.lineno,
                    )
                )
    return effects


def _if_effects(
    node: ast.If,
    parameters: dict[str, int],
) -> set[FunctionEffect]:
    effects: set[FunctionEffect] = set()
    referenced = _referenced_parameter_indices(node.test, parameters)
    if not referenced:
        return effects
    abortive = any(
        isinstance(item, (ast.Raise, ast.Return, ast.Break, ast.Continue))
        for statement in node.body
        for item in ast.walk(statement)
    )
    for index in referenced:
        effects.add(
            FunctionEffect(
                kind=SummaryKind.PREDICATE_GUARD,
                value=_expression(node.test),
                parameter_index=index,
                line=node.lineno,
            )
        )
        if abortive:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.ABORTIVE_GUARD,
                    value=_expression(node.test),
                    parameter_index=index,
                    line=node.lineno,
                )
            )
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.VALIDATOR,
                    value=_expression(node.test),
                    parameter_index=index,
                    line=node.lineno,
                )
            )
    return effects


def _assignment_effects(
    node: ast.Assign | ast.AnnAssign | ast.AugAssign,
    parameters: dict[str, int],
) -> set[FunctionEffect]:
    if isinstance(node, ast.Assign):
        targets = node.targets
        value = node.value
    elif isinstance(node, ast.AnnAssign):
        targets = [node.target]
        value = node.value
    else:
        targets = [node.target]
        value = node.value
    if value is None:
        return set()
    referenced = _referenced_parameter_indices(value, parameters)
    effects: set[FunctionEffect] = set()
    for target in targets:
        receiver = _receiver_path(target)
        if receiver:
            for index in referenced or {None}:
                effects.add(
                    FunctionEffect(
                        kind=SummaryKind.RECEIVER_OR_FIELD_WRITE,
                        value=".".join(receiver),
                        parameter_index=index,
                        resource=_resource(target, parameters),
                        line=getattr(node, "lineno", None),
                    )
                )
        if isinstance(target, ast.Subscript):
            for index in referenced or {None}:
                effects.add(
                    FunctionEffect(
                        kind=SummaryKind.COLLECTION_INSERT,
                        value=_expression(target),
                        parameter_index=index,
                        resource=_resource(target.value, parameters),
                        line=getattr(node, "lineno", None),
                    )
                )
    return effects


def _call_effects(
    node: ast.Call,
    parameters: dict[str, int],
) -> set[FunctionEffect]:
    name = _call_name(node.func)
    lowered = name.lower()
    referenced = _referenced_parameter_indices(node, parameters)
    effects: set[FunctionEffect] = set()
    if _source_call(lowered):
        effects.add(
            FunctionEffect(
                kind=SummaryKind.SOURCE,
                value=name,
                line=node.lineno,
            )
        )
    if _sink_call(lowered):
        for index in referenced or {None}:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.SINK,
                    value=name,
                    parameter_index=index,
                    line=node.lineno,
                )
            )
    if _sanitizer_name(lowered):
        for index in referenced or {None}:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.SANITIZER,
                    value=name,
                    parameter_index=index,
                    line=node.lineno,
                )
            )
    if _validator_name(lowered):
        for index in referenced or {None}:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.VALIDATOR,
                    value=name,
                    parameter_index=index,
                    line=node.lineno,
                )
            )
    if isinstance(node.func, ast.Attribute) and node.func.attr in {
        "append",
        "add",
        "extend",
        "insert",
        "setdefault",
        "update",
    }:
        for index in referenced or {None}:
            effects.add(
                FunctionEffect(
                    kind=SummaryKind.COLLECTION_INSERT,
                    value=name,
                    parameter_index=index,
                    resource=_resource(node.func.value, parameters),
                    line=node.lineno,
                )
            )
    return effects


def _call_sites(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    parameters: dict[str, int],
) -> tuple[_CallSite, ...]:
    sites = set()
    for item in _walk_function_body(node):
        if not isinstance(item, ast.Call):
            continue
        name = _call_name(item.func)
        if not name:
            continue
        arguments = []
        for argument in item.args:
            if isinstance(argument, ast.Name):
                arguments.append(parameters.get(argument.id))
            else:
                arguments.append(None)
        sites.add(
            _CallSite(
                raw_name=name,
                line=item.lineno,
                argument_parameters=tuple(arguments),
            )
        )
    return tuple(
        sorted(
            sites,
            key=lambda item: (
                item.raw_name,
                item.line,
                _argument_sort_key(item.argument_parameters),
            ),
        )
    )


def _resolve_call_graph(
    records: dict[str, _FunctionRecord],
    *,
    max_edges: int,
) -> tuple[
    dict[str, tuple[str, ...]],
    dict[str, tuple[tuple[str, tuple[int | None, ...], int], ...]],
    int,
]:
    by_tail: dict[str, list[str]] = defaultdict(list)
    for name in records:
        tail = name.split("::")[-1].split(".")[-1]
        by_tail[tail].append(name)
    candidate_bindings = []
    for caller, record in sorted(records.items()):
        for site in record.call_sites:
            tail = site.raw_name.split(".")[-1]
            candidates = by_tail.get(tail, [])
            selected = ""
            if "." not in site.raw_name and len(candidates) == 1:
                selected = candidates[0]
            elif site.raw_name.startswith(("self.", "cls.")):
                class_prefix = record.class_name
                matching = [
                    candidate
                    for candidate in candidates
                    if (
                        candidate.split("::")[-1].startswith(
                            f"{class_prefix}."
                        )
                        if class_prefix
                        else False
                    )
                ]
                if len(matching) == 1:
                    selected = matching[0]
            if selected:
                candidate_bindings.append(
                    (
                        caller,
                        selected,
                        site.argument_parameters,
                        site.line,
                    )
                )
    candidate_bindings.sort(
        key=lambda item: (
            item[0],
            item[1],
            _argument_sort_key(item[2]),
            item[3],
        )
    )
    observed = len(candidate_bindings)
    selected_bindings = candidate_bindings[:max_edges]
    edges: dict[str, set[str]] = defaultdict(set)
    bindings: dict[
        str,
        list[tuple[str, tuple[int | None, ...], int]],
    ] = defaultdict(list)
    for caller, callee, argument_parameters, line in selected_bindings:
        edges[caller].add(callee)
        bindings[caller].append((callee, argument_parameters, line))
    return (
        {
            caller: tuple(sorted(callees))
            for caller, callees in sorted(edges.items())
        },
        {
            caller: tuple(
                sorted(
                    values,
                    key=lambda item: (
                        item[0],
                        _argument_sort_key(item[1]),
                        item[2],
                    ),
                )
            )
            for caller, values in sorted(bindings.items())
        },
        observed,
    )


def _argument_sort_key(
    arguments: tuple[int | None, ...],
) -> tuple[int, ...]:
    return tuple(-1 if value is None else value for value in arguments)


def _propagated_effect(
    effect: FunctionEffect,
    *,
    callee: str,
    argument_parameters: tuple[int | None, ...],
    line: int,
    max_depth: int,
) -> FunctionEffect | None:
    via = (callee, *effect.via)
    if len(via) > max_depth:
        return None
    parameter_index = None
    if effect.parameter_index is not None:
        if effect.parameter_index >= len(argument_parameters):
            return None
        parameter_index = argument_parameters[effect.parameter_index]
        if parameter_index is None:
            return None
    return FunctionEffect(
        kind=effect.kind,
        value=effect.value,
        parameter_index=parameter_index,
        resource=None,
        context=effect.context,
        line=line,
        via=via,
        direct=False,
    )


def _strongly_connected_components(
    nodes: tuple[str, ...],
    edges: dict[str, tuple[str, ...]],
) -> list[tuple[str, ...]]:
    index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    lowlinks: dict[str, int] = {}
    components: list[tuple[str, ...]] = []

    def visit(node: str) -> None:
        nonlocal index
        indices[node] = index
        lowlinks[node] = index
        index += 1
        stack.append(node)
        on_stack.add(node)
        for neighbor in edges.get(node, ()):
            if neighbor not in indices:
                visit(neighbor)
                lowlinks[node] = min(
                    lowlinks[node],
                    lowlinks[neighbor],
                )
            elif neighbor in on_stack:
                lowlinks[node] = min(
                    lowlinks[node],
                    indices[neighbor],
                )
        if lowlinks[node] != indices[node]:
            return
        component = []
        while stack:
            selected = stack.pop()
            on_stack.remove(selected)
            component.append(selected)
            if selected == node:
                break
        components.append(tuple(sorted(component)))

    for node in nodes:
        if node not in indices:
            visit(node)
    return components


def _walk_function_body(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
):
    """Yield a function body without attributing nested-scope effects."""

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


def _referenced_parameter_indices(
    node: ast.AST,
    parameters: dict[str, int],
) -> set[int]:
    return {
        parameters[item.id]
        for item in ast.walk(node)
        if isinstance(item, ast.Name) and item.id in parameters
    }


def _receiver_path(node: ast.AST) -> tuple[str, ...]:
    values = []
    current = node
    while isinstance(current, ast.Attribute):
        values.append(current.attr)
        current = current.value
    if isinstance(current, ast.Name) and current.id in {"self", "cls"}:
        return tuple([current.id, *reversed(values)])
    return ()


def _resource(
    node: ast.AST,
    parameters: dict[str, int],
) -> ResourceIdentity | None:
    if isinstance(node, ast.Name):
        kind = "parameter" if node.id in parameters else "local"
        return ResourceIdentity(kind=kind, symbol=node.id)
    receiver = _receiver_path(node)
    if receiver:
        return ResourceIdentity(
            kind="receiver",
            symbol=receiver[0],
            path=receiver[1:],
        )
    if isinstance(node, ast.Attribute):
        return ResourceIdentity(
            kind="attribute",
            symbol=_expression(node),
        )
    return None


def _call_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _call_name(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    return ""


def _expression(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (AttributeError, ValueError):
        return type(node).__name__


def _source_attribute(node: ast.Attribute) -> bool:
    value = _expression(node).lower()
    return any(
        token in value
        for token in (
            "request.args",
            "request.form",
            "request.headers",
            "request.cookies",
            "request.query",
            "sys.argv",
            "os.environ",
        )
    )


def _source_call(name: str) -> bool:
    return (
        name == "input"
        or any(
            token in name
            for token in (
                "request.args.get",
                "request.form.get",
                "request.headers.get",
                "request.cookies.get",
                "get_query_argument",
                "get_json_body",
            )
        )
    )


def _sink_call(name: str) -> bool:
    exact = {
        "eval",
        "exec",
        "open",
        "os.open",
        "redirect",
        "subprocess.call",
        "subprocess.run",
        "subprocess.popen",
    }
    tail = name.split(".")[-1]
    return (
        name in exact
        or tail
        in {
            "decompress",
            "execute",
            "executemany",
            "httpredirect",
            "redirect",
            "send",
            "write",
        }
        or any(
            token in name
            for token in (
                "logger.",
                ".log.",
                ".headers.update",
                ".headers.add",
            )
        )
    )


def _sanitizer_name(name: str) -> bool:
    lowered = name.lower()
    return any(
        token in lowered
        for token in (
            "escape",
            "sanitize",
            "redact",
            "mask_password",
            "mask_secret",
            "normalize",
            "quote",
        )
    )


def _validator_name(name: str) -> bool:
    lowered = name.lower()
    tail = lowered.split(".")[-1]
    return (
        tail.startswith(("validate", "check_"))
        or tail in {"is_safe", "is_valid", "fullmatch"}
        or any(
            token in lowered
            for token in (
                "validators.length",
                "validators.regexp",
                "permission_required",
            )
        )
    )


def _python_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() == ".py" else []
    if not target.exists():
        raise ValueError(f"semantic summary target does not exist: {target}")
    return sorted(
        (
            path
            for path in target.rglob("*.py")
            if path.is_file()
        ),
        key=lambda path: path.relative_to(target).as_posix(),
    )


def _relative_path(path: Path, target: Path) -> str:
    root = target if target.is_dir() else target.parent
    return path.relative_to(root).as_posix()


def _normalized_target(path: Path) -> str:
    return "." if path.is_dir() else path.name


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "FUNCTION_SUMMARY_ANALYSIS_SCHEMA_VERSION",
    "FunctionSummaryAnalysis",
    "FunctionSummaryLimits",
    "analyze_function_summaries",
]
