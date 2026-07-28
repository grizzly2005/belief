"""Orchestration for bounded semantic flow-state contracts."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

from .contracts import (
    analyze_authorization_contracts,
    analyze_protocol_contracts,
    analyze_resource_contracts,
)
from .contracts.common import (
    ClassContractContext,
    ContractObservations,
    FunctionContractContext,
)
from .models import AnalysisGap, FunctionEffect
from .observations import (
    SemanticFlowAnalysis,
    SemanticFlowLimits,
)
from .summaries import (
    FunctionSummaryAnalysis,
    FunctionSummaryLimits,
    analyze_function_summaries,
)


class _ScopeCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.scope: list[str] = []
        self.class_scope: list[str] = []
        self.functions: list[
            tuple[
                str,
                str,
                tuple[str, ...],
                ast.FunctionDef | ast.AsyncFunctionDef,
            ]
        ] = []
        self.classes: list[tuple[str, ast.ClassDef]] = []

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = ".".join([*self.scope, node.name])
        self.classes.append((qualified, node))
        self.scope.append(node.name)
        self.class_scope.append(node.name)
        self.generic_visit(node)
        self.class_scope.pop()
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._function(node)

    def visit_AsyncFunctionDef(
        self,
        node: ast.AsyncFunctionDef,
    ) -> None:
        self._function(node)

    def _function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        qualified = ".".join([*self.scope, node.name])
        class_name = ".".join(self.class_scope)
        self.functions.append(
            (
                qualified,
                class_name,
                _parameters(node),
                node,
            )
        )
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()


def analyze_semantic_flow(
    target: str | Path,
    *,
    summaries: FunctionSummaryAnalysis | None = None,
    limits: SemanticFlowLimits | None = None,
    use_summary_effects: bool = True,
) -> SemanticFlowAnalysis:
    """Analyze reusable security contracts without network or execution."""

    if not isinstance(use_summary_effects, bool):
        raise ValueError("use_summary_effects must be boolean")
    configured = limits or SemanticFlowLimits()
    target_path = Path(target).resolve()
    summary_result = summaries or analyze_function_summaries(
        target_path,
        FunctionSummaryLimits(
            max_files=configured.max_files,
            max_functions=configured.max_functions,
        ),
    )
    summary_effects = (
        _summary_effects(summary_result)
        if use_summary_effects
        else {}
    )
    discovered_files = _all_python_files(target_path)
    files = [path for path in discovered_files if _included_analysis_path(path, target_path)]
    gaps: set[AnalysisGap] = set()
    if len(files) > configured.max_files:
        gaps.add(
            AnalysisGap(
                code="semantic_flow_file_limit_reached",
                stage="semantic_scope_collection",
                reason=("Python files beyond the semantic flow limit were not analyzed"),
                limit_name="max_files",
                limit_value=configured.max_files,
                observed_value=len(files),
            )
        )
    selected_files = files[: configured.max_files]
    all_concerns = {}
    all_guards = {}
    all_transitions = {}
    function_count = 0
    class_count = 0
    parsed_file_count = 0
    ast_node_count = 0
    scope_limit_reported = False
    for file_path in selected_files:
        relative = _relative_path(file_path, target_path)
        try:
            source = file_path.read_text(
                encoding="utf-8",
                errors="replace",
            )
            tree = ast.parse(source, filename=relative)
        except (OSError, SyntaxError, UnicodeError) as exc:
            gaps.add(
                AnalysisGap(
                    code="semantic_flow_parse_failure",
                    stage="semantic_scope_collection",
                    reason=f"{type(exc).__name__}: {exc}",
                    file=relative,
                    line=getattr(exc, "lineno", None),
                )
            )
            continue
        discovered_nodes = sum(1 for _ in ast.walk(tree))
        if ast_node_count + discovered_nodes > configured.max_ast_nodes:
            gaps.add(
                AnalysisGap(
                    code="semantic_flow_ast_node_limit_reached",
                    stage="semantic_scope_collection",
                    reason=(
                        "A file was not analyzed because it would exceed "
                        "the cumulative AST node limit"
                    ),
                    file=relative,
                    limit_name="max_ast_nodes",
                    limit_value=configured.max_ast_nodes,
                    observed_value=ast_node_count + discovered_nodes,
                )
            )
            continue
        ast_node_count += discovered_nodes
        parsed_file_count += 1
        collector = _ScopeCollector()
        collector.visit(tree)
        for (
            qualified_name,
            class_name,
            parameters,
            node,
        ) in collector.functions:
            function_count += 1
            if function_count > configured.max_functions:
                if not scope_limit_reported:
                    gaps.add(
                        AnalysisGap(
                            code="semantic_flow_function_limit_reached",
                            stage="semantic_scope_collection",
                            reason=("Functions beyond the semantic flow limit were not analyzed"),
                            limit_name="max_functions",
                            limit_value=configured.max_functions,
                            observed_value=function_count,
                        )
                    )
                    scope_limit_reported = True
                continue
            effects = summary_effects.get(
                (relative, qualified_name),
                (),
            )
            context = FunctionContractContext(
                file=relative,
                qualified_name=qualified_name,
                class_name=class_name,
                parameters=parameters,
                node=node,
                source=source,
                summary_effects=effects,
            )
            result = ContractObservations.merge(
                (
                    analyze_resource_contracts(context),
                    analyze_protocol_contracts(context),
                    analyze_authorization_contracts(context),
                )
            )
            bounded = _bounded_observations(
                result,
                context=context,
                limits=configured,
            )
            gaps.update(bounded[3])
            for concern in bounded[0]:
                all_concerns[concern.deterministic_digest] = concern
            for guard in bounded[1]:
                all_guards[guard.guard_id] = guard
            for transition in bounded[2]:
                all_transitions[transition.transition_id] = transition

        for qualified_name, node in collector.classes:
            class_count += 1
            context = ClassContractContext(
                file=relative,
                qualified_name=qualified_name,
                node=node,
                source=source,
            )
            result = ContractObservations.merge(
                (
                    analyze_resource_contracts(context),
                    analyze_protocol_contracts(context),
                    analyze_authorization_contracts(context),
                )
            )
            bounded = _bounded_observations(
                result,
                context=context,
                limits=configured,
            )
            gaps.update(bounded[3])
            for concern in bounded[0]:
                all_concerns[concern.deterministic_digest] = concern
            for guard in bounded[1]:
                all_guards[guard.guard_id] = guard
            for transition in bounded[2]:
                all_transitions[transition.transition_id] = transition

    concerns = tuple(
        sorted(
            all_concerns.values(),
            key=lambda item: item.sort_key,
        )
    )
    guards = tuple(
        sorted(
            all_guards.values(),
            key=lambda item: (
                item.guard_id,
                item.resource.canonical,
                item.line or 0,
            ),
        )
    )
    transitions = tuple(
        sorted(
            all_transitions.values(),
            key=lambda item: (
                item.transition_id,
                item.resource.canonical,
                item.line or 0,
            ),
        )
    )
    category_counts = Counter(concern.category for concern in concerns)
    metrics = {
        "ast_node_count": ast_node_count,
        "class_count": class_count,
        "concern_count": len(concerns),
        "discovered_file_count": len(discovered_files),
        "excluded_file_count": len(discovered_files) - len(files),
        "file_count": len(selected_files),
        "function_count": min(
            function_count,
            configured.max_functions,
        ),
        "gap_count": len(gaps),
        "guard_count": len(guards),
        "parsed_file_count": parsed_file_count,
        "transition_count": len(transitions),
        "summary_effects_enabled": int(use_summary_effects),
    }
    for category, count in sorted(category_counts.items()):
        metrics[f"concerns_{category}"] = count
    return SemanticFlowAnalysis(
        target="." if target_path.is_dir() else target_path.name,
        concerns=concerns,
        guards=guards,
        transitions=transitions,
        gaps=tuple(
            sorted(
                gaps,
                key=lambda gap: gap.sort_key,
            )
        ),
        limits=configured,
        metrics=tuple(sorted(metrics.items())),
        function_summary_digest=summary_result.deterministic_digest,
    )


def _bounded_observations(
    result: ContractObservations,
    *,
    context: FunctionContractContext | ClassContractContext,
    limits: SemanticFlowLimits,
):
    gaps = set()
    concerns = result.concerns
    guards = result.guards
    transitions = result.transitions
    identity = (
        context.qualified_name
        if isinstance(context, FunctionContractContext)
        else f"{context.qualified_name}.<class>"
    )
    if len(concerns) > limits.max_concerns_per_function:
        gaps.add(
            AnalysisGap(
                code="semantic_flow_concern_limit_reached",
                stage="semantic_contracts",
                reason=("Concerns beyond the per-scope limit were explicitly discarded"),
                file=context.file,
                function=identity,
                limit_name="max_concerns_per_function",
                limit_value=limits.max_concerns_per_function,
                observed_value=len(concerns),
            )
        )
        concerns = concerns[: limits.max_concerns_per_function]
    if len(guards) > limits.max_guards_per_function:
        gaps.add(
            AnalysisGap(
                code="semantic_flow_guard_limit_reached",
                stage="semantic_contracts",
                reason=("Guards beyond the per-scope limit were explicitly discarded"),
                file=context.file,
                function=identity,
                limit_name="max_guards_per_function",
                limit_value=limits.max_guards_per_function,
                observed_value=len(guards),
            )
        )
        guards = guards[: limits.max_guards_per_function]
    if len(transitions) > limits.max_transitions_per_function:
        gaps.add(
            AnalysisGap(
                code="semantic_flow_transition_limit_reached",
                stage="semantic_contracts",
                reason=("Transitions beyond the per-scope limit were explicitly discarded"),
                file=context.file,
                function=identity,
                limit_name="max_transitions_per_function",
                limit_value=limits.max_transitions_per_function,
                observed_value=len(transitions),
            )
        )
        transitions = transitions[: limits.max_transitions_per_function]
    return concerns, guards, transitions, gaps


def _summary_effects(
    summaries: FunctionSummaryAnalysis,
) -> dict[tuple[str, str], tuple[FunctionEffect, ...]]:
    result = {}
    for summary in summaries.summaries:
        qualified = summary.qualified_name.split("::")[-1]
        result[(summary.file, qualified)] = summary.effects
    return result


def _parameters(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    values = [
        argument.arg
        for argument in (
            *getattr(node.args, "posonlyargs", ()),
            *node.args.args,
        )
    ]
    if node.args.vararg:
        values.append(node.args.vararg.arg)
    values.extend(argument.arg for argument in node.args.kwonlyargs)
    if node.args.kwarg:
        values.append(node.args.kwarg.arg)
    return tuple(values)


def _all_python_files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() == ".py" else []
    if not target.exists():
        raise ValueError(f"semantic flow target does not exist: {target}")
    return sorted(
        (path for path in target.rglob("*.py") if path.is_file()),
        key=lambda path: path.relative_to(target).as_posix(),
    )


def _included_analysis_path(path: Path, target: Path) -> bool:
    if target.is_file():
        return True
    parts = tuple(part.lower() for part in path.relative_to(target).parts[:-1])
    return not any(
        part
        in {
            ".git",
            ".nox",
            ".tox",
            "__pycache__",
            "node_modules",
            "site-packages",
        }
        or part in {"env", "venv"}
        or part.startswith(".venv")
        for part in parts
    )


def _relative_path(path: Path, target: Path) -> str:
    root = target if target.is_dir() else target.parent
    return path.relative_to(root).as_posix()


__all__ = ["analyze_semantic_flow"]
