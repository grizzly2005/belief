"""Oracle-free security review for a candidate Git worktree patch.

The reviewer compares BELIEF observations in the clean ``HEAD`` revision with
the current worktree, restricted to Python functions and lines touched by the
candidate diff. It never reads benchmark labels, reference fixes, hidden tests,
Git history beyond ``HEAD``, or network resources.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import warnings
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from .benchmark.susvibes import (
    SURFACED_VERDICTS,
    DiffFile,
    FocusContext,
    build_focus_context,
    finding_is_focused,
    parse_security_diff,
)
from .reportability.scoring import assess_audit_case_reportability
from .static_analysis_pipeline import (
    StaticAnalysisOptions,
    analyze_static_target,
)
from .semantic.summaries import (
    FUNCTION_SUMMARY_ANALYSIS_SCHEMA_VERSION,
    FunctionSummaryAnalysis,
    FunctionSummaryLimits,
    analyze_function_summaries,
)
from .semantic.evidence import (
    EvidenceGraphLimits,
    SemanticClassification,
    SemanticComparison,
    build_evidence_graph,
    compare_semantic_flows,
)
from .semantic.flow import analyze_semantic_flow
from .semantic.models import AnalysisGap, FunctionSummary
from .semantic.observations import (
    SemanticFlowAnalysis,
    SemanticFlowLimits,
)


CANDIDATE_PATCH_REVIEW_SCHEMA_VERSION = "belief.candidate_patch_review.v1"
SEMANTIC_REVIEW_MODES = (
    "off",
    "summaries",
    "flow_states",
    "evidence_graph",
    "full",
)
_SEMANTIC_FLOW_MODES = frozenset(
    {
        "flow_states",
        "evidence_graph",
        "full",
    }
)
_SEMANTIC_EVIDENCE_MODES = frozenset(
    {
        "evidence_graph",
        "full",
    }
)

_GIT_ENV_OVERRIDES = {
    "GIT_ALLOW_PROTOCOL": "",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


@dataclass(frozen=True)
class _SemanticObservation:
    summary_payload: dict[str, Any]
    flow_payload: dict[str, Any]
    findings: tuple[Any, ...]
    summary_result: FunctionSummaryAnalysis | None
    flow_result: SemanticFlowAnalysis | None


def collect_worktree_patch(target: str | Path) -> str:
    """Return tracked and untracked worktree changes without invoking diff helpers."""

    root = _repository_root(target)
    tracked = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "--full-index",
        "HEAD",
        "--",
    )
    untracked_raw = _git(
        root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        decode=False,
    )
    chunks = [tracked]
    for raw_path in bytes(untracked_raw).split(b"\0"):
        if not raw_path:
            continue
        relative = os.fsdecode(raw_path)
        normalized = _safe_relative_path(relative)
        if not normalized.endswith(".py"):
            continue
        result = _git_completed(
            root,
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--",
            "/dev/null",
            normalized,
        )
        if result.returncode not in {0, 1}:
            _raise_git_error(result, "diff untracked file")
        chunks.append(result.stdout.decode("utf-8", errors="replace"))
    return "".join(chunks)


def review_candidate_patch(
    target: str | Path,
    patch: str | None = None,
    *,
    include_tests: bool = False,
    max_files: int = 100,
    semantic_mode: str = "summaries",
    semantic_limits: FunctionSummaryLimits | None = None,
    semantic_flow_limits: SemanticFlowLimits | None = None,
    semantic_evidence_limits: EvidenceGraphLimits | None = None,
    pipeline: Callable[[Path], Any] | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Review the candidate patch in *target* against its clean ``HEAD`` state."""

    root = _repository_root(target)
    if max_files <= 0:
        raise ValueError("max_files must be positive")
    if semantic_mode not in SEMANTIC_REVIEW_MODES:
        raise ValueError(
            "semantic_mode must be one of: "
            + ", ".join(SEMANTIC_REVIEW_MODES)
        )
    configured_semantic_limits = semantic_limits or (
        FunctionSummaryLimits(
            max_files=max_files,
            max_scc_iterations=16,
            max_summaries_per_function=128,
            max_call_depth=16,
        )
        if semantic_mode == "full"
        else FunctionSummaryLimits(max_files=max_files)
    )
    configured_flow_limits = (
        semantic_flow_limits
        or SemanticFlowLimits(max_files=max_files)
    )
    configured_evidence_limits = (
        semantic_evidence_limits
        or EvidenceGraphLimits()
    )
    patch_text = collect_worktree_patch(root) if patch is None else str(patch)
    started = clock()
    parsed_files = parse_security_diff(patch_text)
    excluded_files = sorted({
        item.output_path
        for item in parsed_files
        if not include_tests and _is_test_path(item.output_path)
    })
    diff_files = tuple(
        item
        for item in parsed_files
        if include_tests or not _is_test_path(item.output_path)
    )
    if len(diff_files) > max_files:
        raise ValueError(
            f"candidate patch changes {len(diff_files)} Python files; "
            f"max_files is {max_files}"
        )

    observations: dict[str, dict[str, Any]] = {}
    summary_results: dict[
        str,
        FunctionSummaryAnalysis | None,
    ] = {}
    flow_results: dict[
        str,
        SemanticFlowAnalysis | None,
    ] = {}
    focus_results: dict[
        str,
        dict[str, FocusContext],
    ] = {}
    with tempfile.TemporaryDirectory(prefix="belief-candidate-review-") as temp:
        temp_root = Path(temp)
        for state in ("vulnerable", "fixed"):
            state_root = temp_root / state
            state_root.mkdir(parents=True, exist_ok=True)
            focus: dict[str, FocusContext] = {}
            materialization_errors: list[str] = []
            for diff_file in diff_files:
                source = _source_for_state(root, diff_file, state)
                if source is None:
                    continue
                output_path = diff_file.output_path
                destination = _safe_destination(state_root, output_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source, encoding="utf-8")
                focus[output_path] = build_focus_context(
                    source,
                    diff_file.hunks,
                    state,
                )
            focus_results[state] = focus
            if not focus:
                semantic = _semantic_observation(
                    state_root,
                    semantic_mode,
                    configured_semantic_limits,
                    configured_flow_limits,
                )
                observations[state] = {
                    "analysis_succeeded": True,
                    "errors": materialization_errors,
                    "diagnostics": [],
                    "findings": [],
                    "function_summary": (
                        semantic.summary_payload
                    ),
                    "semantic_flow": semantic.flow_payload,
                }
                summary_results[state] = (
                    semantic.summary_result
                )
                flow_results[state] = semantic.flow_result
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    result = (pipeline or _default_pipeline)(state_root)
                    semantic = _semantic_observation(
                        state_root,
                        semantic_mode,
                        configured_semantic_limits,
                        configured_flow_limits,
                    )
                observations[state] = {
                    "analysis_succeeded": True,
                    "errors": materialization_errors,
                    "diagnostics": [
                        diagnostic.to_dict()
                        for diagnostic in (
                            getattr(result, "diagnostics", ()) or ()
                        )
                    ],
                    "findings": _focused_findings(
                        result,
                        focus,
                        supplemental_findings=(
                            semantic.findings
                        ),
                    ),
                    "function_summary": (
                        semantic.summary_payload
                    ),
                    "semantic_flow": semantic.flow_payload,
                }
                summary_results[state] = (
                    semantic.summary_result
                )
                flow_results[state] = semantic.flow_result
            except Exception as exc:
                observations[state] = {
                    "analysis_succeeded": False,
                    "errors": [
                        *materialization_errors,
                        f"{type(exc).__name__}: {exc}",
                    ],
                    "diagnostics": [],
                    "findings": [],
                    "function_summary": {
                        "enabled": semantic_mode != "off",
                        "mode": semantic_mode,
                        "analysis_succeeded": False,
                    },
                    "semantic_flow": {
                        "enabled": (
                            semantic_mode
                            in _SEMANTIC_FLOW_MODES
                        ),
                        "mode": semantic_mode,
                        "analysis_succeeded": False,
                    },
                }
                summary_results[state] = None
                flow_results[state] = None

    baseline_rows = observations["vulnerable"]["findings"]
    candidate_rows = observations["fixed"]["findings"]
    semantic_evidence, semantic_comparison = (
        _semantic_evidence_payload(
            semantic_mode,
            summary_results,
            flow_results,
            focus_results,
            configured_evidence_limits,
        )
    )
    introduced, residual, resolved = _classify_findings(
        baseline_rows,
        candidate_rows,
        semantic_comparison,
    )
    actionable = [
        item
        for item in [*introduced, *residual]
        if item["actionable"]
    ]
    feedback = _render_feedback(actionable)
    duration = round(max(0.0, float(clock() - started)), 6)
    payload: dict[str, Any] = {
        "schema_version": CANDIDATE_PATCH_REVIEW_SCHEMA_VERSION,
        "mode": "oracle_free_candidate_patch_review",
        "target": str(root),
        "patch_sha256": hashlib.sha256(
            patch_text.encode("utf-8")
        ).hexdigest(),
        "changed_python_files": [
            item.output_path
            for item in diff_files
        ],
        "excluded_test_files": excluded_files,
        "semantic_analysis": {
            "mode": semantic_mode,
            "limits": configured_semantic_limits.to_dict(),
            "flow_limits": configured_flow_limits.to_dict(),
            "evidence_limits": (
                configured_evidence_limits.to_dict()
            ),
            "flow_uses_summaries": (
                semantic_mode in {"flow_states", "full"}
            ),
            "affects_verdict": (
                semantic_mode in _SEMANTIC_FLOW_MODES
            ),
        },
        "semantic_evidence": semantic_evidence,
        "analysis": {
            "baseline": observations["vulnerable"],
            "candidate": observations["fixed"],
        },
        "introduced_findings": introduced,
        "residual_findings": residual,
        "resolved_findings": resolved,
        "counts": {
            "changed_python_files": len(diff_files),
            "excluded_test_files": len(excluded_files),
            "baseline_findings": len(baseline_rows),
            "candidate_findings": len(candidate_rows),
            "introduced_findings": len(introduced),
            "introduced_actionable": sum(
                bool(item["actionable"])
                and item["classification"] == "introduced"
                for item in introduced
            ),
            "residual_findings": len(residual),
            "residual_actionable": sum(
                bool(item["actionable"]) for item in residual
            ),
            "shifted_actionable": sum(
                bool(item["actionable"])
                and item["classification"] == "shifted"
                for item in introduced
            ),
            "partially_mitigated_actionable": sum(
                bool(item["actionable"])
                and item["classification"]
                == "partially_mitigated"
                for item in introduced
            ),
            "inconclusive_actionable": sum(
                bool(item["actionable"])
                and item["classification"] == "inconclusive"
                for item in introduced
            ),
            "resolved_findings": len(resolved),
            "candidate_actionable": len(actionable),
        },
        "status": "review_required" if actionable else "passed",
        "feedback": feedback,
        "comparability": {
            "susvibes_secpass_equivalent": False,
            "security_tests_executed": False,
            "benchmark_oracle_used": False,
            "measurement": (
                "candidate diff static review against clean HEAD"
            ),
        },
        "duration_seconds": duration,
    }
    payload["deterministic_digest"] = _semantic_digest(payload)
    return payload


def write_candidate_patch_review_json(
    target: str | Path,
    output: str | Path,
    patch: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Review a candidate patch and write the complete deterministic report."""

    payload = review_candidate_patch(target, patch, **kwargs)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _default_pipeline(target: Path) -> Any:
    options = StaticAnalysisOptions(
        max_files=100,
        selected_categories=frozenset({"security", "taint"}),
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        include_audit_cases=True,
        audit_mode=True,
        reportability=True,
        dedup_audit_cases=True,
        security_analysis_profile="patch_review",
    )
    return analyze_static_target(target, options)


def _semantic_observation(
    target: Path,
    mode: str,
    summary_limits: FunctionSummaryLimits,
    flow_limits: SemanticFlowLimits,
) -> _SemanticObservation:
    if mode == "off":
        disabled = {
            "enabled": False,
            "mode": mode,
            "analysis_succeeded": True,
        }
        return _SemanticObservation(
            summary_payload=disabled,
            flow_payload=dict(disabled),
            findings=(),
            summary_result=None,
            flow_result=None,
        )
    result = analyze_function_summaries(target, summary_limits)
    summary_payload = _function_summary_payload(result, mode)
    if mode == "summaries":
        return _SemanticObservation(
            summary_payload=summary_payload,
            flow_payload={
                "enabled": False,
                "mode": mode,
                "analysis_succeeded": True,
            },
            findings=(),
            summary_result=result,
            flow_result=None,
        )
    flow = analyze_semantic_flow(
        target,
        summaries=result,
        limits=flow_limits,
        use_summary_effects=(
            mode != "evidence_graph"
        ),
    )
    return _SemanticObservation(
        summary_payload=summary_payload,
        flow_payload={
            "enabled": True,
            "mode": mode,
            "analysis_succeeded": True,
            **flow.to_dict(),
        },
        findings=tuple(
            concern.to_finding()
            for concern in flow.concerns
        ),
        summary_result=result,
        flow_result=flow,
    )


def _function_summary_payload(
    result: FunctionSummaryAnalysis,
    mode: str,
) -> dict[str, Any]:
    return {
        "enabled": True,
        "mode": mode,
        "analysis_succeeded": True,
        "schema_version": FUNCTION_SUMMARY_ANALYSIS_SCHEMA_VERSION,
        "deterministic_digest": result.deterministic_digest,
        "metrics": dict(result.metrics),
        "limits": result.limits.to_dict(),
        "gaps": [gap.to_dict() for gap in result.gaps],
        "summaries": [
            summary.to_dict()
            for summary in result.summaries
        ],
    }


def _focused_flow_analysis(
    flow: SemanticFlowAnalysis,
    focus: Mapping[str, FocusContext],
) -> SemanticFlowAnalysis:
    concerns = tuple(
        concern
        for concern in flow.concerns
        if finding_is_focused(
            concern.to_finding(),
            focus,
        )
    )
    guards = tuple(
        guard
        for guard in flow.guards
        if _semantic_position_is_focused(
            guard.file,
            guard.function,
            guard.line,
            focus,
        )
    )
    transitions = tuple(
        transition
        for transition in flow.transitions
        if _semantic_position_is_focused(
            transition.file,
            transition.function,
            transition.line,
            focus,
        )
    )
    gaps = tuple(
        gap
        for gap in flow.gaps
        if (
            not gap.file
            or _semantic_position_is_focused(
                gap.file,
                gap.function,
                gap.line,
                focus,
            )
        )
    )
    metrics = dict(flow.metrics)
    metrics.update(
        {
            "concern_count": len(concerns),
            "gap_count": len(gaps),
            "guard_count": len(guards),
            "transition_count": len(transitions),
            "focused_scope": 1,
        }
    )
    return SemanticFlowAnalysis(
        target=flow.target,
        concerns=concerns,
        guards=guards,
        transitions=transitions,
        gaps=gaps,
        limits=flow.limits,
        metrics=tuple(sorted(metrics.items())),
        function_summary_digest=(
            flow.function_summary_digest
        ),
    )


def _focused_summary_analysis(
    result: FunctionSummaryAnalysis,
    focus: Mapping[str, FocusContext],
) -> FunctionSummaryAnalysis:
    summaries_by_name = {
        summary.qualified_name: summary
        for summary in result.summaries
    }
    selected = {
        summary.qualified_name
        for summary in result.summaries
        if _summary_is_focused(summary, focus)
    }
    frontier = list(sorted(selected))
    while frontier:
        name = frontier.pop()
        summary = summaries_by_name.get(name)
        if summary is None:
            continue
        for callee in summary.callees:
            if callee in summaries_by_name and callee not in selected:
                selected.add(callee)
                frontier.append(callee)
    summaries = tuple(
        replace(
            summary,
            complete=not summary.gaps,
        )
        for summary in result.summaries
        if summary.qualified_name in selected
    )
    selected_raw_gaps = {
        gap
        for gap in result.gaps
        if (
            _summary_gap_is_focused(gap, focus)
            or (summaries and not gap.file)
        )
    }
    selected_raw_gaps.update(
        gap
        for summary in summaries
        for gap in summary.gaps
    )
    focused_gaps = {
        *selected_raw_gaps,
        *_missing_focused_summary_gaps(
            result,
            summaries,
            focus,
        ),
    }
    gaps = tuple(
        sorted(
            focused_gaps,
            key=lambda gap: gap.sort_key,
        )
    )
    metrics = {
        "call_edge_count": sum(
            len(summary.callees)
            for summary in summaries
        ),
        "effect_count": sum(
            len(summary.effects)
            for summary in summaries
        ),
        "excluded_out_of_focus_gap_count": (
            len(result.gaps) - len(selected_raw_gaps)
        ),
        "focused_scope": 1,
        "function_count": len(summaries),
        "gap_count": len(gaps),
    }
    return FunctionSummaryAnalysis(
        target=result.target,
        summaries=summaries,
        gaps=gaps,
        limits=result.limits,
        metrics=tuple(sorted(metrics.items())),
    )


def _summary_gap_is_focused(
    gap: AnalysisGap,
    focus: Mapping[str, FocusContext],
) -> bool:
    normalized = _normalize_path(gap.file)
    if not normalized or normalized not in focus:
        return False
    if not gap.function and gap.line is None:
        return True
    return _semantic_position_is_focused(
        normalized,
        gap.function,
        gap.line,
        focus,
    )


def _missing_focused_summary_gaps(
    result: FunctionSummaryAnalysis,
    summaries: tuple[FunctionSummary, ...],
    focus: Mapping[str, FocusContext],
) -> set[AnalysisGap]:
    represented = {
        (
            _normalize_path(summary.file),
            summary.qualified_name.rsplit(
                "::",
                maxsplit=1,
            )[-1].split(".")[-1],
        )
        for summary in summaries
    }
    gaps = set()
    for file, context in sorted(focus.items()):
        for function in sorted(context.functions):
            if (_normalize_path(file), function) in represented:
                continue
            gaps.add(
                AnalysisGap(
                    code="function_summary_focused_function_missing",
                    stage="summary_focus",
                    reason=(
                        "A function touched by the candidate patch was "
                        "not available in the bounded summary result"
                    ),
                    file=_normalize_path(file),
                    function=function,
                    limit_name="max_functions",
                    limit_value=result.limits.max_functions,
                    observed_value=dict(result.metrics).get(
                        "function_count",
                        0,
                    ),
                )
            )
    return gaps


def _summary_is_focused(
    summary: FunctionSummary,
    focus: Mapping[str, FocusContext],
) -> bool:
    scope_name = summary.qualified_name.rsplit("::", maxsplit=1)[-1]
    return _semantic_position_is_focused(
        summary.file,
        scope_name,
        min(
            (
                effect.line
                for effect in summary.effects
                if effect.line is not None
            ),
            default=None,
        ),
        focus,
    )


def _semantic_position_is_focused(
    file: str,
    function: str,
    line: int | None,
    focus: Mapping[str, FocusContext],
) -> bool:
    context = focus.get(_normalize_path(file))
    if context is None:
        return False
    scope_name = function.rsplit("::", maxsplit=1)[-1]
    pieces = scope_name.split(".") if scope_name else []
    name = pieces[-1] if pieces else ""
    class_name = ".".join(pieces[:-1])
    if name:
        if (class_name, name) in context.qualified_functions:
            return True
        if (
            not context.qualified_functions
            and name in context.functions
        ):
            return True
    return bool(
        line is not None
        and any(
            start <= line <= end
            for start, end in context.line_ranges
        )
    )


def _semantic_evidence_payload(
    mode: str,
    summary_results: Mapping[
        str,
        FunctionSummaryAnalysis | None,
    ],
    flow_results: Mapping[
        str,
        SemanticFlowAnalysis | None,
    ],
    focus_results: Mapping[
        str,
        Mapping[str, FocusContext],
    ],
    limits: EvidenceGraphLimits,
) -> tuple[dict[str, Any], SemanticComparison | None]:
    if mode not in _SEMANTIC_EVIDENCE_MODES:
        return (
            {
                "enabled": False,
                "mode": mode,
                "analysis_succeeded": True,
                "affects_verdict": False,
            },
            None,
        )
    baseline_flow = flow_results.get("vulnerable")
    candidate_flow = flow_results.get("fixed")
    if baseline_flow is None or candidate_flow is None:
        return (
            {
                "enabled": True,
                "mode": mode,
                "analysis_succeeded": False,
                "affects_verdict": True,
                "limits": limits.to_dict(),
                "errors": [
                    (
                        "semantic flow result unavailable for "
                        "before/after comparison"
                    )
                ],
            },
            None,
        )
    baseline_flow = _focused_flow_analysis(
        baseline_flow,
        focus_results.get("vulnerable", {}),
    )
    candidate_flow = _focused_flow_analysis(
        candidate_flow,
        focus_results.get("fixed", {}),
    )
    baseline_summaries = None
    candidate_summaries = None
    if mode == "full":
        raw_baseline_summaries = summary_results.get(
            "vulnerable"
        )
        raw_candidate_summaries = summary_results.get("fixed")
        if raw_baseline_summaries is not None:
            baseline_summaries = (
                _focused_summary_analysis(
                    raw_baseline_summaries,
                    focus_results.get("vulnerable", {}),
                )
            )
        if raw_candidate_summaries is not None:
            candidate_summaries = (
                _focused_summary_analysis(
                    raw_candidate_summaries,
                    focus_results.get("fixed", {}),
                )
            )
    baseline_graph = build_evidence_graph(
        baseline_flow,
        "baseline",
        summaries=baseline_summaries,
        limits=limits,
    )
    candidate_graph = build_evidence_graph(
        candidate_flow,
        "candidate",
        summaries=candidate_summaries,
        limits=limits,
    )
    comparison = compare_semantic_flows(
        baseline_flow,
        candidate_flow,
        baseline_summaries=baseline_summaries,
        candidate_summaries=candidate_summaries,
        graph_limits=limits,
    )
    return (
        {
            "enabled": True,
            "mode": mode,
            "analysis_succeeded": True,
            "affects_verdict": True,
            "limits": limits.to_dict(),
            "complete": comparison.complete,
            "explanation": _semantic_comparison_explanation(
                comparison
            ),
            "baseline_graph": baseline_graph.to_dict(),
            "candidate_graph": candidate_graph.to_dict(),
            "comparison": comparison.to_dict(),
        },
        comparison,
    )


def _semantic_comparison_explanation(
    comparison: SemanticComparison,
) -> str:
    metrics = dict(comparison.metrics)
    labels = []
    for classification in SemanticClassification:
        count = metrics.get(
            f"classification_{classification.value}",
            0,
        )
        if count:
            labels.append(
                f"{classification.value}={count}"
            )
    state = "complete" if comparison.complete else "incomplete"
    detail = ", ".join(labels) or "no semantic delta"
    return (
        f"Semantic comparison is {state}: {detail}; "
        f"analysis_gaps={len(comparison.gaps)}."
    )


def _classify_findings(
    baseline_rows: list[dict[str, Any]],
    candidate_rows: list[dict[str, Any]],
    comparison: SemanticComparison | None,
) -> tuple[
    list[dict[str, Any]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    baseline_keys = {
        _finding_identity(item)
        for item in baseline_rows
    }
    candidate_keys = {
        _finding_identity(item)
        for item in candidate_rows
    }
    candidate_semantic = {}
    baseline_semantic = {}
    if comparison is not None:
        for delta in comparison.deltas:
            classification = delta.classification.value
            if delta.candidate_concern:
                candidate_semantic[
                    delta.candidate_concern
                ] = classification
            if delta.baseline_concern:
                baseline_semantic[
                    delta.baseline_concern
                ] = classification

    introduced = []
    residual = []
    for item in candidate_rows:
        digest = str(
            item.get("semantic_concern_digest") or ""
        )
        classification = candidate_semantic.get(digest)
        if not classification:
            classification = (
                "residual"
                if _finding_identity(item) in baseline_keys
                else "introduced"
            )
        classified = {
            **item,
            "classification": classification,
        }
        if classification == "residual":
            residual.append(classified)
        else:
            introduced.append(classified)

    resolved = []
    for item in baseline_rows:
        digest = str(
            item.get("semantic_concern_digest") or ""
        )
        classification = baseline_semantic.get(digest)
        if classification:
            if classification == "resolved":
                resolved.append(
                    {
                        **item,
                        "classification": "resolved",
                    }
                )
            continue
        if _finding_identity(item) not in candidate_keys:
            resolved.append(
                {
                    **item,
                    "classification": "resolved",
                }
            )

    if comparison is not None:
        introduced.extend(
            _analysis_gap_finding(gap)
            for gap in comparison.gaps
        )
    return introduced, residual, resolved


def _analysis_gap_finding(
    gap: AnalysisGap,
) -> dict[str, Any]:
    return {
        "cwe": "CWE-693",
        "rule_id": "BELIEF-SEM-ANALYSIS-GAP",
        "title": "Semantic comparison is incomplete",
        "description": gap.reason,
        "severity": "medium",
        "confidence": 1.0,
        "file": _normalize_path(gap.file),
        "line": gap.line,
        "end_line": None,
        "function": gap.function,
        "class": "",
        "evidence": (
            f"{gap.stage}:{gap.code}: {gap.reason}"
        ),
        "semantic_analysis": True,
        "semantic_concern_digest": "",
        "root_cause_identity": {},
        "dataflow": {
            "source": "bounded_semantic_analysis",
            "sink": "candidate_verdict",
            "missing_guarantees": [
                "complete_semantic_evidence",
            ],
            "guarantees": [],
            "sanitizers": [],
        },
        "verdicts": ["needs_review"],
        "actionable": True,
        "classification": "inconclusive",
    }


def _focused_findings(
    result: Any,
    focus: Mapping[str, FocusContext],
    *,
    supplemental_findings: Iterable[Any] = (),
) -> list[dict[str, Any]]:
    findings = [
        finding
        for finding in (
            *(getattr(result, "findings", ()) or ()),
            *supplemental_findings,
        )
        if finding_is_focused(finding, focus)
        and str(getattr(finding, "cwe", "") or "").strip()
    ]
    cases_by_fingerprint: dict[str, set[str]] = {}
    for case in (getattr(result, "audit_cases", ()) or ()):
        fingerprint = str(
            getattr(case, "related_finding_fingerprint", "") or ""
        )
        verdict = _case_verdict(case)
        if fingerprint and verdict:
            cases_by_fingerprint.setdefault(fingerprint, set()).add(verdict)

    rows: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        metadata = getattr(finding, "metadata", {}) or {}
        dataflow = metadata.get("dataflow")
        if not isinstance(dataflow, Mapping):
            dataflow = {}
        verdicts = sorted(
            cases_by_fingerprint.get(
                str(getattr(finding, "fingerprint", "") or ""),
                set(),
            )
        )
        causal = bool(
            metadata.get("analysis_profile") == "patch_review"
            and dataflow.get("source")
            and dataflow.get("sink")
            and dataflow.get("missing_guarantees")
        )
        if causal and "weak_signal" not in verdicts:
            verdicts.append("weak_signal")
            verdicts.sort()
        row = {
            "cwe": str(getattr(finding, "cwe", "") or ""),
            "rule_id": str(getattr(finding, "rule_id", "") or ""),
            "title": str(getattr(finding, "title", "") or ""),
            "description": str(
                getattr(finding, "description", "") or ""
            ),
            "severity": str(getattr(finding, "severity", "") or ""),
            "confidence": round(
                float(getattr(finding, "confidence", 0.0) or 0.0),
                6,
            ),
            "file": _normalize_path(getattr(finding, "file", "")),
            "line": getattr(finding, "line", None),
            "end_line": getattr(finding, "end_line", None),
            "function": str(metadata.get("function_name") or ""),
            "class": str(metadata.get("class_name") or ""),
            "evidence": str(getattr(finding, "evidence", "") or ""),
            "semantic_analysis": bool(
                metadata.get("semantic_analysis")
            ),
            "semantic_concern_digest": str(
                metadata.get("semantic_concern_digest") or ""
            ),
            "root_cause_identity": (
                dict(metadata["root_cause_identity"])
                if isinstance(
                    metadata.get("root_cause_identity"),
                    Mapping,
                )
                else {}
            ),
            "dataflow": {
                key: dataflow[key]
                for key in (
                    "source",
                    "sink",
                    "missing_guarantees",
                    "sanitizers",
                    "guarantees",
                )
                if key in dataflow
            },
            "verdicts": verdicts,
            "actionable": bool(
                causal or set(verdicts).intersection(SURFACED_VERDICTS)
            ),
        }
        key = (
            row["cwe"],
            row["rule_id"],
            row["file"],
            row["line"],
            row["function"],
            row["class"],
        )
        rows.setdefault(key, row)
    return sorted(
        rows.values(),
        key=lambda item: (
            item["file"],
            item["line"] or 0,
            item["cwe"],
            item["rule_id"],
        ),
    )


def _finding_identity(row: Mapping[str, Any]) -> tuple[str, ...]:
    dataflow = row.get("dataflow")
    sink = ""
    if isinstance(dataflow, Mapping):
        sink = str(dataflow.get("sink") or "")
    return (
        str(row.get("cwe") or ""),
        str(row.get("rule_id") or ""),
        str(row.get("file") or ""),
        str(row.get("class") or ""),
        str(row.get("function") or ""),
        sink,
    )


def _render_feedback(findings: Iterable[Mapping[str, Any]]) -> str:
    rows = list(findings)
    if not rows:
        return (
            "BELIEF found no actionable security-boundary finding in the "
            "candidate Python diff. This is static evidence only; rerun the "
            "project's functional and security tests before finishing."
        )
    lines = [
        (
            "BELIEF found actionable security-boundary risks in the candidate "
            "diff. Re-review and repair them without looking up an upstream "
            "fix, then rerun the relevant tests:"
        )
    ]
    for row in rows:
        dataflow = row.get("dataflow")
        missing = []
        if isinstance(dataflow, Mapping):
            raw_missing = dataflow.get("missing_guarantees", [])
            if isinstance(raw_missing, (list, tuple, set)):
                missing = [str(value) for value in raw_missing]
            elif raw_missing:
                missing = [str(raw_missing)]
        location = str(row.get("file") or "")
        if row.get("line") is not None:
            location += f":{row['line']}"
        scope = str(row.get("function") or "")
        detail = "; ".join(missing) or str(
            row.get("description") or row.get("title") or ""
        )
        classification = str(row.get("classification") or "candidate")
        lines.append(
            f"- [{row.get('cwe')}] {location}"
            f"{f' ({scope})' if scope else ''}: "
            f"{classification}; missing security guarantee: {detail}"
        )
    lines.append(
        "Keep the implementation minimal and preserve the requested "
        "functional behavior."
    )
    return "\n".join(lines)


def _source_for_state(
    root: Path,
    diff_file: DiffFile,
    state: str,
) -> str | None:
    if state == "vulnerable":
        relative = diff_file.old_path
        if not relative:
            return None
        result = _git_completed(root, "cat-file", "blob", f"HEAD:{relative}")
        if result.returncode:
            return None
        return result.stdout.decode("utf-8", errors="strict")

    relative = diff_file.new_path
    if not relative:
        return None
    candidate = root / Path(*PurePosixPath(relative).parts)
    if candidate.is_symlink():
        raise ValueError(f"candidate Python file must not be a symlink: {relative}")
    if not candidate.exists():
        return None
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(
            f"candidate Python file escapes repository root: {relative}"
        ) from exc
    if not resolved.is_file():
        return None
    return resolved.read_text(encoding="utf-8")


def _is_test_path(value: str) -> bool:
    path = PurePosixPath(value)
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    return bool(
        any(part.startswith("test") for part in parts)
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _repository_root(target: str | Path) -> Path:
    root = Path(target).resolve()
    if not root.is_dir():
        raise ValueError(f"candidate target is not a directory: {root}")
    result = _git_completed(root, "rev-parse", "--show-toplevel")
    if result.returncode:
        _raise_git_error(result, "resolve repository root")
    resolved = Path(
        result.stdout.decode("utf-8", errors="strict").strip()
    ).resolve()
    if resolved != root:
        raise ValueError(
            "candidate target must be the Git repository root: "
            f"expected {resolved}, got {root}"
        )
    return root


def _safe_relative_path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
    ):
        raise ValueError(f"unsafe Git path: {value}")
    return path.as_posix()


def _safe_destination(root: Path, relative: str) -> Path:
    normalized = _safe_relative_path(relative)
    destination = root.joinpath(*PurePosixPath(normalized).parts)
    resolved_root = root.resolve()
    resolved_destination = destination.resolve()
    try:
        resolved_destination.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"unsafe materialization path: {relative}") from exc
    return destination


def _normalize_path(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def _case_verdict(case: Any) -> str:
    return assess_audit_case_reportability(case).verdict


def _git(
    root: Path,
    *arguments: str,
    decode: bool = True,
) -> str | bytes:
    result = _git_completed(root, *arguments)
    if result.returncode:
        _raise_git_error(result, " ".join(arguments[:2]))
    if not decode:
        return result.stdout
    return result.stdout.decode("utf-8", errors="replace")


def _git_completed(
    root: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.update(_GIT_ENV_OVERRIDES)
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=30,
    )


def _raise_git_error(
    result: subprocess.CompletedProcess[bytes],
    operation: str,
) -> None:
    error = result.stderr.decode("utf-8", errors="replace").strip()
    raise ValueError(f"Git failed to {operation}: {error or result.returncode}")


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key not in {"target", "duration_seconds", "deterministic_digest"}
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "CANDIDATE_PATCH_REVIEW_SCHEMA_VERSION",
    "SEMANTIC_REVIEW_MODES",
    "collect_worktree_patch",
    "review_candidate_patch",
    "write_candidate_patch_review_json",
]
