"""Reusable, deterministic, offline static-analysis pipeline.

The CLI, benchmarks, and other Python callers share this orchestration layer.
It deliberately contains no console output, process exits, or network access.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import Belief, Finding, _json_safe


STATIC_ANALYSIS_RESULT_SCHEMA_VERSION = "belief.static_analysis_result.v1"
STATIC_ANALYSIS_CATEGORIES = ("structural", "security", "taint", "temporal", "cycles")


@dataclass(frozen=True)
class ScanRecord:
    """A finding together with the scanner family that produced it."""

    category: str
    finding: Finding


@dataclass(frozen=True)
class StaticAnalysisDiagnostic:
    """A deterministic explanation of incomplete or rejected analysis work."""

    code: str
    message: str
    file: str = ""
    line: int | None = None
    function: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "message": self.message,
        }
        if self.file:
            payload["file"] = self.file
        if self.line is not None:
            payload["line"] = self.line
        if self.function:
            payload["function"] = self.function
        if self.details:
            payload["details"] = _json_safe(self.details)
        return payload


@dataclass(frozen=True)
class StaticAnalysisOptions:
    """Options for one local static-analysis run.

    Defaults retain the lightweight historical ``belief scan`` behaviour.
    Features that build hypotheses or audit cases remain opt-in.
    """

    max_files: int = 200
    selected_categories: frozenset[str] = field(
        default_factory=lambda: frozenset(STATIC_ANALYSIS_CATEGORIES)
    )
    min_confidence: float = 0.0
    hide_structural: bool = False
    include_cycles: bool = False
    max_cycles: int = 100
    include_hypotheses: bool = False
    include_guarantees: bool = False
    show_proofs: bool = False
    only_hypotheses: str = "all"
    include_dataflow: bool = False
    show_dataflow: bool = False
    max_dataflow_depth: int = 32
    max_dataflow_nodes: int = 10_000
    dataflow_cycle_detection: bool = True
    security_analysis_profile: str = "default"
    legacy_single_file_path_projection: bool = False
    include_audit_cases: bool = False
    audit_mode: bool = False
    interesting_only: bool = False
    include_routes: bool = False
    import_tool_results: tuple[str, ...] = ()
    reportability: bool = False
    min_reportability_score: int = 0
    only_reportable: bool = False
    dedup_audit_cases: bool = False

    @property
    def hypotheses_enabled(self) -> bool:
        return self.include_hypotheses or self.show_proofs or self.audit_mode

    @property
    def guarantees_enabled(self) -> bool:
        return self.include_guarantees or self.hypotheses_enabled

    @property
    def dataflow_enabled(self) -> bool:
        return self.include_dataflow or self.show_dataflow or self.audit_mode

    @property
    def routes_enabled(self) -> bool:
        return self.include_routes

    @property
    def audit_cases_enabled(self) -> bool:
        return (
            self.include_audit_cases
            or self.audit_mode
            or self.interesting_only
            or bool(self.import_tool_results)
            or self.reportability
            or self.dedup_audit_cases
        )


@dataclass
class StaticAnalysisResult:
    """Structured output returned to every static-analysis consumer."""

    target: str
    files: tuple[Path, ...] = ()
    records: tuple[ScanRecord, ...] = ()
    filtered_records: tuple[ScanRecord, ...] = ()
    totals: dict[str, int] = field(default_factory=dict)
    hypotheses: tuple[dict[str, Any], ...] = ()
    dataflow_summaries: dict[str, Any] = field(default_factory=dict)
    dataflow_paths: tuple[Any, ...] = ()
    routes: tuple[Any, ...] = ()
    guarantees: tuple[Belief, ...] = ()
    audit_cases: tuple[Any, ...] = ()
    audit_case_clusters: tuple[dict[str, Any], ...] = ()
    guarantee_summary: dict[str, int] = field(default_factory=dict)
    imported_tool_results: tuple[Any, ...] = ()
    cycle_metadata: dict[str, Any] | None = None
    diagnostics: tuple[StaticAnalysisDiagnostic, ...] = ()

    @property
    def files_scanned(self) -> int:
        return len(self.files)

    @property
    def findings(self) -> list[Finding]:
        return [record.finding for record in self.filtered_records]

    @property
    def all_findings(self) -> list[Finding]:
        return [record.finding for record in self.records]

    def to_dict(self) -> dict[str, Any]:
        """Return a stable semantic representation (with no elapsed time)."""

        return {
            "schema_version": STATIC_ANALYSIS_RESULT_SCHEMA_VERSION,
            "target": self.target,
            "files": [_normalized_path(path) for path in self.files],
            "totals": dict(sorted(self.totals.items())),
            "findings": [
                _finding_to_dict(record.finding, record.category)
                for record in self.filtered_records
            ],
            "hypotheses": [_json_safe(item) for item in self.hypotheses],
            "dataflow_paths": [path.to_dict() for path in self.dataflow_paths],
            "routes": [route.to_dict() for route in self.routes],
            "guarantees": [guarantee.to_dict() for guarantee in self.guarantees],
            "audit_cases": [case.to_dict() for case in self.audit_cases],
            "audit_case_clusters": [_json_safe(item) for item in self.audit_case_clusters],
            "guarantee_summary": dict(sorted(self.guarantee_summary.items())),
            "diagnostics": [item.to_dict() for item in self.diagnostics],
        }


class StaticAnalysisPipeline:
    """High-level service for an entirely local BELIEF static scan."""

    def analyze(
        self,
        target: str | Path,
        options: StaticAnalysisOptions | None = None,
    ) -> StaticAnalysisResult:
        return analyze_static_target(target, options)


def analyze_static_target(
    target: str | Path,
    options: StaticAnalysisOptions | None = None,
) -> StaticAnalysisResult:
    """Analyze a local file or directory without CLI or network side effects."""

    from .audit_case import (
        attach_route_context_to_audit_cases,
        build_audit_cases,
        summarize_guarantees,
    )
    from .parser import CodeParser
    from .security_patterns import SecurityPatternExtractor
    from .structural import StructuralExtractor
    from .taint import TaintEngine
    from .temporal import TemporalChecker

    opts = options or StaticAnalysisOptions()
    _validate_options(opts)
    target_path = Path(target)
    parser = CodeParser(str(target_path))
    files = tuple(parser._collect_python_files()[: opts.max_files])

    routes: list[Any] = []
    if opts.routes_enabled:
        from .routes import extract_routes_from_files

        route_root = target_path if target_path.is_dir() else (
            target_path.parent
            if opts.legacy_single_file_path_projection
            else None
        )
        routes = extract_routes_from_files(files, target_root=route_root)

    structural = StructuralExtractor()
    security = SecurityPatternExtractor(
        analysis_profile=opts.security_analysis_profile,
    )
    taint = TaintEngine(
        max_depth=opts.max_dataflow_depth,
        max_nodes=opts.max_dataflow_nodes,
        cycle_detection=opts.dataflow_cycle_detection,
    )
    temporal = TemporalChecker()
    invariant_miner = None
    if opts.guarantees_enabled:
        from .invariant_miner import InvariantMiner

        invariant_miner = InvariantMiner()

    totals = {name: 0 for name in ("structural", "security", "taint", "temporal")}
    records: list[ScanRecord] = []
    guarantees: list[Belief] = []
    source_contexts: dict[str, str] = {}
    dataflow_summaries: dict[str, Any] = {}
    diagnostics: list[StaticAnalysisDiagnostic] = []

    for file_path in files:
        relative = _target_relative_path(file_path, target_path)
        try:
            source = file_path.read_text(errors="replace")
        except OSError as exc:
            diagnostics.append(StaticAnalysisDiagnostic(
                code="source_read_failed",
                message=str(exc),
                file=relative,
            ))
            continue

        source_contexts[relative] = source
        if opts.dataflow_enabled:
            summary = _analyze_dataflow(source, relative, opts)
            dataflow_summaries[relative] = summary
            diagnostics.extend(_dataflow_diagnostics(summary, relative))
        if invariant_miner is not None:
            guarantees.extend(invariant_miner.extract(source, relative))

        structural_beliefs = structural.extract(source, relative)
        security_beliefs = security.extract(source, relative)
        taint_beliefs = taint.analyze_to_beliefs(source, relative)
        diagnostics.extend(_analysis_diagnostics(taint.diagnostics, relative))
        temporal_beliefs = temporal.check(source, relative)
        for category, beliefs in (
            ("structural", structural_beliefs),
            ("security", security_beliefs),
            ("taint", taint_beliefs),
            ("temporal", temporal_beliefs),
        ):
            totals[category] += len(beliefs)
            records.extend(_beliefs_to_records(category, beliefs))

    cycle_metadata = None
    if opts.include_cycles:
        from .cycle_detector import detect_cycle_findings_with_metadata

        parser.parse()
        cycle_findings, cycle_metadata = detect_cycle_findings_with_metadata(
            parser.call_graph,
            max_cycles=opts.max_cycles,
        )
        totals["cycles"] = len(cycle_findings)
        records.extend(
            ScanRecord("cycles", _with_category(finding, "cycles"))
            for finding in cycle_findings
        )
    elif (
        "cycles" in opts.selected_categories
        and set(opts.selected_categories) != set(STATIC_ANALYSIS_CATEGORIES)
    ):
        diagnostics.append(StaticAnalysisDiagnostic(
            code="cycle_analysis_not_enabled",
            message="Cycle findings were requested by category but cycle analysis is disabled.",
        ))

    imported_results: list[Any] = []
    imported_cases: list[Any] = []
    if opts.import_tool_results:
        imported_results, imported_findings, imported_cases = _load_tool_results(
            opts.import_tool_results
        )
        totals["security"] += len(imported_findings)
        records.extend(
            ScanRecord("security", _with_category(finding, "security"))
            for finding in imported_findings
        )

    if opts.dataflow_enabled:
        from .dataflow import attach_dataflow_to_findings

        attach_dataflow_to_findings(
            [record.finding for record in records],
            dataflow_summaries,
            show_dataflow=opts.show_dataflow,
        )

    if opts.hypotheses_enabled:
        from .guarantee_index import build_guarantee_index
        from .hypothesis_engine import attach_hypotheses_to_findings

        guarantee_root = target_path if (
            target_path.is_dir() or opts.legacy_single_file_path_projection
        ) else None
        guarantee_index = build_guarantee_index(files, target_root=guarantee_root)
        guarantees = _dedupe_beliefs([*guarantees, *guarantee_index.all_guarantees])
        attach_hypotheses_to_findings(
            [record.finding for record in records],
            guarantees,
            show_proofs=opts.show_proofs,
            guarantee_index=guarantee_index,
            local_contexts=source_contexts,
            dataflow_summaries=dataflow_summaries if opts.dataflow_enabled else None,
            show_dataflow=opts.show_dataflow,
        )
    else:
        guarantees = _dedupe_beliefs(guarantees)

    filtered_records = _filter_records(records, opts)
    audit_cases: list[Any] = []
    cluster_payload: list[dict[str, Any]] = []
    guarantee_summary: dict[str, int] = {}
    if opts.audit_cases_enabled:
        audit_cases = build_audit_cases(
            [record.finding for record in records],
            dataflow_summaries=dataflow_summaries if opts.dataflow_enabled else None,
        )
        if opts.routes_enabled:
            audit_cases = attach_route_context_to_audit_cases(
                audit_cases,
                routes,
                source_contexts=source_contexts,
            )
        if imported_cases:
            from .tool_results.merger import merge_audit_cases

            audit_cases = merge_audit_cases([*audit_cases, *imported_cases])
        guarantee_summary = summarize_guarantees(guarantees)
        if opts.dedup_audit_cases:
            from .audit_dedup import cluster_audit_cases, cluster_to_dict

            clusters = cluster_audit_cases(audit_cases)
            audit_cases = [cluster["representative"] for cluster in clusters]
            cluster_payload = [cluster_to_dict(cluster) for cluster in clusters]
        if opts.reportability:
            audit_cases = _apply_reportability(audit_cases, opts)

    dataflow_paths = sorted(
        (
            path
            for summary in dataflow_summaries.values()
            for path in summary.paths
        ),
        key=_dataflow_path_sort_key,
    )
    hypotheses = tuple(
        hypothesis
        for record in records
        for hypothesis in [_finding_hypothesis(record.finding)]
        if hypothesis is not None
    )
    return StaticAnalysisResult(
        target=str(target_path),
        files=files,
        records=tuple(records),
        filtered_records=tuple(filtered_records),
        totals=totals,
        hypotheses=hypotheses,
        dataflow_summaries=dataflow_summaries,
        dataflow_paths=tuple(dataflow_paths),
        routes=tuple(routes),
        guarantees=tuple(guarantees),
        audit_cases=tuple(audit_cases),
        audit_case_clusters=tuple(cluster_payload),
        guarantee_summary=guarantee_summary,
        imported_tool_results=tuple(imported_results),
        cycle_metadata=cycle_metadata,
        diagnostics=tuple(_dedupe_diagnostics(diagnostics)),
    )


def filter_scan_records(
    records: Iterable[ScanRecord],
    *,
    selected_categories: Iterable[str],
    min_confidence: float,
    hide_structural: bool,
    only_hypothesis_status: str = "all",
) -> list[ScanRecord]:
    """Compatibility-friendly deterministic finding filter."""

    categories = set(selected_categories)
    if hide_structural:
        categories.discard("structural")
    status_filter = (only_hypothesis_status or "all").strip().lower()
    return [
        record
        for record in records
        if record.category in categories
        and float(getattr(record.finding, "confidence", 0.0)) >= min_confidence
        and (
            status_filter == "all"
            or (
                (hypothesis := _finding_hypothesis(record.finding)) is not None
                and hypothesis.get("status") == status_filter
            )
        )
    ]


def sort_scan_records(records: Iterable[ScanRecord]) -> list[ScanRecord]:
    return sorted(records, key=_scan_record_sort_key)


def dedupe_scan_records(records: Iterable[ScanRecord]) -> list[ScanRecord]:
    seen: set[tuple[Any, ...]] = set()
    result: list[ScanRecord] = []
    for record in records:
        key = scan_record_dedup_key(record)
        if key not in seen:
            seen.add(key)
            result.append(record)
    return result


def scan_record_dedup_key(record: ScanRecord) -> tuple[Any, ...]:
    import re

    finding = record.finding
    file = str(getattr(finding, "file", ""))
    line = getattr(finding, "line", None)
    rule_id = str(getattr(finding, "rule_id", ""))
    dedup_key = str(getattr(finding, "dedup_key", ""))
    if dedup_key:
        return file, line, rule_id, dedup_key
    fallback = " ".join([
        str(getattr(finding, "evidence", "")),
        str(getattr(finding, "title", "")),
        str(getattr(finding, "description", "")),
    ])
    return file, line, rule_id, re.sub(r"\s+", " ", fallback).strip().lower()


def _validate_options(options: StaticAnalysisOptions) -> None:
    invalid = sorted(set(options.selected_categories) - set(STATIC_ANALYSIS_CATEGORIES))
    if invalid:
        raise ValueError(f"invalid static-analysis categories: {', '.join(invalid)}")
    if options.max_files < 0:
        raise ValueError("max_files must be non-negative")
    if options.max_cycles < 0:
        raise ValueError("max_cycles must be non-negative")
    if options.max_dataflow_depth < 0:
        raise ValueError("max_dataflow_depth must be non-negative")
    if options.max_dataflow_nodes < 0:
        raise ValueError("max_dataflow_nodes must be non-negative")
    if options.security_analysis_profile not in {"default", "patch_review"}:
        raise ValueError(
            "security_analysis_profile must be one of: default, patch_review"
        )
    if not 0.0 <= options.min_confidence <= 1.0:
        raise ValueError("min_confidence must be between 0 and 1")
    if options.only_hypotheses not in {
        "all", "unproven", "weakened", "strengthened", "contradicted"
    }:
        raise ValueError(f"invalid hypothesis status: {options.only_hypotheses}")


def _analyze_dataflow(source: str, relative: str, options: StaticAnalysisOptions) -> Any:
    from .dataflow import analyze_source_dataflow

    return analyze_source_dataflow(
        source,
        relative,
        max_depth=options.max_dataflow_depth,
        max_nodes=options.max_dataflow_nodes,
        cycle_detection=options.dataflow_cycle_detection,
    )


def _dataflow_diagnostics(summary: Any, file: str) -> list[StaticAnalysisDiagnostic]:
    return _analysis_diagnostics(getattr(summary, "diagnostics", ()) or (), file)


def _analysis_diagnostics(
    diagnostics: Iterable[Any],
    file: str,
) -> list[StaticAnalysisDiagnostic]:
    result = []
    for item in diagnostics:
        if isinstance(item, StaticAnalysisDiagnostic):
            result.append(item)
            continue
        if isinstance(item, str):
            result.append(StaticAnalysisDiagnostic(code=item, message=item, file=file))
            continue
        if isinstance(item, dict):
            code = str(item.get("code") or item.get("reason") or "dataflow_diagnostic")
            result.append(StaticAnalysisDiagnostic(
                code=code,
                message=str(item.get("message") or code),
                file=str(item.get("file") or file),
                line=item.get("line"),
                function=str(item.get("function") or ""),
                details={
                    key: value
                    for key, value in item.items()
                    if key not in {"code", "reason", "message", "file", "line", "function"}
                },
            ))
    return result


def _beliefs_to_records(category: str, beliefs: Iterable[Belief]) -> list[ScanRecord]:
    return [
        ScanRecord(
            category,
            _with_category(Finding.from_belief(belief, source=category), category),
        )
        for belief in beliefs
    ]


def _with_category(finding: Finding, category: str) -> Finding:
    metadata = dict(getattr(finding, "metadata", {}) or {})
    metadata.setdefault("category", category)
    finding.metadata = metadata
    return finding


def _filter_records(records: Iterable[ScanRecord], options: StaticAnalysisOptions) -> list[ScanRecord]:
    return filter_scan_records(
        records,
        selected_categories=options.selected_categories,
        min_confidence=options.min_confidence,
        hide_structural=options.hide_structural,
        only_hypothesis_status=(options.only_hypotheses if options.hypotheses_enabled else "all"),
    )


def _load_tool_results(paths: Iterable[str]) -> tuple[list[Any], list[Finding], list[Any]]:
    from .tool_results.io import read_many_normalized_tool_results
    from .tool_results.mapper import normalized_result_to_audit_cases, normalized_result_to_findings
    from .tool_results.models import ToolResultSchemaError

    try:
        results = read_many_normalized_tool_results([Path(path) for path in paths])
    except (OSError, ToolResultSchemaError) as exc:
        raise ValueError(f"failed to import normalized tool results: {exc}") from exc
    findings: list[Finding] = []
    audit_cases: list[Any] = []
    for result in results:
        findings.extend(normalized_result_to_findings(result))
        audit_cases.extend(normalized_result_to_audit_cases(result))
    return results, findings, audit_cases


def _apply_reportability(cases: list[Any], options: StaticAnalysisOptions) -> list[Any]:
    from .reportability.scoring import attach_reportability_to_cases

    assessed = attach_reportability_to_cases(cases)
    if options.min_reportability_score:
        assessed = [
            case for case in assessed
            if _case_reportability(case).get("score", 0) >= options.min_reportability_score
        ]
    if options.only_reportable:
        allowed = {"reportable_candidate", "needs_manual_validation"}
        assessed = [
            case for case in assessed
            if _case_reportability(case).get("verdict") in allowed
        ]
    return assessed


def _case_reportability(case: Any) -> dict[str, Any]:
    metadata = getattr(case, "metadata", None)
    if not isinstance(metadata, dict):
        return {}
    reportability = metadata.get("reportability")
    return reportability if isinstance(reportability, dict) else {}


def _finding_hypothesis(finding: Finding) -> dict[str, Any] | None:
    metadata = getattr(finding, "metadata", None)
    if not isinstance(metadata, dict):
        return None
    hypothesis = metadata.get("hypothesis")
    return hypothesis if isinstance(hypothesis, dict) else None


def _dedupe_beliefs(beliefs: Iterable[Belief]) -> list[Belief]:
    seen: set[tuple[str, str]] = set()
    result = []
    for belief in beliefs:
        belief_id = str(getattr(belief, "id", "") or "")
        metadata = getattr(belief, "source_metadata", {}) or {}
        key = (belief_id, str(metadata.get("propagated_via") or ""))
        if belief_id and key in seen:
            continue
        if belief_id:
            seen.add(key)
        result.append(belief)
    return result


def _dedupe_diagnostics(
    diagnostics: Iterable[StaticAnalysisDiagnostic],
) -> list[StaticAnalysisDiagnostic]:
    unique: dict[tuple[Any, ...], StaticAnalysisDiagnostic] = {}
    for item in diagnostics:
        key = (item.code, item.file, item.line or 0, item.function, item.message)
        unique.setdefault(key, item)
    return [unique[key] for key in sorted(unique)]


def _scan_record_sort_key(record: ScanRecord) -> tuple[Any, ...]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    finding = record.finding
    return (
        -float(getattr(finding, "confidence", 0.0)),
        severity_order.get(str(getattr(finding, "severity", "info")).lower(), 9),
        record.category,
        str(getattr(finding, "file", "")),
        getattr(finding, "line", None) or 0,
        str(getattr(finding, "rule_id", "")),
        str(getattr(finding, "dedup_key", "")),
    )


def _dataflow_path_sort_key(path: Any) -> tuple[Any, ...]:
    return (
        str(getattr(path, "file_path", "")),
        str(getattr(path, "function_name", "")),
        getattr(path, "sink_line", None) or 0,
        getattr(path, "source_line", None) or 0,
        str(getattr(getattr(path, "sink", None), "expression", "")),
        str(getattr(getattr(path, "source", None), "expression", "")),
    )


def _target_relative_path(file_path: Path, target: Path) -> str:
    if target.is_dir():
        return str(file_path.relative_to(target))
    return str(file_path)


def _normalized_path(path: str | Path) -> str:
    return str(path).replace("\\", "/")


def _finding_to_dict(finding: Finding, category: str) -> dict[str, Any]:
    payload = finding.to_dict()
    payload.setdefault("category", category)
    return payload


__all__ = [
    "STATIC_ANALYSIS_CATEGORIES",
    "STATIC_ANALYSIS_RESULT_SCHEMA_VERSION",
    "ScanRecord",
    "StaticAnalysisDiagnostic",
    "StaticAnalysisOptions",
    "StaticAnalysisPipeline",
    "StaticAnalysisResult",
    "analyze_static_target",
    "dedupe_scan_records",
    "filter_scan_records",
    "scan_record_dedup_key",
    "sort_scan_records",
]
