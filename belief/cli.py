"""
BELIEF — Command-line interface.

Usage:
    belief analyze <project_path> [--output <dir>] [--max-frontiers <n>]
    belief frontier <file_a> <file_b> [--func-a <name>] [--func-b <name>]
    belief report <json_path>
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from xml.etree import ElementTree as ET
from pathlib import Path
from typing import Any, Optional

from .config import BeliefConfig
from .orchestrator import Orchestrator
from .static_analysis_pipeline import ScanRecord


_ASCII_FALLBACKS = str.maketrans({
    "→": "->",
    "—": "-",
    "–": "-",
    "│": "|",
    "└": "`",
    "─": "-",
    "✓": "OK",
    "✅": "OK",
    "❌": "X",
    "⚠": "!",
    "\ufe0f": "",
})


def _safe_text(text: str, stream=None) -> str:
    stream = stream or sys.stdout
    encoding = getattr(stream, "encoding", None) or "utf-8"
    try:
        text.encode(encoding)
        return text
    except UnicodeEncodeError:
        fallback = text.translate(_ASCII_FALLBACKS)
        return fallback.encode(encoding, errors="replace").decode(encoding)


def safe_print(*values, sep: str = " ", end: str = "\n", file=None, flush: bool = False):
    stream = file or sys.stdout
    text = sep.join(str(v) for v in values) + end
    stream.write(_safe_text(text, stream))
    if flush:
        stream.flush()


class SafeArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that degrades Unicode help text on narrow encodings."""

    def _print_message(self, message, file=None):
        if message:
            stream = file or sys.stderr
            stream.write(_safe_text(message, stream))


SCAN_SCHEMA_VERSION = "belief.scan.filtered.v1"
SCAN_CATEGORIES = ("structural", "security", "taint", "temporal", "cycles")
SCAN_CATEGORY_SET = set(SCAN_CATEGORIES)


def setup_logging(verbose: bool = True):
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def cmd_analyze(args):
    """Run full BELIEF analysis on a project."""
    project_path = Path(args.project_path)
    if not project_path.exists():
        print(f"ERROR: Project path does not exist: {project_path}")
        sys.exit(1)
    if not project_path.is_dir():
        print(f"ERROR: Project path is not a directory: {project_path}")
        sys.exit(1)

    config = BeliefConfig.from_env()
    config.verbose = args.verbose
    config.output_dir = args.output

    if not config.providers:
        print("ERROR: No LLM providers configured.")
        print("Set up at least one of:")
        print("  - Ollama running locally (ollama serve)")
        print("  - GROQ_API_KEY environment variable")
        print("  - GOOGLE_AI_KEY environment variable")
        sys.exit(1)

    setup_logging(args.verbose)

    Path(args.output).mkdir(parents=True, exist_ok=True)

    with Orchestrator(config) as orch:
        # Parse --exclude into a set of directory names
        extra_excludes = None
        if hasattr(args, 'exclude') and args.exclude:
            extra_excludes = set(args.exclude.split(","))

        report = orch.analyze_project(
            project_path=args.project_path,
            project_name=args.name or "",
            max_frontiers=args.max_frontiers,
            exclude_dirs=extra_excludes,
        )

        # Save report
        output_path = Path(args.output) / "belief_report.json"
        report.save(str(output_path))
        print(f"\nReport saved to: {output_path}")

        # Print summary
        print("\n" + "=" * 60)
        print(f"  BELIEF Analysis: {report.project_name}")
        print("=" * 60)
        print(f"  Beliefs extracted:      {len(report.beliefs)}")
        print(f"  Frontiers analyzed:     {len(report.frontiers)}")
        print(f"  Conflicts detected:     {len(report.conflicts)}")
        print(f"  Drift events:           {len(report.drift_events)}")
        print(f"  Incomprehensible zones: {len(report.incomprehensible_zones)}")
        print(f"  Cognitive debt:         {report.cognitive_debt:.1%}")
        print(f"  Mean fragility:         {report.mean_fragility:.3f}")
        print()

        # Print top conflicts
        if report.conflicts:
            print("Top conflicts:")
            for c in sorted(
                report.conflicts,
                key=lambda x: ["critical", "high", "medium", "low", "info"].index(x.severity.value),
            )[:5]:
                print(f"  [{c.severity.value.upper()}] {c.description[:100]}")
            print()

        # Epistemic health
        print("Epistemic health distribution:")
        for cat, info in report.epistemic_health.items():
            bar = "#" * int(info["percent"] / 2)
            print(f"  {cat}: {info['count']:3d} ({info['percent']:5.1f}%) {bar}")


def cmd_frontier(args):
    """Analyze a single frontier between two code files."""
    for fpath in [args.file_a, args.file_b]:
        if not Path(fpath).exists():
            print(f"ERROR: File does not exist: {fpath}")
            sys.exit(1)

    config = BeliefConfig.from_env()
    setup_logging(args.verbose)

    code_a = Path(args.file_a).read_text(encoding="utf-8", errors="replace")
    code_b = Path(args.file_b).read_text(encoding="utf-8", errors="replace")

    with Orchestrator(config) as orch:
        result = orch.analyze_single_frontier(
            code_a=code_a,
            code_b=code_b,
            name_a=args.func_a or Path(args.file_a).stem,
            name_b=args.func_b or Path(args.file_b).stem,
            file_path=args.file_a,
        )

        print(json.dumps(result, indent=2))


def cmd_report(args):
    """Display a saved BELIEF report."""
    from .models import AnalysisReport

    report = AnalysisReport.load(args.json_path)
    print(json.dumps(report.to_dict(), indent=2))


def cmd_hunt(args):
    """Run aggressive zero-day hunt on a target."""
    from .hunter import ZeroDayHunter

    setup_logging(args.verbose)
    hunter = ZeroDayHunter()
    result = hunter.hunt(args.target_path, max_files=args.max_files)
    print(result.summary())

    if args.output:
        Path(args.output).mkdir(parents=True, exist_ok=True)
        out = Path(args.output) / "hunt_result.json"
        import json as _json
        out.write_text(_json.dumps({
            "target": result.target_path,
            "files_scanned": result.files_scanned,
            "total_beliefs": result.total_beliefs,
            "critical": len(result.critical_findings),
            "high": len(result.high_findings),
            "medium": len(result.medium_findings),
            "beliefs": [b.to_dict() for b in result.all_beliefs[:200]],
        }, indent=2))
        print(f"\nResults saved to: {out}")


def cmd_scan(args):
    """Quick structural + security scan (no LLM needed)."""
    from .static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target

    setup_logging(args.verbose)
    target = Path(args.target_path)
    try:
        selected_categories = _parse_scan_only(args.only)
    except ValueError as exc:
        safe_print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    if getattr(args, "audit_mode", False) and getattr(args, "only", "all") == "all":
        selected_categories = {"security", "taint"}
    options = StaticAnalysisOptions(
        max_files=int(args.max_files),
        selected_categories=frozenset(selected_categories),
        min_confidence=float(args.min_confidence),
        hide_structural=bool(args.hide_structural),
        include_cycles=bool(getattr(args, "include_cycles", False)),
        max_cycles=int(args.max_cycles),
        include_hypotheses=_scan_hypotheses_enabled(args),
        include_guarantees=_scan_hypotheses_enabled(args),
        show_proofs=bool(getattr(args, "show_proofs", False)),
        only_hypotheses=str(getattr(args, "only_hypotheses", "all")),
        include_dataflow=_scan_dataflow_enabled(args),
        show_dataflow=bool(getattr(args, "show_dataflow", False)),
        legacy_single_file_path_projection=True,
        include_audit_cases=_scan_audit_cases_enabled(args),
        audit_mode=bool(getattr(args, "audit_mode", False)),
        interesting_only=bool(getattr(args, "interesting_only", False)),
        include_routes=_scan_routes_enabled(args),
        import_tool_results=tuple(
            str(path) for path in (getattr(args, "import_tool_results", None) or [])
        ),
        reportability=_scan_reportability_enabled(args),
        min_reportability_score=int(getattr(args, "min_reportability_score", 0) or 0),
        only_reportable=bool(getattr(args, "only_reportable", False)),
        dedup_audit_cases=bool(getattr(args, "dedup_audit_cases", False)),
    )
    try:
        result = analyze_static_target(target, options)
    except ValueError as exc:
        safe_print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)

    files = list(result.files)
    routes = list(result.routes)
    total = dict(result.totals)
    scan_records = list(result.records)
    filtered_records = list(result.filtered_records)
    invariant_beliefs = list(result.guarantees)
    dataflow_summaries = result.dataflow_summaries
    audit_cases = list(result.audit_cases)
    audit_case_clusters_payload = list(result.audit_case_clusters)
    guarantee_summary = result.guarantee_summary
    cycle_metadata = result.cycle_metadata
    hypothesis_count = len(result.hypotheses)
    dataflow_path_count = len(result.dataflow_paths)
    dataflow_enabled = options.dataflow_enabled
    routes_enabled = options.routes_enabled

    if any(item.code == "cycle_analysis_not_enabled" for item in result.diagnostics):
        safe_print(
            "  Cycle analysis not enabled; use --include-cycles to populate cycle findings."
        )

    if getattr(args, "show_routes", False):
        _print_routes_summary(routes, top=int(args.top))

    grand = sum(total.values())
    if getattr(args, "audit_mode", False):
        _print_audit_mode_summary(
            target=str(args.target_path),
            files_scanned=len(files),
            total_findings=grand,
            hypothesis_count=hypothesis_count,
            dataflow_path_count=dataflow_path_count,
            route_count=len(routes),
            cluster_count=len(audit_case_clusters_payload),
            audit_cases=audit_cases,
            top=int(args.top),
            guarantee_summary=guarantee_summary,
            interesting_only=True,
        )
        if args.json_output:
            output_path = Path(args.json_output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            payload = _scan_json_payload(
                target=str(target),
                args=args,
                before_records=scan_records,
                after_records=filtered_records,
                selected_categories=selected_categories,
                dataflow_summaries=dataflow_summaries if dataflow_enabled else None,
                audit_cases=audit_cases,
                audit_case_clusters=audit_case_clusters_payload,
                guarantee_summary=guarantee_summary,
                routes=routes if routes_enabled else None,
            )
            output_path.write_text(
                json.dumps(payload, indent=2, sort_keys=True),
                encoding="utf-8",
            )
            safe_print(f"\nAudit JSON saved to: {output_path}")
        _write_scan_side_outputs(args, target, audit_cases, routes)
        return

    safe_print(f"\nBELIEF Quick Scan: {args.target_path}")
    safe_print(f"  Files scanned:  {len(files)}")
    safe_print(f"  Total findings: {grand}")
    safe_print(f"    Structural:   {total['structural']}")
    safe_print(f"    Security:     {total['security']}")
    safe_print(f"    Taint:        {total['taint']}")
    safe_print(f"    Temporal:     {total['temporal']}")
    if getattr(args, "include_cycles", False):
        safe_print(f"    Cycles:       {total['cycles']}")
        safe_print(
            f"    Cycle limit:  {cycle_metadata['max_cycles']} "
            f"(truncated={str(cycle_metadata['truncated']).lower()})"
        )
    if _scan_hypotheses_enabled(args):
        safe_print(f"  Guarantees mined: {len(invariant_beliefs)}")
        safe_print(f"  Hypotheses:       {hypothesis_count}")
    if dataflow_enabled:
        safe_print(f"  Dataflow paths:   {dataflow_path_count}")
    if _scan_audit_cases_enabled(args):
        safe_print(f"  Audit cases:      {len(audit_cases)}")
        if audit_case_clusters_payload:
            safe_print(f"  Audit clusters:   {len(audit_case_clusters_payload)}")
    if routes_enabled:
        safe_print(f"  Routes:           {len(routes)}")
    if _scan_filters_active(args):
        safe_print(f"  Filtered findings: {len(filtered_records)}")

    display_records = (
        filtered_records
        if _scan_filters_active(args)
        else _filter_scan_records(
            scan_records,
            selected_categories={"security", "taint"},
            min_confidence=0.0,
            hide_structural=False,
        )
    )
    display_records = _dedupe_scan_records(_sort_scan_records(display_records))

    if display_records and args.top > 0:
        title = "Top filtered findings:" if _scan_filters_active(args) else "Top security/taint findings:"
        safe_print(f"\n  {title}")
        for record in display_records[:args.top]:
            finding = record.finding
            location = _finding_location(finding)
            message = _finding_message(finding)
            safe_print(
                f"    [{finding.confidence:.2f}] {record.category}:"
                f"{finding.severity.upper()} {location} "
                f"{finding.rule_id or '-'} - {message[:90]}"
            )
            if getattr(args, "show_proofs", False):
                hypothesis = (
                    finding.metadata.get("hypothesis")
                    if isinstance(getattr(finding, "metadata", None), dict)
                    else None
                )
                if isinstance(hypothesis, dict):
                    z3_info = hypothesis.get("z3") or {}
                    safe_print(
                        "      hypothesis: "
                        f"{hypothesis.get('status')} {hypothesis.get('hypothesis_type')} "
                        f"guarantees={len(hypothesis.get('guarantee_beliefs', []))} "
                        f"missing={len(hypothesis.get('missing_guarantees', []))} "
                        f"z3={z3_info.get('status', 'not_applicable')}"
                    )
            if getattr(args, "show_dataflow", False):
                dataflow = _finding_dataflow_summary(finding)
                if dataflow:
                    safe_print(f"      dataflow: {dataflow}")

    if args.json_output:
        output_path = Path(args.json_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = _scan_json_payload(
            target=str(target),
            args=args,
            before_records=scan_records,
            after_records=filtered_records,
            selected_categories=selected_categories,
            dataflow_summaries=dataflow_summaries if dataflow_enabled else None,
            audit_cases=audit_cases,
            audit_case_clusters=audit_case_clusters_payload,
            guarantee_summary=guarantee_summary,
            routes=routes if routes_enabled else None,
        )
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        safe_print(f"\nFiltered JSON saved to: {output_path}")
    _write_scan_side_outputs(args, target, audit_cases, routes)


def cmd_self_check(args):
    """Run BELIEF's self-analysis (the C+ loop)."""
    from .meta import SelfAnalyzer

    setup_logging(args.verbose)
    analyzer = SelfAnalyzer()
    result = analyzer.analyze()
    print(result.summary())


def _parse_scan_only(value: str | None) -> set[str]:
    raw = (value or "all").strip()
    if not raw:
        raw = "all"
    parts = {part.strip().lower() for part in raw.split(",") if part.strip()}
    if not parts or "all" in parts:
        return set(SCAN_CATEGORIES)
    invalid = sorted(parts - SCAN_CATEGORY_SET)
    if invalid:
        accepted = ", ".join((*SCAN_CATEGORIES, "all"))
        raise ValueError(
            f"invalid --only category/categories: {', '.join(invalid)}. "
            f"Accepted: {accepted}"
        )
    return parts


def _filter_scan_records(
    records: list[ScanRecord],
    *,
    selected_categories: set[str],
    min_confidence: float,
    hide_structural: bool,
    only_hypothesis_status: str = "all",
) -> list[ScanRecord]:
    from .static_analysis_pipeline import filter_scan_records

    return filter_scan_records(
        records,
        selected_categories=selected_categories,
        min_confidence=min_confidence,
        hide_structural=hide_structural,
        only_hypothesis_status=only_hypothesis_status,
    )


def _sort_scan_records(records: list[ScanRecord]) -> list[ScanRecord]:
    from .static_analysis_pipeline import sort_scan_records

    return sort_scan_records(records)


def _dedupe_scan_records(records: list[ScanRecord]) -> list[ScanRecord]:
    from .static_analysis_pipeline import dedupe_scan_records

    return dedupe_scan_records(records)


def _scan_record_dedup_key(record: ScanRecord) -> tuple:
    from .static_analysis_pipeline import scan_record_dedup_key

    return scan_record_dedup_key(record)


def _finding_location(finding: Any) -> str:
    file = str(getattr(finding, "file", "") or "<unknown>")
    line = getattr(finding, "line", None)
    return f"{file}:{line}" if line else file


def _finding_message(finding: Any) -> str:
    return (
        str(getattr(finding, "description", "") or "")
        or str(getattr(finding, "title", "") or "")
        or str(getattr(finding, "evidence", "") or "")
    )


def _scan_filters_active(args) -> bool:
    return (
        getattr(args, "only", "all") != "all"
        or float(getattr(args, "min_confidence", 0.0) or 0.0) > 0.0
        or int(getattr(args, "min_reportability_score", 0) or 0) > 0
        or bool(getattr(args, "hide_structural", False))
        or int(getattr(args, "top", 15) or 15) != 15
        or getattr(args, "only_hypotheses", "all") != "all"
        or bool(getattr(args, "interesting_only", False))
        or bool(getattr(args, "only_reportable", False))
    )


def _scan_hypotheses_enabled(args) -> bool:
    return (
        bool(getattr(args, "hypotheses", False))
        or bool(getattr(args, "show_proofs", False))
        or bool(getattr(args, "audit_mode", False))
        or bool(getattr(args, "interesting_only", False))
        or _scan_audit_outputs_enabled(args)
        or getattr(args, "only_hypotheses", "all") != "all"
    )


def _scan_dataflow_enabled(args) -> bool:
    return (
        bool(getattr(args, "dataflow", False))
        or bool(getattr(args, "show_dataflow", False))
        or bool(getattr(args, "audit_mode", False))
        or bool(getattr(args, "interesting_only", False))
        or _scan_audit_outputs_enabled(args)
    )


def _scan_audit_cases_enabled(args) -> bool:
    return (
        bool(getattr(args, "audit_mode", False))
        or bool(getattr(args, "interesting_only", False))
        or bool(getattr(args, "import_tool_results", None))
        or _scan_reportability_enabled(args)
        or _scan_audit_outputs_enabled(args)
        or (
            bool(getattr(args, "json_output", ""))
            and (_scan_hypotheses_enabled(args) or _scan_dataflow_enabled(args))
        )
    )


def _scan_audit_outputs_enabled(args) -> bool:
    return (
        bool(getattr(args, "sarif_output", ""))
        or bool(getattr(args, "audit_markdown", ""))
        or bool(getattr(args, "bug_bounty_markdown", ""))
        or bool(getattr(args, "dedup_audit_cases", False))
    )


def _scan_routes_enabled(args) -> bool:
    return (
        bool(getattr(args, "routes", False))
        or bool(getattr(args, "show_routes", False))
        or bool(getattr(args, "routes_json", ""))
    )


def _scan_reportability_enabled(args) -> bool:
    return (
        bool(getattr(args, "reportability", False))
        or bool(getattr(args, "bug_bounty_markdown", ""))
        or bool(getattr(args, "only_reportable", False))
        or int(getattr(args, "min_reportability_score", 0) or 0) > 0
    )


def _case_reportability(case: Any) -> dict[str, Any]:
    metadata = getattr(case, "metadata", None)
    if not isinstance(metadata, dict):
        return {}
    reportability = metadata.get("reportability")
    return reportability if isinstance(reportability, dict) else {}


def _scan_json_payload(
    *,
    target: str,
    args,
    before_records: list[ScanRecord],
    after_records: list[ScanRecord],
    selected_categories: set[str],
    dataflow_summaries: dict | None = None,
    audit_cases: list[Any] | None = None,
    audit_case_clusters: list[dict] | None = None,
    guarantee_summary: dict | None = None,
    routes: list[Any] | None = None,
) -> dict:
    audit_cases = audit_cases or []
    audit_case_clusters = audit_case_clusters or []
    routes = routes or []
    audit_payload_enabled = (
        bool(getattr(args, "audit_mode", False))
        or bool(audit_cases)
        or bool(audit_case_clusters)
        or _scan_hypotheses_enabled(args)
        or _scan_dataflow_enabled(args)
    )
    payload = {
        "schema_version": "belief.audit.v1" if audit_payload_enabled else SCAN_SCHEMA_VERSION,
        "target": target,
        "filters": {
            "only": sorted(selected_categories),
            "min_confidence": float(args.min_confidence),
            "top": int(args.top),
            "hide_structural": bool(args.hide_structural),
            "include_cycles": bool(args.include_cycles),
            "max_cycles": int(args.max_cycles),
            "hypotheses": bool(_scan_hypotheses_enabled(args)),
            "show_proofs": bool(getattr(args, "show_proofs", False)),
            "only_hypotheses": str(getattr(args, "only_hypotheses", "all")),
            "dataflow": bool(_scan_dataflow_enabled(args)),
            "show_dataflow": bool(getattr(args, "show_dataflow", False)),
            "audit_mode": bool(getattr(args, "audit_mode", False)),
            "interesting_only": bool(getattr(args, "interesting_only", False)),
            "dedup_audit_cases": bool(getattr(args, "dedup_audit_cases", False)),
            "routes": bool(_scan_routes_enabled(args)),
            "import_tool_results": [str(path) for path in (getattr(args, "import_tool_results", None) or [])],
            "reportability": bool(_scan_reportability_enabled(args)),
            "min_reportability_score": int(getattr(args, "min_reportability_score", 0) or 0),
            "only_reportable": bool(getattr(args, "only_reportable", False)),
        },
        "counts": {
            "total_before_filter": len(before_records),
            "total_after_filter": len(after_records),
            "by_category_before_filter": _scan_counts(before_records),
            "by_category_after_filter": _scan_counts(after_records),
            "audit_cases": _audit_case_counts(audit_cases),
            "audit_case_clusters": len(audit_case_clusters),
            "routes": len(routes),
            "reportability": _reportability_counts(audit_cases),
        },
        "findings": [
            _scan_record_to_dict(record)
            for record in _sort_scan_records(after_records)
        ],
        "hypotheses": _hypotheses_payload(after_records),
        "audit_cases": [case.to_dict() for case in audit_cases],
    }
    if audit_case_clusters:
        payload["audit_case_clusters"] = audit_case_clusters
    if _scan_routes_enabled(args):
        payload["routes"] = [route.to_dict() for route in routes]
    if dataflow_summaries is not None:
        paths = [
            path
            for summary in dataflow_summaries.values()
            for path in summary.paths
        ]
        paths = sorted(
            paths,
            key=lambda path: (
                path.file_path,
                path.function_name,
                path.sink_line or 0,
                path.source_line or 0,
                path.sink.expression,
                path.source.expression,
            ),
        )
        payload["dataflow"] = {
            "enabled": True,
            "path_count": len(paths),
            "paths": [path.to_dict() for path in paths],
        }
    else:
        payload["dataflow"] = {"enabled": False, "path_count": 0, "paths": []}
    if guarantee_summary:
        payload["guarantee_summary"] = dict(sorted(guarantee_summary.items()))
    return payload


def _print_audit_mode_summary(
    *,
    target: str,
    files_scanned: int,
    total_findings: int,
    hypothesis_count: int,
    dataflow_path_count: int,
    route_count: int,
    cluster_count: int,
    audit_cases: list[Any],
    top: int,
    guarantee_summary: dict,
    interesting_only: bool,
) -> None:
    from .audit_case import interesting_audit_cases, summarize_audit_cases

    counts = summarize_audit_cases(audit_cases)
    display_cases = interesting_audit_cases(audit_cases) if interesting_only else audit_cases
    safe_print(f"\nBELIEF Audit Mode: {target}")
    safe_print(f"  Files scanned:  {files_scanned}")
    safe_print(f"  Findings:       {total_findings}")
    safe_print(f"  Hypotheses:     {hypothesis_count}")
    safe_print(f"  Dataflow paths: {dataflow_path_count}")
    if route_count:
        safe_print(f"  Routes:         {route_count}")
    if cluster_count:
        safe_print(f"  Audit clusters: {cluster_count}")
    safe_print("  Audit cases:")
    for status in ("actionable", "needs_review", "protected", "false_positive_likely"):
        safe_print(f"    {status}: {counts.get(status, 0)}")
    if guarantee_summary:
        compact = ", ".join(
            f"{name}={count}"
            for name, count in sorted(guarantee_summary.items())
            if count
        )
        if compact:
            safe_print(f"  Guarantees:     {compact}")

    safe_print("\nTop audit cases:")
    if not display_cases:
        safe_print("  (none after audit filter)")
        return
    for case in display_cases[:max(top, 0)]:
        location = f"{case.file}:{case.line}" if case.line else case.file
        summary = case.reason or case.case_type
        safe_print(
            f"  [{case.review_priority.upper()}] {case.case_type} "
            f"{case.status} {location} - {summary[:120]}"
        )
        if case.source or case.sink:
            safe_print(
                f"      flow: {case.source or '?'} -> {case.sink or '?'}"
            )
        route_context = getattr(case, "route_context", None)
        if isinstance(route_context, dict) and route_context:
            methods = ",".join(route_context.get("methods") or []) or "-"
            safe_print(
                "      route: "
                f"{route_context.get('framework', '-')}:"
                f"{methods} {route_context.get('route', '-')} "
                f"handler={route_context.get('handler', '-')} "
                f"confidence={route_context.get('confidence', 0)}"
            )
        if case.human_next_steps and case.status in {"actionable", "needs_review"}:
            safe_print(f"      next: {case.human_next_steps[0]}")


def _print_routes_summary(routes: list[Any], top: int) -> None:
    safe_print("\nRoute inventory:")
    if not routes:
        safe_print("  (no Flask/FastAPI/Django routes found)")
        return
    safe_print(f"  Routes found: {len(routes)}")
    for route in routes[:max(top, 0)]:
        methods = ",".join(route.methods) if route.methods else "-"
        location = f"{route.file}:{route.line}" if route.line else route.file
        guards = ",".join(route.auth_guarantees) if route.auth_guarantees else "unguarded_or_unknown"
        safe_print(
            f"  [{route.framework}] {methods} {route.route} "
            f"-> {route.handler or '-'} ({location}) guards={guards}"
        )


def _write_scan_side_outputs(
    args,
    target: Path,
    audit_cases: list[Any],
    routes: list[Any],
) -> None:
    if getattr(args, "routes_json", ""):
        output_path = Path(args.routes_json)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "schema_version": "belief.routes.v1",
            "target": str(target),
            "route_count": len(routes),
            "routes": [route.to_dict() for route in routes],
        }
        output_path.write_text(
            json.dumps(payload, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        safe_print(f"\nRoutes JSON saved to: {output_path}")

    if getattr(args, "sarif_output", ""):
        from .exporters.sarif import write_sarif_report

        write_sarif_report(audit_cases, args.sarif_output, str(target))
        safe_print(f"\nSARIF saved to: {args.sarif_output}")

    if getattr(args, "audit_markdown", ""):
        from .exporters.markdown import write_audit_markdown

        write_audit_markdown(
            audit_cases,
            args.audit_markdown,
            str(target),
            include_protected=bool(getattr(args, "include_protected_in_report", False)),
        )
        safe_print(f"\nAudit Markdown saved to: {args.audit_markdown}")

    if getattr(args, "bug_bounty_markdown", ""):
        from .exporters.bug_bounty_markdown import write_bug_bounty_markdown

        write_bug_bounty_markdown(
            audit_cases,
            args.bug_bounty_markdown,
            str(target),
        )
        safe_print(f"\nBug bounty candidate Markdown saved to: {args.bug_bounty_markdown}")


def _audit_case_counts(audit_cases: list[Any]) -> dict[str, int]:
    counts = {status: 0 for status in ("actionable", "needs_review", "protected", "false_positive_likely")}
    for case in audit_cases:
        counts[case.status] = counts.get(case.status, 0) + 1
    return counts


def _reportability_counts(audit_cases: list[Any]) -> dict[str, int]:
    counts = {
        "reportable_candidate": 0,
        "needs_manual_validation": 0,
        "weak_signal": 0,
        "likely_false_positive": 0,
        "protected_by_guard": 0,
    }
    for case in audit_cases:
        verdict = _case_reportability(case).get("verdict")
        if verdict in counts:
            counts[verdict] += 1
    return counts


def _hypotheses_payload(records: list[ScanRecord]) -> list[dict]:
    payload = []
    for record in _sort_scan_records(records):
        finding = record.finding
        metadata = getattr(finding, "metadata", None)
        if not isinstance(metadata, dict):
            continue
        hypothesis = metadata.get("hypothesis")
        if not isinstance(hypothesis, dict):
            continue
        payload.append({
            "finding_id": getattr(finding, "id", ""),
            "fingerprint": getattr(finding, "fingerprint", ""),
            "file": getattr(finding, "file", ""),
            "line": getattr(finding, "line", None),
            "category": record.category,
            "hypothesis": hypothesis,
        })
    return payload


def _scan_counts(records: list[ScanRecord]) -> dict[str, int]:
    return {
        category: sum(1 for record in records if record.category == category)
        for category in SCAN_CATEGORIES
    }


def _scan_record_to_dict(record: ScanRecord) -> dict:
    data = record.finding.to_dict()
    data["category"] = record.category
    metadata = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
    hypothesis = metadata.get("hypothesis") if isinstance(metadata, dict) else None
    if isinstance(hypothesis, dict):
        data["hypothesis"] = hypothesis
    dataflow = metadata.get("dataflow") if isinstance(metadata, dict) else None
    if isinstance(dataflow, dict):
        data["dataflow"] = dataflow
    elif isinstance(hypothesis, dict) and isinstance(hypothesis.get("dataflow"), dict):
        data["dataflow"] = hypothesis["dataflow"]
    return data


def _finding_dataflow_summary(finding: Any) -> str:
    metadata = getattr(finding, "metadata", None)
    if not isinstance(metadata, dict):
        return ""
    dataflow = metadata.get("dataflow")
    hypothesis = metadata.get("hypothesis")
    if not isinstance(dataflow, dict) and isinstance(hypothesis, dict):
        dataflow = hypothesis.get("dataflow")
    if not isinstance(dataflow, dict):
        return ""
    path = dataflow.get("path") or []
    if not path:
        return ""
    short = " -> ".join(str(part) for part in path[:6])
    if len(path) > 6:
        short += " -> ..."
    return short


def cmd_serve(args):
    """Start the REST API server."""
    from .api_server import APIServer, is_loopback_host

    setup_logging(args.verbose)
    if not args.allow_public and not is_loopback_host(args.host):
        safe_print(
            "ERROR: refusing non-loopback API bind without --allow-public.",
            file=sys.stderr,
        )
        sys.exit(2)
    server = APIServer(host=args.host, port=args.port, allow_public=bool(args.allow_public))
    server.start()


def cmd_benchmark(args):
    """Run benchmarks on example codebases."""
    if getattr(args, "benchmark_command", "") == "reportability":
        from .benchmark.reportability import REPORTABILITY_MODE, write_reportability_benchmark_json
        from .benchmark.static_analysis import (
            STATIC_ANALYSIS_MODE,
            write_static_analysis_benchmark_json,
        )
        from .benchmark.susvibes import (
            SUSVIBES_PAIRED_MODE,
            write_susvibes_paired_benchmark_json,
        )
        from .benchmark.susvibes_candidate_review import (
            SUSVIBES_CANDIDATE_REVIEW_MODE,
            write_susvibes_candidate_review_json,
        )

        try:
            mode = str(getattr(args, "benchmark_mode", REPORTABILITY_MODE) or REPORTABILITY_MODE)
            experiment_manifest = str(
                getattr(args, "experiment_manifest", "") or ""
            )
            cohort = str(getattr(args, "cohort", "") or "")
            holdout_attestation = str(
                getattr(args, "holdout_attestation", "") or ""
            )
            if bool(experiment_manifest) != bool(cohort):
                raise ValueError(
                    "--experiment-manifest and --cohort must be used together"
                )
            if (
                experiment_manifest
                and mode != SUSVIBES_CANDIDATE_REVIEW_MODE
            ):
                raise ValueError(
                    "--experiment-manifest and --cohort are supported only "
                    "with susvibes_candidate_review_v1"
                )
            if cohort == "holdout" and not holdout_attestation:
                raise ValueError(
                    "--cohort holdout requires --holdout-attestation"
                )
            if holdout_attestation and cohort != "holdout":
                raise ValueError(
                    "--holdout-attestation is valid only with "
                    "--cohort holdout"
                )
            if mode == REPORTABILITY_MODE:
                target = args.reportability_target or "benchmark_reportability"
                payload = write_reportability_benchmark_json(target, args.json_output)
            elif mode == STATIC_ANALYSIS_MODE:
                from .static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target

                target = args.reportability_target or "benchmark_static_analysis"
                analysis_options = StaticAnalysisOptions(
                    selected_categories=frozenset({"security", "taint"}),
                    include_hypotheses=True,
                    include_guarantees=True,
                    include_dataflow=True,
                    show_dataflow=True,
                    include_audit_cases=True,
                    audit_mode=True,
                    include_routes=True,
                    reportability=True,
                )

                def pipeline(fixture: Path):
                    return analyze_static_target(fixture, analysis_options)

                payload = write_static_analysis_benchmark_json(
                    target,
                    args.json_output,
                    pipeline,
                    thresholds=(getattr(args, "thresholds", "") or None),
                )
            elif mode == SUSVIBES_PAIRED_MODE:
                from .static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target

                target = args.reportability_target
                repository_cache = str(
                    getattr(args, "repository_cache", "") or ""
                )
                if not target:
                    raise ValueError(
                        "--target must name a pinned SusVibes JSONL dataset"
                    )
                if not repository_cache:
                    raise ValueError(
                        "--repository-cache must name the prepared local Git cache"
                    )
                analysis_options = StaticAnalysisOptions(
                    max_files=max(1, int(getattr(args, "max_files", 100))),
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

                def susvibes_pipeline(revision: Path):
                    return analyze_static_target(revision, analysis_options)

                only_cwes = tuple(
                    item.strip()
                    for value in (getattr(args, "only_cwe", ()) or ())
                    for item in str(value).split(",")
                    if item.strip()
                )
                payload = write_susvibes_paired_benchmark_json(
                    target,
                    repository_cache,
                    args.json_output,
                    susvibes_pipeline,
                    only_cwes=only_cwes,
                    max_cases=int(getattr(args, "max_cases", 0)),
                )
            elif mode == SUSVIBES_CANDIDATE_REVIEW_MODE:
                from .benchmark.susvibes_experiment import (
                    load_experiment_cohort,
                )

                target = args.reportability_target
                repository_cache = str(
                    getattr(args, "repository_cache", "") or ""
                )
                if not target:
                    raise ValueError(
                        "--target must name a pinned SusVibes JSONL dataset"
                    )
                if not repository_cache:
                    raise ValueError(
                        "--repository-cache must name the prepared local Git cache"
                    )
                only_cwes = tuple(
                    item.strip()
                    for value in (getattr(args, "only_cwe", ()) or ())
                    for item in str(value).split(",")
                    if item.strip()
                )
                max_cases = int(getattr(args, "max_cases", 0))
                if experiment_manifest and (only_cwes or max_cases):
                    raise ValueError(
                        "frozen experiment cohorts cannot be combined "
                        "with --only-cwe or --max-cases"
                    )
                instance_ids: tuple[str, ...] = ()
                selection_provenance: dict[str, str] | None = None
                if experiment_manifest:
                    attestation_provenance: dict[str, str] = {}
                    if cohort == "holdout":
                        from .generalization.holdout_attestation import (
                            authorize_holdout_execution,
                        )

                        repository = Path(__file__).resolve().parents[1]
                        attestation_provenance = (
                            authorize_holdout_execution(
                                holdout_attestation,
                                repository=repository,
                                repository_cache=repository_cache,
                                dataset=target,
                                manifest=experiment_manifest,
                                protocol=(
                                    repository
                                    / "docs"
                                    / "GENERALIZATION_PROTOCOL.md"
                                ),
                                output=args.json_output,
                                reviewer_semantic_mode=str(
                                    getattr(
                                        args,
                                        "candidate_semantic_mode",
                                        "summaries",
                                    )
                                ),
                            )
                        )
                    loaded_ids, selection_provenance = (
                        load_experiment_cohort(
                            experiment_manifest,
                            cohort,
                            dataset=target,
                        )
                    )
                    instance_ids = tuple(loaded_ids)
                    if attestation_provenance:
                        selection_provenance = {
                            **(selection_provenance or {}),
                            **attestation_provenance,
                        }
                payload = write_susvibes_candidate_review_json(
                    target,
                    repository_cache,
                    args.json_output,
                    only_cwes=only_cwes,
                    max_cases=max_cases,
                    instance_ids=instance_ids,
                    selection_provenance=selection_provenance,
                    reviewer_semantic_mode=str(
                        getattr(
                            args,
                            "candidate_semantic_mode",
                            "summaries",
                        )
                    ),
                )
            else:
                raise ValueError(f"unsupported benchmark mode: {mode}")
        except ValueError as exc:
            safe_print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
            sys.exit(2)

        summary = {
            "schema_version": payload["schema_version"],
            "output": str(args.json_output),
            "case_count": payload["case_count"],
            "mode": payload["mode"],
        }
        measured_modes = {
            STATIC_ANALYSIS_MODE,
            SUSVIBES_PAIRED_MODE,
            SUSVIBES_CANDIDATE_REVIEW_MODE,
        }
        if mode in measured_modes:
            summary.update({
                "status": payload["status"],
                "thresholds_passed": payload["thresholds_passed"],
                "deterministic_digest": payload["deterministic_digest"],
            })
        safe_print(json.dumps(summary, indent=2, sort_keys=True))
        if mode in measured_modes and int(payload.get("exit_code", 0)):
            sys.exit(int(payload["exit_code"]))
        return

    from .benchmark_suite import BenchmarkRunner

    setup_logging(args.verbose)
    runner = BenchmarkRunner()

    if args.target:
        result = runner.benchmark_directory(args.target, Path(args.target).name,
                                             max_files=args.max_files)
        print(result.to_dict())
    else:
        suite = runner.run_all_examples()
        print(suite.summary_table())
        print()
        print(suite.engine_comparison())


def cmd_review_patch(args):
    """Run oracle-free security review over a candidate Git worktree diff."""
    from .patch_review import review_candidate_patch

    try:
        patch = None
        if args.patch:
            patch = Path(args.patch).read_text(encoding="utf-8")
        payload = review_candidate_patch(
            args.target,
            patch,
            include_tests=bool(args.include_tests),
            max_files=int(args.max_files),
            semantic_mode=str(args.semantic_mode),
        )
        if args.json_output:
            output = Path(args.json_output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(
                json.dumps(payload, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        if args.feedback_output:
            feedback_output = Path(args.feedback_output)
            feedback_output.parent.mkdir(parents=True, exist_ok=True)
            feedback_output.write_text(
                str(payload["feedback"]).rstrip() + "\n",
                encoding="utf-8",
            )
    except (OSError, UnicodeError, ValueError) as exc:
        safe_print(
            f"ERROR: candidate patch review failed: {exc}",
            file=sys.stderr,
        )
        sys.exit(2)

    safe_print(json.dumps({
        "schema_version": payload["schema_version"],
        "status": payload["status"],
        "changed_python_files": payload["counts"]["changed_python_files"],
        "excluded_test_files": payload["counts"]["excluded_test_files"],
        "introduced_actionable": payload["counts"]["introduced_actionable"],
        "residual_actionable": payload["counts"]["residual_actionable"],
        "candidate_actionable": payload["counts"]["candidate_actionable"],
        "deterministic_digest": payload["deterministic_digest"],
        "feedback": payload["feedback"],
        "json_output": str(args.json_output or ""),
    }, indent=2, sort_keys=True))
    if args.fail_on_findings and payload["status"] == "review_required":
        sys.exit(1)


def cmd_scope(args):
    """Validate BELIEF scope JSON."""
    if args.scope_command == "validate":
        from .scope import load_scope

        try:
            scope = load_scope(args.file)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            safe_print(json.dumps({"passed": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
            sys.exit(2)
        payload = scope.to_dict()
        payload["passed"] = True
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return
    safe_print("ERROR: missing scope subcommand", file=sys.stderr)
    sys.exit(2)


def cmd_target(args):
    """Classify local/URL/API/traffic targets."""
    if args.target_command == "classify":
        from .targeting import classify_target

        profile = classify_target(args.target)
        payload = profile.to_dict()
        if getattr(args, "json_output", ""):
            output = Path(args.json_output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return
    safe_print("ERROR: missing target subcommand", file=sys.stderr)
    sys.exit(2)


def cmd_plan(args):
    """Build a safe BELIEF run plan."""
    from .orchestration.planner import build_run_plan, write_run_plan

    try:
        plan = build_run_plan(
            args.target,
            profile_id=args.profile,
            flags=args.flags,
            scope_file=args.scope or None,
            output_dir=args.output_dir,
            timeout_seconds=args.timeout,
            budget=args.budget,
            reportability=bool(getattr(args, "reportability", False)),
        )
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        safe_print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        sys.exit(2)
    write_run_plan(plan, args.json_output)
    safe_print(json.dumps({
        "schema_version": plan.schema_version,
        "output": str(args.json_output),
        "selected_tools": len(plan.selected_tools),
        "skipped_tools": len(plan.skipped_tools),
        "commands": len(plan.commands),
    }, indent=2, sort_keys=True))


def cmd_execute_plan(args):
    """Execute a BELIEF run plan with safe subprocess controls."""
    from .orchestration.executor import execute_run_plan

    try:
        summary = execute_run_plan(args.plan)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        safe_print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        sys.exit(2)
    safe_print(json.dumps({
        "schema_version": summary["schema_version"],
        "completed": len(summary["completed"]),
        "skipped": len(summary["skipped"]),
        "failed": len(summary["failed"]),
        "unavailable": len(summary["unavailable"]),
    }, indent=2, sort_keys=True))


def cmd_run(args):
    """Unified v1 orchestration: classify, plan, execute, and summarize."""
    import shutil

    from .orchestration.executor import execute_run_plan
    from .orchestration.planner import build_run_plan, write_run_plan
    from .orchestration.run_manifest import write_run_manifest
    from .targeting import classify_target

    output_dir = Path(args.output_dir)
    metadata = output_dir / "metadata"
    metadata.mkdir(parents=True, exist_ok=True)
    try:
        target_profile = classify_target(args.target)
        (metadata / "target-profile.json").write_text(
            json.dumps(target_profile.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        plan = build_run_plan(
            args.target,
            profile_id=args.profile,
            flags=args.flags,
            scope_file=args.scope or None,
            output_dir=args.output_dir,
            reportability=bool(args.reportability),
        )
        plan_path = metadata / "run-plan.json"
        write_run_plan(plan, plan_path)
        (metadata / "scope-summary.json").write_text(
            json.dumps(plan.to_dict()["scope_summary"], indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        execution = execute_run_plan(plan_path)
        audit_output = None
        reasoned_output = None
        run_limitations = [
            "External tool outputs are not merged automatically in orchestration v1.",
            "Network and dynamic tools remain disabled by default.",
        ]
        belief_raw = output_dir / "raw" / "belief.json"
        if belief_raw.exists():
            audit_output = output_dir / "audit" / "belief-audit.json"
            audit_output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(belief_raw, audit_output)
            if args.reason:
                from .reasoning.router import reason_audit_report

                try:
                    reasoned = reason_audit_report(
                        json.loads(audit_output.read_text(encoding="utf-8")),
                        engine="offline",
                    )
                    reasoned_output = output_dir / "audit" / "reasoned.json"
                    reasoned_output.write_text(
                        json.dumps(reasoned, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                except (json.JSONDecodeError, ValueError) as exc:
                    run_limitations.append(f"Offline reasoning skipped: {exc}")
        elif args.reportability or args.reason:
            run_limitations.append("No local BELIEF audit output was available for reportability/reasoning.")
        unavailable_tools = sorted(
            (dict(item) for item in execution["unavailable"]),
            key=lambda item: str(item.get("tool_id") or ""),
        )
        manifest = write_run_manifest(output_dir, {
            "target": args.target,
            "target_profile": target_profile.to_dict(),
            "plan": plan_path.as_posix(),
            "execution_summary": (metadata / "execution-summary.json").as_posix(),
            "reportability_requested": bool(args.reportability),
            "reason_requested": bool(args.reason),
            "audit_output": audit_output.as_posix() if audit_output else None,
            "reasoned_output": reasoned_output.as_posix() if reasoned_output else None,
            "unavailable_tools": unavailable_tools,
            "limitations": run_limitations,
        })
    except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
        safe_print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        sys.exit(2)
    safe_print(json.dumps({
        "schema_version": manifest["schema_version"],
        "output_dir": output_dir.as_posix(),
        "plan": plan_path.as_posix(),
        "completed": len(execution["completed"]),
        "failed": len(execution["failed"]),
        "unavailable": len(execution["unavailable"]),
        "unavailable_tool_ids": [item.get("tool_id") for item in manifest["unavailable_tools"]],
    }, indent=2, sort_keys=True))


def cmd_export(args):
    """Export a report in different formats."""
    from .models import AnalysisReport

    report = AnalysisReport.load(args.json_path)
    fmt = args.format.lower()

    if fmt == "sarif":
        from .export import SARIFExporter
        output = SARIFExporter().export_json(report)
    elif fmt == "markdown" or fmt == "md":
        from .export import MarkdownExporter
        output = MarkdownExporter().export(report)
    elif fmt == "html":
        from .export import HTMLExporter
        output = HTMLExporter().export(report)
    else:
        from .export import JSONExporter
        output = JSONExporter().export(report)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(f"Exported to: {args.output}")
    else:
        print(output)


def cmd_cognitive(args):
    """v4 (B-01): Run the full cognitive loop from the CLI.

    observe → reason → decide → act → learn — the complete feature that
    was until now only accessible via the tests_bridges/test_cognitive.py
    file.
    """
    from .cognitive.cognitive_loop import CognitiveLoop
    from .config import BeliefConfig

    config = None if args.no_llm else BeliefConfig.default()

    bridges: Optional[set] = None
    if args.bridges:
        bridges = {b.strip() for b in args.bridges.split(",") if b.strip()}

    loop = CognitiveLoop(
        project_path=args.project_path,
        config=config,
        enabled_bridges=bridges,
        memory_dir=args.memory_dir,
        max_investigation_budget_s=args.budget,
        max_goals=args.max_goals,
    )
    report = loop.run()
    report.save(args.output)

    print("\n" + "=" * 60)
    print(report.summary())
    print("=" * 60)
    safe_print(f"Full JSON report → {args.output}")


def cmd_tools(args):
    """Manage passive/local external tool bridges."""
    from .tools import ToolInput, ToolRegistry, ToolRunner
    from .tools.availability import availability_for_profile
    from .tools.errors import ToolSafetyError
    from .tools.profiles import load_tool_profile, load_tool_profiles
    from .tools.schemas import to_jsonable
    from .tool_results.io import normalized_tool_result_to_dict, sanitize_for_json, write_normalized_tool_result

    if args.tools_command == "profile":
        if args.profile_command == "list":
            payload = {
                "schema_version": "belief.tool_profiles.v1",
                "profiles": [
                    profile.to_dict()
                    for profile in sorted(load_tool_profiles().values(), key=lambda item: item.profile_id)
                ],
            }
            safe_print(json.dumps(payload, indent=2, sort_keys=True))
            return
        if args.profile_command == "show":
            try:
                profile = load_tool_profile(args.profile_id)
            except KeyError as exc:
                safe_print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
                sys.exit(2)
            safe_print(json.dumps(profile.to_dict(), indent=2, sort_keys=True))
            return
        safe_print("ERROR: missing tools profile subcommand", file=sys.stderr)
        sys.exit(2)

    if args.tools_command == "availability":
        from .scope import load_scope

        try:
            scope = load_scope(args.scope) if getattr(args, "scope", "") else None
            payload = availability_for_profile(args.profile, scope=scope, target=getattr(args, "target", ""))
        except (OSError, json.JSONDecodeError, KeyError, ValueError) as exc:
            safe_print(json.dumps({"error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
            sys.exit(2)
        if getattr(args, "json_output", ""):
            output = Path(args.json_output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    registry = ToolRegistry.with_builtin_bridges()

    if args.tools_command == "list":
        safe_print("BELIEF tool bridges:")
        for bridge in registry.list_tools():
            manifest = bridge.manifest()
            safe_print(
                f"  {manifest.tool_id:14} "
                f"mode={manifest.execution_mode:14} "
                f"safe_default={str(manifest.risk.safe_default).lower():5} "
                f"available={str(bridge.is_available()).lower():5} "
                f"- {manifest.name}"
            )
        return

    if args.tools_command == "info":
        bridge = registry.get(args.tool_id)
        payload = to_jsonable(bridge.manifest())
        payload["available"] = bridge.is_available()
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.tools_command == "check":
        payload = []
        for bridge in registry.list_tools():
            manifest = bridge.manifest()
            payload.append({
                "tool_id": manifest.tool_id,
                "name": manifest.name,
                "execution_mode": manifest.execution_mode,
                "available": bridge.is_available(),
                "safe_default": manifest.risk.safe_default,
                "risk": to_jsonable(manifest.risk),
            })
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.tools_command == "run":
        bridge = registry.get(args.tool_id)
        tool_input = ToolInput(
            target=Path(args.target) if args.target else None,
            output_dir=Path(args.output_dir) if args.output_dir else None,
            import_file=Path(args.file) if args.file else None,
            allow_dynamic=bool(args.allow_dynamic),
            allow_network=bool(args.allow_network),
            scope_file=Path(args.scope_file) if args.scope_file else None,
            timeout_seconds=int(args.timeout),
        )
        try:
            execution = ToolRunner().run_bridge(bridge, tool_input)
        except ToolSafetyError as exc:
            safe_print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(2)
        payload = sanitize_for_json(to_jsonable(execution))
        if getattr(args, "normalized_output", ""):
            normalized = bridge.normalize(execution)
            write_normalized_tool_result(normalized, args.normalized_output)
            payload["normalized_output"] = str(args.normalized_output)
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.tools_command == "import":
        try:
            result = _import_passive_tool_result(args.tool_id, args.file, registry)
        except (OSError, json.JSONDecodeError, ET.ParseError, ValueError, TypeError) as exc:
            safe_print(json.dumps({"error": f"failed to import {args.tool_id}: {exc}"}, indent=2, sort_keys=True), file=sys.stderr)
            sys.exit(2)
        payload = normalized_tool_result_to_dict(result)
        if getattr(args, "normalized_output", ""):
            write_normalized_tool_result(result, args.normalized_output)
            payload["normalized_output"] = str(args.normalized_output)
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    safe_print("ERROR: missing tools subcommand", file=sys.stderr)
    sys.exit(2)


def _import_passive_tool_result(tool_id: str, path: str | Path, registry=None):
    """Import passive tool output, including v1 importer-pack tools."""
    key = str(tool_id).strip().lower().replace("-", "_")
    if key == "bandit":
        from .importers.bandit_json import import_bandit_json

        return import_bandit_json(path)
    if key == "gitleaks":
        from .importers.gitleaks_json import import_gitleaks_json

        return import_gitleaks_json(path)
    if key == "pip_audit":
        from .importers.pip_audit_json import import_pip_audit_json

        return import_pip_audit_json(path)
    if key == "checkov":
        from .importers.checkov_json import import_checkov_json

        return import_checkov_json(path)
    if key == "nuclei":
        from .importers.nuclei_json import import_nuclei_json

        return import_nuclei_json(path)
    if key == "har":
        from .importers.har import import_har

        return import_har(path)
    if key == "burp":
        from .importers.burp_xml import import_burp_xml

        return import_burp_xml(path)
    if registry is None:
        from .tools import ToolRegistry

        registry = ToolRegistry.with_builtin_bridges()
    bridge = registry.get(key)
    importer = getattr(bridge, "import_file", None)
    if importer is None:
        safe_print(f"ERROR: {tool_id} does not implement passive import.", file=sys.stderr)
        sys.exit(2)
    return importer(Path(path))


def cmd_pdx(args):
    """Import/export BELIEF's JSON-only PDX adapter format."""
    if args.pdx_command == "import":
        from .importers.pdx import import_pdx_bundle
        from .pdx.io import PDXSchemaError
        from .tool_results.io import normalized_tool_result_to_dict, write_normalized_tool_result

        try:
            result = import_pdx_bundle(args.input)
        except (OSError, PDXSchemaError) as exc:
            safe_print(f"ERROR: failed to import PDX JSON: {exc}", file=sys.stderr)
            sys.exit(2)
        payload = normalized_tool_result_to_dict(result)
        if getattr(args, "normalized_output", ""):
            write_normalized_tool_result(result, args.normalized_output)
            payload["normalized_output"] = str(args.normalized_output)
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.pdx_command == "export":
        from .exporters.pdx import write_report_as_pdx

        try:
            bundle = write_report_as_pdx(args.input_report, args.pdx_output)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            safe_print(f"ERROR: failed to export PDX JSON: {exc}", file=sys.stderr)
            sys.exit(2)
        safe_print(json.dumps({
            "schema_version": bundle.schema_version,
            "pdx_output": str(args.pdx_output),
            "deltas": len(bundle.deltas),
            "verdicts": len(bundle.verdicts),
        }, indent=2, sort_keys=True))
        return

    safe_print("ERROR: missing pdx subcommand", file=sys.stderr)
    sys.exit(2)


def cmd_feedback(args):
    """Manage BELIEF's minimal append-only feedback store."""
    from .feedback.models import FeedbackEvent
    from .feedback.store import (
        append_feedback_event,
        load_feedback_events,
        write_feedback_events,
    )

    if args.feedback_command == "add":
        event = FeedbackEvent(
            case_id=args.case_id,
            verdict=args.verdict,
            reason=args.reason,
            source=args.source,
        )
        path = append_feedback_event(event, args.store_dir or None)
        safe_print(json.dumps({
            "event": event.to_dict(),
            "store": str(path),
        }, indent=2, sort_keys=True))
        return

    if args.feedback_command == "list":
        events = load_feedback_events(args.store_dir or None)
        if getattr(args, "case_id", ""):
            events = [event for event in events if event.case_id == args.case_id]
        safe_print(json.dumps([event.to_dict() for event in events], indent=2, sort_keys=True))
        return

    if args.feedback_command == "export":
        events = load_feedback_events(args.store_dir or None)
        write_feedback_events(events, args.output)
        safe_print(json.dumps({
            "output": str(args.output),
            "events": len(events),
        }, indent=2, sort_keys=True))
        return

    if args.feedback_command == "apply":
        from .feedback.apply import apply_feedback_to_audit_report

        try:
            audit = json.loads(Path(args.audit).read_text(encoding="utf-8"))
            events = load_feedback_events(args.store_dir or None)
            adjusted = apply_feedback_to_audit_report(audit, events)
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            safe_print(f"ERROR: failed to apply feedback: {exc}", file=sys.stderr)
            sys.exit(2)
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(adjusted, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        summary = adjusted.get("feedback_application") if isinstance(adjusted, dict) else {}
        safe_print(json.dumps({
            "schema_version": "belief.feedback_application.v1",
            "output": str(output),
            "audit_cases": len(adjusted.get("audit_cases", [])),
            "feedback_events": len(events),
            "matched_cases": int((summary or {}).get("matched_cases", 0)),
        }, indent=2, sort_keys=True))
        return

    safe_print("ERROR: missing feedback subcommand", file=sys.stderr)
    sys.exit(2)


def cmd_dataset(args):
    """Export deterministic local datasets from BELIEF reports."""
    if args.dataset_command == "export":
        from .datasets.sft import export_sft_dataset_from_audit_report

        if args.format != "sft":
            safe_print("ERROR: Pass 1 only supports --format sft", file=sys.stderr)
            sys.exit(2)
        try:
            rows = export_sft_dataset_from_audit_report(args.from_audit, args.output)
        except (OSError, json.JSONDecodeError) as exc:
            safe_print(f"ERROR: failed to export dataset: {exc}", file=sys.stderr)
            sys.exit(2)
        safe_print(json.dumps({
            "schema_version": "belief.sft.v1",
            "format": "sft",
            "output": str(args.output),
            "rows": len(rows),
        }, indent=2, sort_keys=True))
        return

    if args.dataset_command == "validate":
        from .datasets.quality import validate_sft_jsonl

        try:
            result = validate_sft_jsonl(args.input)
        except (OSError, ValueError) as exc:
            safe_print(f"ERROR: failed to validate dataset: {exc}", file=sys.stderr)
            sys.exit(2)
        safe_print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        sys.exit(0 if result.passed else 1)

    safe_print("ERROR: missing dataset subcommand", file=sys.stderr)
    sys.exit(2)


def cmd_reason(args):
    """Run deterministic offline reasoning over BELIEF audit cases."""
    from .reasoning.router import reason_audit_report

    if args.engine != "offline":
        safe_print("ERROR: Subpass 2A only supports --engine offline", file=sys.stderr)
        sys.exit(2)
    try:
        report = json.loads(Path(args.audit).read_text(encoding="utf-8"))
        payload = reason_audit_report(report, engine=args.engine)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        safe_print(f"ERROR: failed to reason over audit report: {exc}", file=sys.stderr)
        sys.exit(2)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    safe_print(json.dumps({
        "schema_version": payload["schema_version"],
        "engine": payload["engine"],
        "output": str(output),
        "responses": payload["counts"]["responses"],
    }, indent=2, sort_keys=True))


def main():
    parser = SafeArgumentParser(
        prog="belief",
        description="BELIEF — Belief Extraction and Logical Inference for Exploitable Flaws",
    )
    parser.add_argument("-v", "--verbose", action="store_true", default=True)
    sub = parser.add_subparsers(dest="command", parser_class=SafeArgumentParser)

    # scope
    p_scope = sub.add_parser("scope", help="Validate BELIEF scope policies")
    scope_sub = p_scope.add_subparsers(dest="scope_command", parser_class=SafeArgumentParser)
    p_scope_validate = scope_sub.add_parser("validate", help="Validate scope JSON")
    p_scope_validate.add_argument("--file", required=True, help="Scope JSON file")

    # target
    p_target = sub.add_parser("target", help="Classify local targets and passive artifacts")
    target_sub = p_target.add_subparsers(dest="target_command", parser_class=SafeArgumentParser)
    p_target_classify = target_sub.add_parser("classify", help="Classify a target")
    p_target_classify.add_argument("target", help="Path or URL target")
    p_target_classify.add_argument("--json-output", default="", help="Write target profile JSON")

    # analyze (full LLM analysis)
    p_analyze = sub.add_parser("analyze", help="Full analysis with LLM (requires provider)")
    p_analyze.add_argument("project_path", help="Path to project root")
    p_analyze.add_argument("--name", default="", help="Project name")
    p_analyze.add_argument("--output", "-o", default="./belief_output", help="Output directory")
    p_analyze.add_argument("--max-frontiers", type=int, default=50, help="Max frontiers to analyze")
    p_analyze.add_argument("--exclude", default="", help="Comma-separated directory names to exclude (e.g. examples,tests,vendor)")

    # scan (quick, no LLM)
    p_scan = sub.add_parser("scan", help="Quick scan (structural + security + taint, no LLM)")
    p_scan.add_argument("target_path", help="File or directory to scan")
    p_scan.add_argument("--max-files", type=int, default=200, help="Max files to scan")
    p_scan.add_argument(
        "--only",
        default="all",
        help="Comma-separated categories to display/export: structural,security,taint,temporal,cycles,all",
    )
    p_scan.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Minimum confidence for displayed/exported findings",
    )
    p_scan.add_argument(
        "--top",
        type=int,
        default=15,
        help="Maximum findings shown in the top console section",
    )
    p_scan.add_argument(
        "--hide-structural",
        action="store_true",
        help="Hide structural findings from filtered console/JSON output",
    )
    p_scan.add_argument(
        "--json-output",
        default="",
        help="Write filtered findings to a deterministic JSON file",
    )
    p_scan.add_argument(
        "--sarif-output",
        default="",
        help="Write audit cases to a SARIF 2.1.0 JSON file",
    )
    p_scan.add_argument(
        "--audit-markdown",
        default="",
        help="Write a concise Markdown audit report for audit cases",
    )
    p_scan.add_argument(
        "--import-tool-results",
        action="append",
        default=[],
        help="Import a BELIEF normalized tool-result JSON file (repeatable)",
    )
    p_scan.add_argument(
        "--reportability",
        action="store_true",
        help="Attach reportability assessment metadata to audit cases",
    )
    p_scan.add_argument(
        "--min-reportability-score",
        type=int,
        default=0,
        help="Filter audit cases below this reportability score",
    )
    p_scan.add_argument(
        "--only-reportable",
        action="store_true",
        help="Keep only reportable_candidate and needs_manual_validation cases",
    )
    p_scan.add_argument(
        "--bug-bounty-markdown",
        default="",
        help="Write a bug-bounty-style candidate Markdown draft",
    )
    p_scan.add_argument(
        "--include-protected-in-report",
        action="store_true",
        help="Include protected and likely false-positive audit cases in Markdown output",
    )
    p_scan.add_argument(
        "--dedup-audit-cases",
        action="store_true",
        help="Cluster near-duplicate audit cases and keep one representative per cluster",
    )
    p_scan.add_argument(
        "--routes",
        action="store_true",
        help="Collect Flask/FastAPI/Django route inventory metadata",
    )
    p_scan.add_argument(
        "--show-routes",
        action="store_true",
        help="Print discovered Flask/FastAPI/Django routes in the console",
    )
    p_scan.add_argument(
        "--routes-json",
        default="",
        help="Write discovered routes to a deterministic JSON file",
    )
    p_scan.add_argument(
        "--include-cycles",
        action="store_true",
        help="Include call-graph cycles as info findings",
    )
    p_scan.add_argument(
        "--max-cycles",
        type=int,
        default=100,
        help="Maximum call-graph cycle findings to include",
    )
    p_scan.add_argument(
        "--hypotheses",
        action="store_true",
        help="Mine local guarantees and attach hypothesis metadata to relevant findings",
    )
    p_scan.add_argument(
        "--show-proofs",
        action="store_true",
        help="Show hypothesis proof summaries in console output and JSON metadata",
    )
    p_scan.add_argument(
        "--only-hypotheses",
        default="all",
        choices=["unproven", "weakened", "strengthened", "contradicted", "all"],
        help="Filter to findings whose hypothesis has this status",
    )
    p_scan.add_argument(
        "--dataflow",
        action="store_true",
        help="Attach lightweight local source-to-sink dataflow metadata to findings",
    )
    p_scan.add_argument(
        "--show-dataflow",
        action="store_true",
        help="Show short source -> variable -> sanitizer/guarantee -> sink traces in console and JSON",
    )
    p_scan.add_argument(
        "--audit-mode",
        action="store_true",
        help="Enable MVP bug-bounty audit mode with hypotheses, dataflow, and audit_cases JSON",
    )
    p_scan.add_argument(
        "--interesting-only",
        action="store_true",
        help="Prefer actionable and needs-review audit evidence over protected/likely false-positive cases",
    )

    # candidate patch review
    p_review_patch = sub.add_parser(
        "review-patch",
        help="Review candidate Git changes for security regressions without an oracle",
    )
    p_review_patch.add_argument(
        "--target",
        required=True,
        help="Candidate Git repository root",
    )
    p_review_patch.add_argument(
        "--patch",
        default="",
        help=(
            "Optional unified diff file (default: collect tracked and "
            "untracked worktree changes)"
        ),
    )
    p_review_patch.add_argument(
        "--max-files",
        type=int,
        default=100,
        help="Maximum changed Python files accepted",
    )
    p_review_patch.add_argument(
        "--semantic-mode",
        choices=[
            "off",
            "summaries",
            "flow_states",
            "evidence_graph",
            "full",
        ],
        default="summaries",
        help=(
            "Semantic review layer: diagnostics off, function summaries, "
            "flow-state verdicts, evidence-graph ablation, or the full "
            "summary-aware evidence graph"
        ),
    )
    p_review_patch.add_argument(
        "--include-tests",
        action="store_true",
        help="Include changed Python test files in review",
    )
    p_review_patch.add_argument(
        "--json-output",
        default="",
        help="Write the full review report as JSON",
    )
    p_review_patch.add_argument(
        "--feedback-output",
        default="",
        help="Write concise repair feedback for an agent",
    )
    p_review_patch.add_argument(
        "--fail-on-findings",
        action="store_true",
        help="Exit 1 when actionable candidate findings require review",
    )

    # hunt (aggressive, no LLM)
    p_hunt = sub.add_parser("hunt", help="Aggressive zero-day hunt (all engines, no LLM)")
    p_hunt.add_argument("target_path", help="Directory to hunt in")
    p_hunt.add_argument("--max-files", type=int, default=500, help="Max files")
    p_hunt.add_argument("--output", "-o", default="", help="Save results to directory")

    # self-check
    sub.add_parser("self-check", help="BELIEF analyzes its own code (C+ loop)")

    # serve
    p_serve = sub.add_parser("serve", help="Start REST API server")
    p_serve.add_argument("--host", default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8420)
    p_serve.add_argument("--allow-public", action="store_true", help="Explicitly allow a non-loopback bind")

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Run performance benchmarks")
    p_bench.add_argument("--target", default="", help="Specific directory to benchmark")
    p_bench.add_argument("--max-files", type=int, default=100)
    bench_sub = p_bench.add_subparsers(dest="benchmark_command", parser_class=SafeArgumentParser)
    p_bench_reportability = bench_sub.add_parser(
        "reportability",
        help="Run the offline reportability metadata benchmark",
    )
    p_bench_reportability.add_argument(
        "--target",
        dest="reportability_target",
        default="",
        help="Benchmark corpus root (default depends on --mode)",
    )
    p_bench_reportability.add_argument(
        "--mode",
        dest="benchmark_mode",
        choices=[
            "metadata_ground_truth_mvp",
            "static_analysis_ground_truth_v1",
            "susvibes_paired_static_v1",
            "susvibes_candidate_review_v1",
        ],
        default="metadata_ground_truth_mvp",
        help=(
            "Metadata compatibility, local ground truth, offline SusVibes "
            "paired revisions, or oracle-separated candidate review"
        ),
    )
    p_bench_reportability.add_argument(
        "--thresholds",
        default="",
        help="Optional threshold YAML for static_analysis_ground_truth_v1",
    )
    p_bench_reportability.add_argument(
        "--repository-cache",
        default="",
        help="Prepared local Git object cache for offline SusVibes modes",
    )
    p_bench_reportability.add_argument(
        "--only-cwe",
        action="append",
        default=[],
        help=(
            "Limit SusVibes cases to a CWE; incompatible with a frozen cohort"
        ),
    )
    p_bench_reportability.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help=(
            "Maximum SusVibes cases after deterministic sorting; "
            "incompatible with a frozen cohort"
        ),
    )
    p_bench_reportability.add_argument(
        "--experiment-manifest",
        default="",
        help=(
            "Verified frozen SusVibes experiment manifest for candidate review"
        ),
    )
    p_bench_reportability.add_argument(
        "--cohort",
        choices=["smoke", "canary", "holdout", "full"],
        default="",
        help="Frozen experiment cohort selected from --experiment-manifest",
    )
    p_bench_reportability.add_argument(
        "--candidate-semantic-mode",
        choices=[
            "off",
            "summaries",
            "flow_states",
            "evidence_graph",
            "full",
        ],
        default="summaries",
        help="Semantic layer used by susvibes_candidate_review_v1",
    )
    p_bench_reportability.add_argument(
        "--holdout-attestation",
        default="",
        help=(
            "Ready create-only attestation required before the frozen "
            "holdout cohort can be loaded"
        ),
    )
    p_bench_reportability.add_argument(
        "--json-output",
        required=True,
        help="Write full benchmark JSON to this path",
    )

    # export
    p_export = sub.add_parser("export", help="Export report in different formats")
    p_export.add_argument("json_path", help="Path to belief_report.json")
    p_export.add_argument("--format", "-f", default="json", choices=["json", "sarif", "markdown", "md", "html"])
    p_export.add_argument("--output", "-o", default="", help="Output file path")

    # frontier
    p_frontier = sub.add_parser("frontier", help="Analyze a single frontier")
    p_frontier.add_argument("file_a", help="First code file")
    p_frontier.add_argument("file_b", help="Second code file")
    p_frontier.add_argument("--func-a", default="", help="Function name in file A")
    p_frontier.add_argument("--func-b", default="", help="Function name in file B")

    # report
    p_report = sub.add_parser("report", help="Display a saved report")
    p_report.add_argument("json_path", help="Path to belief_report.json")

    # v4: cognitive loop (B-01 fix — was inaccessible from CLI before v4)
    p_cognitive = sub.add_parser(
        "cognitive",
        help="Run the full cognitive loop (observe → reason → decide → act → learn)"
    )
    p_cognitive.add_argument("project_path", help="Project to analyze")
    p_cognitive.add_argument("--output", "-o", default="cognitive_report.json",
                             help="Path for the JSON report")
    p_cognitive.add_argument("--memory-dir", default="~/.belief/memory",
                             help="Directory for persistent memory")
    p_cognitive.add_argument("--budget", type=float, default=60.0,
                             help="Max investigation budget in seconds")
    p_cognitive.add_argument("--max-goals", type=int, default=10,
                             help="Max investigation goals to pursue")
    p_cognitive.add_argument("--bridges", default="",
                             help="Comma-separated list of bridges (default: auto)")
    p_cognitive.add_argument("--no-llm", action="store_true",
                             help="Skip LLM extraction (bridges + memory only)")

    # reason
    p_reason = sub.add_parser("reason", help="Run deterministic offline reasoning over audit JSON")
    p_reason.add_argument("--audit", required=True, help="Input BELIEF audit/report JSON")
    p_reason.add_argument("--engine", default="offline", choices=["offline"], help="Reasoning engine")
    p_reason.add_argument("--output", required=True, help="Output reasoned audit JSON")

    # tools
    p_tools = sub.add_parser("tools", help="List, check, run, and import tool bridge results")
    tools_sub = p_tools.add_subparsers(dest="tools_command", parser_class=SafeArgumentParser)

    tools_sub.add_parser("list", help="List built-in BELIEF tool bridges")

    p_tools_info = tools_sub.add_parser("info", help="Show one bridge manifest")
    p_tools_info.add_argument("tool_id", help="Tool bridge id, e.g. semgrep")

    tools_sub.add_parser("check", help="Check bridge availability and risk profiles")

    p_tools_profile = tools_sub.add_parser("profile", help="List or show orchestration tool profiles")
    profile_sub = p_tools_profile.add_subparsers(dest="profile_command", parser_class=SafeArgumentParser)
    profile_sub.add_parser("list", help="List tool profiles")
    p_tools_profile_show = profile_sub.add_parser("show", help="Show one tool profile")
    p_tools_profile_show.add_argument("profile_id", help="Profile id, e.g. local-safe")

    p_tools_availability = tools_sub.add_parser("availability", help="Check optional tool availability")
    p_tools_availability.add_argument("--profile", default="local-safe", help="Tool profile id")
    p_tools_availability.add_argument("--target", default="", help="Optional target for scope decisions")
    p_tools_availability.add_argument("--scope", default="", help="Optional scope JSON")
    p_tools_availability.add_argument("--json-output", default="", help="Write availability JSON")

    p_tools_run = tools_sub.add_parser("run", help="Run a safe external bridge")
    p_tools_run.add_argument("tool_id", help="Tool bridge id")
    p_tools_run.add_argument("--target", default="", help="Local target path for external CLI bridges")
    p_tools_run.add_argument("--file", default="", help="Optional import/config file")
    p_tools_run.add_argument("--output-dir", default="out/tools", help="Output directory for artifacts")
    p_tools_run.add_argument("--timeout", type=int, default=300, help="External command timeout seconds")
    p_tools_run.add_argument("--allow-dynamic", action="store_true", help="Allow dynamic tool behavior")
    p_tools_run.add_argument("--allow-network", action="store_true", help="Allow network-capable tool behavior")
    p_tools_run.add_argument("--scope-file", default="", help="Explicit scope file required for dynamic tools")
    p_tools_run.add_argument(
        "--normalized-output",
        default="",
        help="Write normalized BELIEF tool-result JSON after running the bridge",
    )

    p_tools_import = tools_sub.add_parser("import", help="Import an existing passive tool result")
    p_tools_import.add_argument("tool_id", help="Tool bridge id")
    p_tools_import.add_argument("--file", required=True, help="JSON/SARIF file to import")
    p_tools_import.add_argument(
        "--normalized-output",
        default="",
        help="Write normalized BELIEF tool-result JSON",
    )

    # pdx
    p_pdx = sub.add_parser("pdx", help="Import/export JSON-only PDX data")
    pdx_sub = p_pdx.add_subparsers(dest="pdx_command", parser_class=SafeArgumentParser)

    p_pdx_import = pdx_sub.add_parser("import", help="Import a PDX JSON bundle as normalized BELIEF tool results")
    p_pdx_import.add_argument("input", help="Path to belief.pdx.v1 JSON bundle")
    p_pdx_import.add_argument(
        "--normalized-output",
        default="",
        help="Write normalized BELIEF tool-result JSON",
    )

    p_pdx_export = pdx_sub.add_parser("export", help="Export a BELIEF report/audit JSON as PDX JSON")
    p_pdx_export.add_argument("input_report", help="Path to BELIEF scan/audit JSON")
    p_pdx_export.add_argument("--pdx-output", required=True, help="Output PDX JSON path")

    # feedback
    p_feedback = sub.add_parser("feedback", help="Manage append-only BELIEF feedback JSONL")
    feedback_sub = p_feedback.add_subparsers(dest="feedback_command", parser_class=SafeArgumentParser)

    p_feedback_add = feedback_sub.add_parser("add", help="Append one feedback event")
    p_feedback_add.add_argument("--store-dir", default="", help="Feedback directory (default: ./belief_feedback)")
    p_feedback_add.add_argument("--case-id", required=True, help="Audit case id")
    p_feedback_add.add_argument("--verdict", required=True, help="Human verdict, e.g. false_positive or valid")
    p_feedback_add.add_argument("--reason", required=True, help="Short human-readable reason")
    p_feedback_add.add_argument("--source", default="human", help="Feedback source label")

    p_feedback_list = feedback_sub.add_parser("list", help="List feedback events")
    p_feedback_list.add_argument("--store-dir", default="", help="Feedback directory (default: ./belief_feedback)")
    p_feedback_list.add_argument("--case-id", default="", help="Optional case id filter")

    p_feedback_export = feedback_sub.add_parser("export", help="Export feedback JSONL")
    p_feedback_export.add_argument("--store-dir", default="", help="Feedback directory (default: ./belief_feedback)")
    p_feedback_export.add_argument("--output", required=True, help="Output JSONL path")

    p_feedback_apply = feedback_sub.add_parser("apply", help="Apply exact-case feedback to an audit JSON")
    p_feedback_apply.add_argument("--audit", required=True, help="Input BELIEF audit/report JSON")
    p_feedback_apply.add_argument("--store-dir", default="", help="Feedback directory (default: ./belief_feedback)")
    p_feedback_apply.add_argument("--output", required=True, help="Adjusted audit JSON output path")

    # dataset
    p_dataset = sub.add_parser("dataset", help="Export deterministic local datasets")
    dataset_sub = p_dataset.add_subparsers(dest="dataset_command", parser_class=SafeArgumentParser)

    p_dataset_export = dataset_sub.add_parser("export", help="Export a minimal SFT dataset from a BELIEF audit report")
    p_dataset_export.add_argument("--from-audit", required=True, help="Input BELIEF audit/report JSON")
    p_dataset_export.add_argument("--format", default="sft", choices=["sft"], help="Dataset format")
    p_dataset_export.add_argument("--output", required=True, help="Output JSONL path")

    p_dataset_validate = dataset_sub.add_parser("validate", help="Validate minimal SFT JSONL quality")
    p_dataset_validate.add_argument("--input", required=True, help="Input SFT JSONL path")

    # plan / execute-plan / run
    p_plan = sub.add_parser("plan", help="Build a safe BELIEF orchestration run plan")
    p_plan.add_argument("target", help="Path or URL target")
    p_plan.add_argument("--profile", default="local-safe", help="Tool profile id")
    p_plan.add_argument("--flags", default="auto", help="Comma-separated planning flags")
    p_plan.add_argument("--scope", default="", help="Optional scope JSON")
    p_plan.add_argument("--output-dir", default="out/run", help="Run output directory")
    p_plan.add_argument("--json-output", required=True, help="Run plan JSON output")
    p_plan.add_argument("--timeout", type=int, default=None, help="Override tool timeout seconds")
    p_plan.add_argument("--budget", default="balanced", choices=["fast", "balanced", "deep"], help="Planning budget")
    p_plan.add_argument("--reportability", action="store_true", help="Include reportability metadata in the local BELIEF scan step")

    p_execute_plan = sub.add_parser("execute-plan", help="Execute a BELIEF run plan safely")
    p_execute_plan.add_argument("plan", help="Run plan JSON")

    p_run = sub.add_parser("run", help="Classify, plan, execute, and summarize a local BELIEF run")
    p_run.add_argument("target", help="Path or URL target")
    p_run.add_argument("--profile", default="local-safe", help="Tool profile id")
    p_run.add_argument("--flags", default="auto", help="Comma-separated planning flags")
    p_run.add_argument("--scope", default="", help="Optional scope JSON")
    p_run.add_argument("--output-dir", default="out/run", help="Run output directory")
    p_run.add_argument("--reportability", action="store_true", help="Request reportability mode when scan integration is available")
    p_run.add_argument("--reason", action="store_true", help="Request offline reasoning when audit JSON is available")

    args = parser.parse_args()

    commands = {
        "analyze": cmd_analyze,
        "scope": cmd_scope,
        "target": cmd_target,
        "scan": cmd_scan,
        "review-patch": cmd_review_patch,
        "hunt": cmd_hunt,
        "self-check": cmd_self_check,
        "serve": cmd_serve,
        "benchmark": cmd_benchmark,
        "export": cmd_export,
        "frontier": cmd_frontier,
        "report": cmd_report,
        "cognitive": cmd_cognitive,
        "reason": cmd_reason,
        "tools": cmd_tools,
        "plan": cmd_plan,
        "execute-plan": cmd_execute_plan,
        "run": cmd_run,
        "pdx": cmd_pdx,
        "feedback": cmd_feedback,
        "dataset": cmd_dataset,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
