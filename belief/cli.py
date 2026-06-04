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
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Set

from .config import BeliefConfig
from .orchestrator import Orchestrator


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


@dataclass(frozen=True)
class ScanRecord:
    category: str
    finding: Any


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
    from .parser import CodeParser
    from .structural import StructuralExtractor
    from .security_patterns import SecurityPatternExtractor
    from .taint import TaintEngine
    from .temporal import TemporalChecker
    dataflow_enabled = _scan_dataflow_enabled(args)
    routes_enabled = _scan_routes_enabled(args)
    if dataflow_enabled:
        from .dataflow import analyze_source_dataflow, attach_dataflow_to_findings
    if _scan_hypotheses_enabled(args):
        from .guarantee_index import build_guarantee_index
        from .hypothesis_engine import attach_hypotheses_to_findings
        from .invariant_miner import InvariantMiner
    if _scan_audit_cases_enabled(args):
        from .audit_case import (
            attach_route_context_to_audit_cases,
            build_audit_cases,
            summarize_guarantees,
        )
    if routes_enabled:
        from .routes import extract_routes_from_files

    setup_logging(args.verbose)
    target = Path(args.target_path)
    try:
        selected_categories = _parse_scan_only(args.only)
    except ValueError as exc:
        safe_print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    if getattr(args, "audit_mode", False) and getattr(args, "only", "all") == "all":
        selected_categories = {"security", "taint"}

    parser = CodeParser(str(target))
    files = parser._collect_python_files()[:args.max_files]
    routes = []
    if routes_enabled:
        route_root = target if target.is_dir() else target.parent
        routes = extract_routes_from_files(files, target_root=route_root)

    structural = StructuralExtractor()
    security = SecurityPatternExtractor()
    taint = TaintEngine()
    temporal = TemporalChecker()
    invariant_miner = InvariantMiner() if _scan_hypotheses_enabled(args) else None

    total = {"structural": 0, "security": 0, "taint": 0, "temporal": 0}
    scan_records: list[ScanRecord] = []
    invariant_beliefs = []
    source_contexts: dict[str, str] = {}
    dataflow_summaries = {}

    for f in files:
        try:
            source = f.read_text(errors="replace")
        except Exception:
            continue

        rel = str(f.relative_to(target)) if target.is_dir() else str(f)
        source_contexts[rel] = source
        if dataflow_enabled:
            dataflow_summaries[rel] = analyze_source_dataflow(source, rel)
        if invariant_miner is not None:
            invariant_beliefs.extend(invariant_miner.extract(source, rel))

        sb = structural.extract(source, rel)
        total["structural"] += len(sb)
        scan_records.extend(_beliefs_to_scan_records("structural", sb))

        sec = security.extract(source, rel)
        total["security"] += len(sec)
        scan_records.extend(_beliefs_to_scan_records("security", sec))

        tb = taint.analyze_to_beliefs(source, rel)
        total["taint"] += len(tb)
        scan_records.extend(_beliefs_to_scan_records("taint", tb))

        temp = temporal.check(source, rel)
        total["temporal"] += len(temp)
        scan_records.extend(_beliefs_to_scan_records("temporal", temp))

    cycle_metadata = None
    if getattr(args, "include_cycles", False):
        from .cycle_detector import detect_cycle_findings_with_metadata

        parser.parse()
        cycle_findings, cycle_metadata = detect_cycle_findings_with_metadata(
            parser.call_graph,
            max_cycles=args.max_cycles,
        )
        total["cycles"] = len(cycle_findings)
        scan_records.extend(
            ScanRecord("cycles", _with_scan_category(finding, "cycles"))
            for finding in cycle_findings
        )
    elif "cycles" in selected_categories and selected_categories != SCAN_CATEGORY_SET:
        safe_print(
            "  Cycle analysis not enabled; use --include-cycles to populate cycle findings."
        )

    if dataflow_enabled:
        attach_dataflow_to_findings(
            [record.finding for record in scan_records],
            dataflow_summaries,
            show_dataflow=bool(getattr(args, "show_dataflow", False)),
        )

    guarantee_index = None
    if _scan_hypotheses_enabled(args):
        guarantee_index = build_guarantee_index(files, target_root=target)
        invariant_beliefs = _dedupe_beliefs_by_id([
            *invariant_beliefs,
            *guarantee_index.all_guarantees,
        ])
        attach_hypotheses_to_findings(
            [record.finding for record in scan_records],
            invariant_beliefs,
            show_proofs=bool(args.show_proofs),
            guarantee_index=guarantee_index,
            local_contexts=source_contexts,
            dataflow_summaries=dataflow_summaries if dataflow_enabled else None,
            show_dataflow=bool(getattr(args, "show_dataflow", False)),
        )
    hypothesis_count = sum(
        1 for record in scan_records
        if isinstance(getattr(record.finding, "metadata", None), dict)
        and isinstance(record.finding.metadata.get("hypothesis"), dict)
    )
    dataflow_path_count = sum(
        len(summary.paths) for summary in dataflow_summaries.values()
    ) if dataflow_enabled else 0

    filtered_records = _filter_scan_records(
        scan_records,
        selected_categories=selected_categories,
        min_confidence=args.min_confidence,
        hide_structural=args.hide_structural,
        only_hypothesis_status=(
            args.only_hypotheses if _scan_hypotheses_enabled(args) else "all"
        ),
    )
    audit_cases = []
    audit_case_clusters_payload = []
    guarantee_summary = {}
    if _scan_audit_cases_enabled(args):
        audit_cases = build_audit_cases(
            [record.finding for record in scan_records],
            dataflow_summaries=dataflow_summaries if dataflow_enabled else None,
        )
        if routes_enabled:
            audit_cases = attach_route_context_to_audit_cases(
                audit_cases,
                routes,
                source_contexts=source_contexts,
            )
        guarantee_summary = summarize_guarantees(invariant_beliefs)
        if getattr(args, "dedup_audit_cases", False):
            from .audit_dedup import cluster_audit_cases, cluster_to_dict

            audit_case_clusters = cluster_audit_cases(audit_cases)
            audit_cases = [cluster["representative"] for cluster in audit_case_clusters]
            audit_case_clusters_payload = [
                cluster_to_dict(cluster) for cluster in audit_case_clusters
            ]

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


def _beliefs_to_scan_records(category: str, beliefs: list[Any]) -> list[ScanRecord]:
    from .models import Finding

    records = []
    for belief in beliefs:
        records.append(
            ScanRecord(
                category,
                _with_scan_category(Finding.from_belief(belief, source=category), category),
            )
        )
    return records


def _with_scan_category(finding: Any, category: str) -> Any:
    metadata = dict(getattr(finding, "metadata", {}) or {})
    metadata.setdefault("category", category)
    finding.metadata = metadata
    return finding


def _filter_scan_records(
    records: list[ScanRecord],
    *,
    selected_categories: set[str],
    min_confidence: float,
    hide_structural: bool,
    only_hypothesis_status: str = "all",
) -> list[ScanRecord]:
    categories = set(selected_categories)
    if hide_structural:
        categories.discard("structural")
    status_filter = (only_hypothesis_status or "all").strip().lower()
    return [
        record for record in records
        if record.category in categories
        and float(getattr(record.finding, "confidence", 0.0)) >= min_confidence
        and (
            status_filter == "all"
            or (
                isinstance(getattr(record.finding, "metadata", None), dict)
                and isinstance(record.finding.metadata.get("hypothesis"), dict)
                and record.finding.metadata["hypothesis"].get("status") == status_filter
            )
        )
    ]


def _sort_scan_records(records: list[ScanRecord]) -> list[ScanRecord]:
    return sorted(records, key=_scan_record_sort_key)


def _scan_record_sort_key(record: ScanRecord) -> tuple:
    finding = record.finding
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return (
        -float(getattr(finding, "confidence", 0.0)),
        severity_order.get(str(getattr(finding, "severity", "info")).lower(), 9),
        record.category,
        str(getattr(finding, "file", "")),
        getattr(finding, "line", None) or 0,
        str(getattr(finding, "rule_id", "")),
        str(getattr(finding, "dedup_key", "")),
    )


def _dedupe_scan_records(records: list[ScanRecord]) -> list[ScanRecord]:
    seen = set()
    deduped: list[ScanRecord] = []
    for record in records:
        key = _scan_record_dedup_key(record)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(record)
    return deduped


def _scan_record_dedup_key(record: ScanRecord) -> tuple:
    finding = record.finding
    file = str(getattr(finding, "file", ""))
    line = getattr(finding, "line", None)
    rule_id = str(getattr(finding, "rule_id", ""))
    dedup_key = str(getattr(finding, "dedup_key", ""))
    if dedup_key:
        return (file, line, rule_id, dedup_key)
    fallback_text = " ".join([
        str(getattr(finding, "evidence", "")),
        str(getattr(finding, "title", "")),
        str(getattr(finding, "description", "")),
    ])
    normalized = re.sub(r"\s+", " ", fallback_text).strip().lower()
    return (file, line, rule_id, normalized)


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
        or bool(getattr(args, "hide_structural", False))
        or int(getattr(args, "top", 15) or 15) != 15
        or getattr(args, "only_hypotheses", "all") != "all"
        or bool(getattr(args, "interesting_only", False))
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
        or bool(getattr(args, "dedup_audit_cases", False))
    )


def _scan_routes_enabled(args) -> bool:
    return (
        bool(getattr(args, "routes", False))
        or bool(getattr(args, "show_routes", False))
        or bool(getattr(args, "routes_json", ""))
    )


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
        },
        "counts": {
            "total_before_filter": len(before_records),
            "total_after_filter": len(after_records),
            "by_category_before_filter": _scan_counts(before_records),
            "by_category_after_filter": _scan_counts(after_records),
            "audit_cases": _audit_case_counts(audit_cases),
            "audit_case_clusters": len(audit_case_clusters),
            "routes": len(routes),
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


def _audit_case_counts(audit_cases: list[Any]) -> dict[str, int]:
    counts = {status: 0 for status in ("actionable", "needs_review", "protected", "false_positive_likely")}
    for case in audit_cases:
        counts[case.status] = counts.get(case.status, 0) + 1
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


def _dedupe_beliefs_by_id(beliefs: list[Any]) -> list[Any]:
    seen = set()
    deduped = []
    for belief in beliefs:
        key = (
            getattr(belief, "id", ""),
            (getattr(belief, "source_metadata", {}) or {}).get("propagated_via", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(belief)
    return deduped


def cmd_serve(args):
    """Start the REST API server."""
    from .api_server import APIServer

    setup_logging(args.verbose)
    server = APIServer(host=args.host, port=args.port)
    server.start()


def cmd_benchmark(args):
    """Run benchmarks on example codebases."""
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
    from .tools.errors import ToolSafetyError
    from .tools.schemas import to_jsonable

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
        payload = to_jsonable(execution)
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.tools_command == "import":
        bridge = registry.get(args.tool_id)
        importer = getattr(bridge, "import_file", None)
        if importer is None:
            safe_print(f"ERROR: {args.tool_id} does not implement passive import.", file=sys.stderr)
            sys.exit(2)
        result = importer(Path(args.file))
        payload = to_jsonable(result)
        safe_print(json.dumps(payload, indent=2, sort_keys=True))
        return

    safe_print("ERROR: missing tools subcommand", file=sys.stderr)
    sys.exit(2)


def main():
    parser = SafeArgumentParser(
        prog="belief",
        description="BELIEF — Belief Extraction and Logical Inference for Exploitable Flaws",
    )
    parser.add_argument("-v", "--verbose", action="store_true", default=True)
    sub = parser.add_subparsers(dest="command", parser_class=SafeArgumentParser)

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

    # benchmark
    p_bench = sub.add_parser("benchmark", help="Run performance benchmarks")
    p_bench.add_argument("--target", default="", help="Specific directory to benchmark")
    p_bench.add_argument("--max-files", type=int, default=100)

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

    # tools
    p_tools = sub.add_parser("tools", help="List, check, run, and import tool bridge results")
    tools_sub = p_tools.add_subparsers(dest="tools_command", parser_class=SafeArgumentParser)

    tools_sub.add_parser("list", help="List built-in BELIEF tool bridges")

    p_tools_info = tools_sub.add_parser("info", help="Show one bridge manifest")
    p_tools_info.add_argument("tool_id", help="Tool bridge id, e.g. semgrep")

    tools_sub.add_parser("check", help="Check bridge availability and risk profiles")

    p_tools_run = tools_sub.add_parser("run", help="Run a safe external bridge")
    p_tools_run.add_argument("tool_id", help="Tool bridge id")
    p_tools_run.add_argument("--target", default="", help="Local target path for external CLI bridges")
    p_tools_run.add_argument("--file", default="", help="Optional import/config file")
    p_tools_run.add_argument("--output-dir", default="out/tools", help="Output directory for artifacts")
    p_tools_run.add_argument("--timeout", type=int, default=300, help="External command timeout seconds")
    p_tools_run.add_argument("--allow-dynamic", action="store_true", help="Allow dynamic tool behavior")
    p_tools_run.add_argument("--allow-network", action="store_true", help="Allow network-capable tool behavior")
    p_tools_run.add_argument("--scope-file", default="", help="Explicit scope file required for dynamic tools")

    p_tools_import = tools_sub.add_parser("import", help="Import an existing passive tool result")
    p_tools_import.add_argument("tool_id", help="Tool bridge id")
    p_tools_import.add_argument("--file", required=True, help="JSON/SARIF file to import")

    args = parser.parse_args()

    commands = {
        "analyze": cmd_analyze,
        "scan": cmd_scan,
        "hunt": cmd_hunt,
        "self-check": cmd_self_check,
        "serve": cmd_serve,
        "benchmark": cmd_benchmark,
        "export": cmd_export,
        "frontier": cmd_frontier,
        "report": cmd_report,
        "cognitive": cmd_cognitive,
        "tools": cmd_tools,
    }

    handler = commands.get(args.command)
    if handler:
        handler(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
