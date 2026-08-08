"""Frozen static runner for the transparent web-validation development corpus.

The runner is deliberately closed over BELIEF's committed development corpus.
It accepts no source path, module, callable, registry entry, or execution
target.  It performs two offline static-analysis repetitions and generates
non-executing ValidationPlan projections for matching audit cases.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from belief.static_analysis_pipeline import (
    STATIC_ANALYSIS_CATEGORIES,
    ScanRecord,
    StaticAnalysisDiagnostic,
    StaticAnalysisOptions,
    analyze_static_target,
)
from belief.validation.plan_models import canonical_digest
from belief.validation.plans import build_validation_plan

from .web_generalization import (
    WEB_VALIDATION_BENCHMARK_ID,
    WEB_VALIDATION_THRESHOLDS,
    verify_web_validation_development_corpus,
)


WEB_VALIDATION_STATIC_RUN_SCHEMA_VERSION = (
    "belief.web_validation_static_run.v1"
)
WEB_VALIDATION_STATIC_RUNNER_VERSION = (
    "belief.web_validation_static_runner.v1"
)
WEB_VALIDATION_STATIC_REPETITIONS = 2

_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_CORPUS_ROOT = _REPOSITORY_ROOT / "benchmark_web_validation"
_PREREGISTRATION_PATH = _CORPUS_ROOT / "preregistration.json"
_MANIFEST_PATH = _CORPUS_ROOT / "development" / "cases.json"
_SOURCE_ROOT = _CORPUS_ROOT / "development" / "sources"

_POSITIVE_STATUSES = frozenset({"actionable", "needs_review"})
_SAFE_STATUSES = frozenset({"protected", "false_positive_likely"})
_BINARY_GROUND_TRUTH = frozenset({"vulnerable", "safe"})
_PREDICTIONS = frozenset({"candidate", "safe", "abstain"})

_WEB_VALIDATION_STATIC_RUNNER_POLICY_JSON = json.dumps({
    "cohort": "development",
    "corpus_binding": "repository_bundled_exact_manifest",
    "repetitions": WEB_VALIDATION_STATIC_REPETITIONS,
    "analysis": {
        "selected_categories": list(STATIC_ANALYSIS_CATEGORIES),
        "audit_mode": True,
        "include_routes": True,
        "reportability": True,
        "deduplicate_audit_cases": True,
        "imported_tool_results": False,
    },
    "classification": {
        "positive_statuses": sorted(_POSITIVE_STATUSES),
        "safe_statuses": sorted(_SAFE_STATUSES),
        "no_matching_case": "safe",
        "conflicting_status_groups": "abstain",
        "unknown_status": "abstain",
        "ground_truth_not_used_for_prediction": True,
    },
    "metrics": {
        "binary_ground_truth": sorted(_BINARY_GROUND_TRUTH),
        "ambiguous_excluded_from_precision_and_recall": True,
        "vulnerable_abstention_counts_as_false_negative": True,
        "safe_abstention_counts_as_neither_tn_nor_fp": True,
        "static_abstention_gate_uses_all_development_cases": True,
        "zero_denominator_rate": 0.0,
    },
    "plan_scope": {
        "matching_audit_cases_only": True,
        "generation_is_offline": True,
        "execution_binding_created": False,
        "executable_plan_coverage_measured": False,
    },
    "boundaries": {
        "network_allowed": False,
        "subprocess_allowed": False,
        "shell_allowed": False,
        "docker_allowed": False,
        "external_project_allowed": False,
        "reserved_source_allowed": False,
        "susvibes_artifacts_allowed": False,
        "arbitrary_source_path_allowed": False,
        "arbitrary_module_allowed": False,
        "arbitrary_callable_allowed": False,
    },
}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
WEB_VALIDATION_STATIC_RUNNER_POLICY_DIGEST = canonical_digest(
    json.loads(_WEB_VALIDATION_STATIC_RUNNER_POLICY_JSON)
)


def evaluate_web_validation_development() -> dict[str, Any]:
    """Evaluate the exact bundled development corpus twice, without writes."""

    first = _evaluate_once()
    second = _evaluate_once()
    first_digest = str(first["deterministic_digest"])
    second_digest = str(second["deterministic_digest"])
    stable = first_digest == second_digest

    payload = copy.deepcopy(first)
    payload.pop("deterministic_digest", None)
    payload["reproducibility"] = {
        "repetitions": WEB_VALIDATION_STATIC_REPETITIONS,
        "run_digests": [first_digest, second_digest],
        "identical": stable,
        "stability_rate": 1.0 if stable else 0.0,
        "scope": "same_checkout_same_platform",
    }
    payload["gate_evaluations"][
        "minimum_semantic_digest_stability_rate"
    ] = _minimum_gate(
        1.0 if stable else 0.0,
        WEB_VALIDATION_THRESHOLDS[
            "minimum_semantic_digest_stability_rate"
        ],
    )
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_web_validation_development_result(
    output: str | Path,
) -> dict[str, Any]:
    """Create one result document and refuse corpus writes or overwrite."""

    destination = Path(output).resolve()
    corpus_root = _CORPUS_ROOT.resolve()
    if destination == corpus_root or destination.is_relative_to(corpus_root):
        raise ValueError(
            "web validation result must be written outside the corpus"
        )
    if destination.exists():
        raise ValueError(
            f"refusing to overwrite web validation result: {destination}"
        )

    payload = evaluate_web_validation_development()
    rendered = json.dumps(
        payload,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open(
            "x",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(rendered)
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite web validation result: {destination}"
        ) from exc
    return payload


def _evaluate_once() -> dict[str, Any]:
    verification = verify_web_validation_development_corpus(
        _CORPUS_ROOT
    )
    preregistration = _read_object(
        _PREREGISTRATION_PATH,
        "web validation preregistration",
    )
    manifest = _read_object(
        _MANIFEST_PATH,
        "web validation development manifest",
    )
    cases = _validated_manifest_cases(manifest, preregistration)

    analysis = analyze_static_target(
        _SOURCE_ROOT,
        StaticAnalysisOptions(
            max_files=len(cases),
            selected_categories=frozenset(
                _runner_policy()["analysis"][
                    "selected_categories"
                ]
            ),
            audit_mode=True,
            include_routes=True,
            reportability=True,
            dedup_audit_cases=True,
        ),
    )
    fatal_diagnostics = sorted({
        str(item.code)
        for item in analysis.diagnostics
        if str(item.code) == "source_read_failed"
    })
    if fatal_diagnostics:
        raise ValueError(
            "static runner encountered a fatal analysis diagnostic"
        )
    expected_files = {
        PurePosixPath(str(case["source_path"])).name
        for case in cases
    }
    observed_files = _observed_file_names(
        analysis.files,
        source_root=_SOURCE_ROOT,
    )
    if observed_files != expected_files:
        raise ValueError(
            "static runner did not scan the exact development source set"
        )

    records_by_file = _records_by_file(analysis.filtered_records)
    audit_cases_by_file = _audit_cases_by_file(analysis.audit_cases)
    diagnostics_by_file = _diagnostics_by_file(analysis.diagnostics)

    case_results = [
        _case_result(
            case,
            records=records_by_file.get(
                PurePosixPath(str(case["source_path"])).name,
                (),
            ),
            audit_cases=audit_cases_by_file.get(
                PurePosixPath(str(case["source_path"])).name,
                (),
            ),
            diagnostics=diagnostics_by_file.get(
                PurePosixPath(str(case["source_path"])).name,
                (),
            ),
        )
        for case in cases
    ]
    metrics = _static_metrics(case_results)
    gate_evaluations = _gate_evaluations(metrics)
    payload: dict[str, Any] = {
        "schema_version": WEB_VALIDATION_STATIC_RUN_SCHEMA_VERSION,
        "benchmark_id": WEB_VALIDATION_BENCHMARK_ID,
        "cohort": "development",
        "starting_commit": str(manifest["starting_commit"]),
        "preregistration_digest": str(
            preregistration["deterministic_digest"]
        ),
        "development_manifest_digest": str(
            manifest["deterministic_digest"]
        ),
        "runner_version": WEB_VALIDATION_STATIC_RUNNER_VERSION,
        "runner_policy": _runner_policy(),
        "runner_policy_digest": (
            WEB_VALIDATION_STATIC_RUNNER_POLICY_DIGEST
        ),
        "corpus_verification": {
            key: verification[key]
            for key in sorted(verification)
        },
        "scan_summary": {
            "files_scanned": len(observed_files),
            "finding_count": len(analysis.filtered_records),
            "audit_case_count": len(analysis.audit_cases),
            "diagnostic_count": len(analysis.diagnostics),
            "totals": dict(sorted(analysis.totals.items())),
        },
        "metrics": metrics,
        "gate_evaluations": gate_evaluations,
        "case_results": case_results,
        "execution_boundaries": {
            "static_analysis_only": True,
            "validation_plans_executed": False,
            "execution_bindings_created": False,
            "network_used": False,
            "subprocess_used": False,
            "shell_used": False,
            "docker_used": False,
            "external_project_used": False,
            "reserved_source_opened": False,
            "susvibes_artifacts_opened": False,
            "secpass_equivalent": False,
            "leaderboard_comparable": False,
        },
        "limitations": [
            (
                "Development labels are public and may be used only for "
                "development diagnostics, not a leaderboard claim."
            ),
            (
                "Generated ValidationPlans are non-executing and are not "
                "counted as executable until a closed registry binds them."
            ),
            (
                "Cross-platform agreement and every runtime gate remain "
                "unmeasured in this static checkpoint."
            ),
        ],
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def _validated_manifest_cases(
    manifest: Mapping[str, Any],
    preregistration: Mapping[str, Any],
) -> list[dict[str, Any]]:
    if manifest.get("benchmark_id") != WEB_VALIDATION_BENCHMARK_ID:
        raise ValueError("unexpected web validation benchmark id")
    if manifest.get("cohort") != "development":
        raise ValueError("static runner accepts the development cohort only")
    if (
        manifest.get("preregistration_digest")
        != preregistration.get("deterministic_digest")
    ):
        raise ValueError("development manifest is not preregistration-bound")
    rows = manifest.get("cases")
    if not isinstance(rows, list):
        raise ValueError("development manifest cases must be a list")
    if manifest.get("case_count") != len(rows) or not rows:
        raise ValueError("development manifest case_count is invalid")

    corpus = preregistration.get("corpus")
    if not isinstance(corpus, Mapping):
        raise ValueError("development corpus seal is unavailable")
    expected_ids = corpus.get("development_case_ids")
    if not isinstance(expected_ids, list):
        raise ValueError("development case seal is unavailable")

    normalized: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    for raw in rows:
        if not isinstance(raw, Mapping):
            raise ValueError("development case must be an object")
        case = copy.deepcopy(dict(raw))
        case_id = str(case.get("case_id") or "")
        source_path = str(case.get("source_path") or "")
        pure = PurePosixPath(source_path)
        if (
            not case_id
            or case_id in seen_ids
            or pure.parts[:2] != ("development", "sources")
            or len(pure.parts) != 3
            or pure.suffix != ".py"
            or pure.name in {"", ".", ".."}
            or source_path in seen_paths
        ):
            raise ValueError("development case identity or path is invalid")
        if case.get("ground_truth") not in {
            "vulnerable",
            "safe",
            "ambiguous",
        }:
            raise ValueError("development ground truth is invalid")
        if case.get("case_type") not in {
            "path_traversal_possible",
            "idor_bola_possible",
        }:
            raise ValueError("development case type is invalid")

        source = _CORPUS_ROOT.joinpath(*pure.parts).resolve()
        if (
            not source.is_relative_to(_SOURCE_ROOT.resolve())
            or not source.is_file()
        ):
            raise ValueError("development source escaped the sealed directory")
        observed_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        if observed_sha256 != case.get("source_sha256"):
            raise ValueError("development source digest mismatch")
        seen_ids.add(case_id)
        seen_paths.add(source_path)
        normalized.append(case)

    if seen_ids != set(str(item) for item in expected_ids):
        raise ValueError("development manifest case ids do not match the seal")
    return sorted(normalized, key=lambda item: str(item["case_id"]))


def _case_result(
    case: Mapping[str, Any],
    *,
    records: Sequence[ScanRecord],
    audit_cases: Sequence[Any],
    diagnostics: Sequence[StaticAnalysisDiagnostic],
) -> dict[str, Any]:
    source_path = str(case["source_path"])
    expected_type = str(case["case_type"])
    projected_cases = [
        _canonical_audit_case(item, source_path=source_path)
        for item in audit_cases
        if str(getattr(item, "case_type", "")) == expected_type
    ]
    projected_cases.sort(
        key=lambda item: (
            str(item.get("status") or ""),
            str(item.get("case_id") or ""),
        )
    )
    statuses = [
        str(item.get("status") or "")
        for item in projected_cases
    ]
    prediction = _static_prediction(statuses)
    plan_summaries = []
    for audit_case in projected_cases:
        plan = build_validation_plan(audit_case)
        plan_summaries.append({
            "plan_id": plan.plan_id,
            "subject_id": plan.subject_id,
            "case_status": plan.case_status,
            "strategy": plan.strategy,
            "evidence_gap_count": len(plan.evidence_gaps),
            "has_route_context": isinstance(
                plan.target.get("route_context"),
                Mapping,
            ),
            "execution_bound": False,
            "plan_digest": canonical_digest(plan.to_dict()),
        })
    plan_summaries.sort(key=lambda item: str(item["plan_id"]))

    finding_digests = sorted(
        canonical_digest(
            _canonical_finding_record(
                record,
                source_path=source_path,
            )
        )
        for record in records
    )
    result: dict[str, Any] = {
        "case_id": str(case["case_id"]),
        "family_id": str(case["family_id"]),
        "framework": str(case["framework"]),
        "case_type": expected_type,
        "variant": str(case["variant"]),
        "ground_truth": str(case["ground_truth"]),
        "source_path": source_path,
        "source_sha256": str(case["source_sha256"]),
        "observed_static_class": prediction,
        "matching_audit_case_count": len(projected_cases),
        "matching_statuses": statuses,
        "finding_count": len(records),
        "finding_digests": finding_digests,
        "diagnostic_codes": sorted({
            str(item.code)
            for item in diagnostics
            if str(item.code)
        }),
        "plan_count": len(plan_summaries),
        "plans": plan_summaries,
        "execution_binding_created": False,
    }
    result["semantic_digest"] = canonical_digest(result)
    return result


def _static_prediction(statuses: Sequence[str]) -> str:
    normalized = {str(item).strip().lower() for item in statuses}
    if not normalized:
        return "safe"
    if normalized - (_POSITIVE_STATUSES | _SAFE_STATUSES):
        return "abstain"
    positive = bool(normalized & _POSITIVE_STATUSES)
    safe = bool(normalized & _SAFE_STATUSES)
    if positive and safe:
        return "abstain"
    if positive:
        return "candidate"
    if safe:
        return "safe"
    return "abstain"


def _static_metrics(case_results: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    truth_counts = Counter(
        str(item.get("ground_truth") or "")
        for item in case_results
    )
    prediction_counts = Counter(
        str(item.get("observed_static_class") or "")
        for item in case_results
    )
    if set(prediction_counts) - _PREDICTIONS:
        raise ValueError("static runner produced an invalid prediction")

    tp = fp = tn = fn = 0
    binary_abstentions = 0
    ambiguous_predictions: Counter[str] = Counter()
    for item in case_results:
        truth = str(item.get("ground_truth") or "")
        observed = str(item.get("observed_static_class") or "")
        if truth == "ambiguous":
            ambiguous_predictions[observed] += 1
            continue
        if truth not in _BINARY_GROUND_TRUTH:
            raise ValueError("static metric received invalid ground truth")
        if observed == "abstain":
            binary_abstentions += 1
        if truth == "vulnerable":
            if observed == "candidate":
                tp += 1
            else:
                fn += 1
        elif observed == "candidate":
            fp += 1
        elif observed == "safe":
            tn += 1

    binary_total = sum(
        truth_counts[label]
        for label in _BINARY_GROUND_TRUTH
    )
    ambiguous_total = truth_counts["ambiguous"]
    plan_eligible = sum(
        1
        for item in case_results
        if int(item.get("matching_audit_case_count") or 0) > 0
    )
    plan_generated = sum(
        1
        for item in case_results
        if int(item.get("matching_audit_case_count") or 0) > 0
        and int(item.get("plan_count") or 0) > 0
    )
    return {
        "case_count": len(case_results),
        "ground_truth_counts": dict(sorted(truth_counts.items())),
        "prediction_counts": dict(sorted(prediction_counts.items())),
        "binary_case_count": binary_total,
        "ambiguous_case_count": ambiguous_total,
        "confusion": {
            "true_positive": tp,
            "false_positive": fp,
            "true_negative": tn,
            "false_negative": fn,
            "binary_abstention": binary_abstentions,
        },
        "static_precision": _rate(tp, tp + fp),
        "static_recall": _rate(tp, truth_counts["vulnerable"]),
        "static_binary_accuracy": _rate(tp + tn, binary_total),
        "static_abstention_rate": _rate(
            prediction_counts["abstain"],
            len(case_results),
        ),
        "binary_abstention_rate": _rate(
            binary_abstentions,
            binary_total,
        ),
        "ambiguous_prediction_counts": dict(
            sorted(ambiguous_predictions.items())
        ),
        "ambiguous_abstention_rate": _rate(
            ambiguous_predictions["abstain"],
            ambiguous_total,
        ),
        "plan_eligible_case_count": plan_eligible,
        "plan_generated_case_count": plan_generated,
        "plan_generation_coverage": _rate(
            plan_generated,
            plan_eligible,
        ),
        "executable_plan_coverage": None,
    }


def _gate_evaluations(metrics: Mapping[str, Any]) -> dict[str, Any]:
    gates = {
        "maximum_abstention_rate": _maximum_gate(
            float(metrics["static_abstention_rate"]),
            WEB_VALIDATION_THRESHOLDS["maximum_abstention_rate"],
        ),
        "minimum_static_precision": _minimum_gate(
            float(metrics["static_precision"]),
            WEB_VALIDATION_THRESHOLDS["minimum_static_precision"],
        ),
        "minimum_static_recall": _minimum_gate(
            float(metrics["static_recall"]),
            WEB_VALIDATION_THRESHOLDS["minimum_static_recall"],
        ),
    }
    for name in sorted(
        set(WEB_VALIDATION_THRESHOLDS) - set(gates)
    ):
        gates[name] = {
            "status": "not_measured",
            "threshold": WEB_VALIDATION_THRESHOLDS[name],
            "reason": _unmeasured_reason(name),
        }
    return dict(sorted(gates.items()))


def _minimum_gate(value: float, threshold: float) -> dict[str, Any]:
    return {
        "status": "pass" if value >= threshold else "fail",
        "comparison": ">=",
        "value": value,
        "threshold": threshold,
    }


def _maximum_gate(value: float, threshold: float) -> dict[str, Any]:
    return {
        "status": "pass" if value <= threshold else "fail",
        "comparison": "<=",
        "value": value,
        "threshold": threshold,
    }


def _unmeasured_reason(name: str) -> str:
    if name == "minimum_executable_plan_coverage":
        return "plans are generated but not bound to an execution registry"
    if name == "minimum_windows_linux_outcome_agreement_rate":
        return "only one platform is evaluated per local result"
    if name == "minimum_semantic_digest_stability_rate":
        return "assigned after the two frozen runner repetitions"
    return "requires closed-registry runtime validation"


def _observed_file_names(
    files: Sequence[Path],
    *,
    source_root: Path,
) -> set[str]:
    root = source_root.resolve()
    observed: set[str] = set()
    for raw in files:
        path = Path(raw).resolve()
        if not path.is_relative_to(root):
            raise ValueError("static analysis escaped the source directory")
        relative = path.relative_to(root)
        if len(relative.parts) != 1 or relative.suffix != ".py":
            raise ValueError("static analysis returned an unexpected file")
        observed.add(relative.name)
    if len(observed) != len(files):
        raise ValueError("static analysis returned duplicate files")
    return observed


def _records_by_file(
    records: Sequence[ScanRecord],
) -> dict[str, tuple[ScanRecord, ...]]:
    grouped: defaultdict[str, list[ScanRecord]] = defaultdict(list)
    for record in records:
        grouped[_flat_file_name(record.finding.file)].append(record)
    return {
        name: tuple(rows)
        for name, rows in grouped.items()
    }


def _audit_cases_by_file(
    cases: Sequence[Any],
) -> dict[str, tuple[Any, ...]]:
    grouped: defaultdict[str, list[Any]] = defaultdict(list)
    for case in cases:
        grouped[_flat_file_name(getattr(case, "file", ""))].append(case)
    return {
        name: tuple(rows)
        for name, rows in grouped.items()
    }


def _diagnostics_by_file(
    diagnostics: Sequence[StaticAnalysisDiagnostic],
) -> dict[str, tuple[StaticAnalysisDiagnostic, ...]]:
    grouped: defaultdict[str, list[StaticAnalysisDiagnostic]] = (
        defaultdict(list)
    )
    for item in diagnostics:
        if item.file:
            grouped[_flat_file_name(item.file)].append(item)
    return {
        name: tuple(rows)
        for name, rows in grouped.items()
    }


def _flat_file_name(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    pure = PurePosixPath(normalized)
    if (
        not normalized
        or pure.is_absolute()
        or len(pure.parts) != 1
        or pure.suffix != ".py"
    ):
        raise ValueError("analysis evidence has an unexpected source path")
    return pure.name


def _canonical_audit_case(
    case: Any,
    *,
    source_path: str,
) -> dict[str, Any]:
    serializer = getattr(case, "to_dict", None)
    payload = serializer() if callable(serializer) else None
    if not isinstance(payload, Mapping):
        raise ValueError("static audit case is not serializable")
    result = copy.deepcopy(dict(payload))
    result["file"] = source_path
    route = result.get("route_context")
    if isinstance(route, dict) and "file" in route:
        route["file"] = source_path
    return result


def _canonical_finding_record(
    record: ScanRecord,
    *,
    source_path: str,
) -> dict[str, Any]:
    payload = record.finding.to_dict()
    if not isinstance(payload, Mapping):
        raise ValueError("static finding is not serializable")
    result = copy.deepcopy(dict(payload))
    result["file"] = source_path
    result["category"] = record.category
    return result


def _read_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be an object")
    return payload


def _runner_policy() -> dict[str, Any]:
    return json.loads(_WEB_VALIDATION_STATIC_RUNNER_POLICY_JSON)


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


__all__ = [
    "WEB_VALIDATION_STATIC_REPETITIONS",
    "WEB_VALIDATION_STATIC_RUNNER_POLICY_DIGEST",
    "WEB_VALIDATION_STATIC_RUNNER_VERSION",
    "WEB_VALIDATION_STATIC_RUN_SCHEMA_VERSION",
    "evaluate_web_validation_development",
    "write_web_validation_development_result",
]
