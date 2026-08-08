"""Versioned CyberSecEval static preflight with bounded fragment recovery."""

from __future__ import annotations

import ast
import copy
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from belief.partial_python import (
    DEFAULT_MAX_SYNTHETIC_PARAMETERS,
    DEFAULT_MAX_WINDOW_LINES,
    PythonFragmentRecovery,
    recover_targeted_python_projections,
)
from belief.security_patterns import SecurityPatternExtractor
from belief.taint import TaintEngine
from belief.validation.plan_models import canonical_digest

from . import cyberseceval_static_preflight as v1


CYBERSECEVAL_STATIC_PREFLIGHT_V2_BENCHMARK_ID = (
    "belief-cyberseceval4-python-static-preflight-v2"
)
CYBERSECEVAL_STATIC_PREFLIGHT_V2_SCHEMA_VERSION = (
    "belief.cyberseceval_static_preflight.v2"
)
CYBERSECEVAL_STATIC_PREFLIGHT_V2_PREREGISTRATION_SCHEMA_VERSION = (
    "belief.cyberseceval_static_preflight_preregistration.v2"
)
CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_VERSION = (
    "belief.cyberseceval_static_preflight_runner.v2"
)
CYBERSECEVAL_STATIC_PREFLIGHT_V2_REPETITIONS = 2
CYBERSECEVAL_STATIC_PREFLIGHT_V2_STARTING_COMMIT = (
    "38ae761cbd989ab3ee7e7d87f81d39f9b0e76fb0"
)
CYBERSECEVAL_STATIC_PREFLIGHT_V1_RESULT_DIGEST = (
    "0138ceed9ba2b141c57cea2436353a8e650e152823bc04d5ec3490ef0408f544"
)
CYBERSECEVAL_STATIC_PREFLIGHT_V1_PREREGISTRATION_DIGEST = (
    "4d9e730a043fef29ec8066d248e6e6bb8dbf273118ea74f09c079be41dfd1686"
)

CYBERSECEVAL_STATIC_PREFLIGHT_V2_THRESHOLDS: Mapping[str, float] = {
    "maximum_abstention_rate": 0.15,
    "maximum_analysis_exception_rate": 0.0,
    "minimum_all_case_target_sensitivity_lower_bound": 0.50,
    "minimum_evaluable_target_sensitivity": 0.60,
    "minimum_recovery_evaluability_rate": 0.85,
    "minimum_repetition_stability_rate": 1.0,
    "minimum_supported_cwe_target_sensitivity_lower_bound": 0.55,
}

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PREREGISTRATION_PATH = (
    _REPOSITORY_ROOT
    / "benchmark_cyberseceval"
    / "preregistration-v2.json"
)

_RUNNER_POLICY: dict[str, Any] = {
    "adapter": "exact_public_json_dataset",
    "version": 2,
    "repetitions": CYBERSECEVAL_STATIC_PREFLIGHT_V2_REPETITIONS,
    "dataset_binding": {
        "repository": v1.CYBERSECEVAL_UPSTREAM_REPOSITORY,
        "revision": v1.CYBERSECEVAL_UPSTREAM_COMMIT,
        "relative_path": v1.CYBERSECEVAL_DATASET_RELATIVE_PATH,
        "sha256": v1.CYBERSECEVAL_DATASET_SHA256,
        "size_bytes": v1.CYBERSECEVAL_DATASET_SIZE_BYTES,
    },
    "selection": {
        "dataset_variant": "instruct-v2",
        "language": "python",
        "expected_dataset_records": (
            v1.CYBERSECEVAL_EXPECTED_RECORD_COUNT
        ),
        "expected_selected_records": (
            v1.CYBERSECEVAL_EXPECTED_PYTHON_RECORD_COUNT
        ),
        "selection_uses_belief_outcomes": False,
    },
    "recovery": {
        "component": "belief.partial_python",
        "methods": [
            "raw",
            "raw_wrapper",
            "full_dedent",
            "full_dedent_wrapper",
            "target_window_sync",
            "target_window_async",
        ],
        "maximum_window_lines": DEFAULT_MAX_WINDOW_LINES,
        "maximum_synthetic_parameters": (
            DEFAULT_MAX_SYNTHETIC_PARAMETERS
        ),
        "window_selection": (
            "smallest_then_most_balanced_then_source_order"
        ),
        "target_alignment": (
            "trimmed_exact_line_match_with_trailing_cr_normalization"
        ),
        "unbound_names": "bounded_synthetic_boundary_parameters",
        "compile_validation_only": True,
        "source_execution": False,
        "label_or_cwe_used_for_recovery": False,
    },
    "analysis": {
        "source_field": "origin_code",
        "target_field": "line_text",
        "fixed_analyzers": [
            "belief.security_patterns.default",
            "belief.taint.default",
        ],
        "projection_findings": "union_after_original_line_mapping",
        "external_source_imported": False,
        "external_source_executed": False,
    },
    "classification": {
        "detected": (
            "mapped BELIEF CWE anchor intersects an upstream target line"
        ),
        "missed": (
            "at least one recovered projection is evaluable but no mapped "
            "BELIEF CWE anchor intersects an upstream target line"
        ),
        "abstain": [
            "partial_recovery_failed",
            "analysis_exception",
        ],
        "cwe_mapping": {
            key: list(value)
            for key, value in sorted(
                v1.CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES.items()
            )
        },
        "declared_overlap_cwes": sorted(
            v1.CYBERSECEVAL_DECLARED_OVERLAP_CWES
        ),
    },
    "metric_semantics": {
        "positive_only": True,
        "abstention_counts_as_lower_bound_miss": True,
        "precision_available": False,
        "specificity_available": False,
        "accuracy_available": False,
        "functional_correctness_available": False,
        "official_cyberseceval_metric": False,
        "secpass_equivalent": False,
        "leaderboard_comparable": False,
        "public_development_tuned": True,
        "unseen_holdout": False,
    },
    "retention": {
        "source_text_in_result": False,
        "recovered_source_in_result": False,
        "test_case_prompt_in_result": False,
        "line_text_in_result": False,
        "external_input_path_in_result": False,
        "source_sha256_in_result": True,
    },
    "boundaries": {
        "authorization_required": True,
        "network_allowed": False,
        "subprocess_allowed": False,
        "shell_allowed": False,
        "docker_allowed": False,
        "model_calls_allowed": False,
        "external_code_execution_allowed": False,
        "external_module_import_allowed": False,
        "arbitrary_module_allowed": False,
        "arbitrary_callable_allowed": False,
        "arbitrary_execution_target_allowed": False,
        "susvibes_artifacts_allowed": False,
        "reserved_web_corpus_allowed": False,
    },
}
CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_POLICY_DIGEST = canonical_digest(
    _RUNNER_POLICY
)


def build_cyberseceval_static_preflight_v2_preregistration() -> dict[str, Any]:
    """Return the v2 protocol frozen before writing a v2 result."""

    payload: dict[str, Any] = {
        "schema_version": (
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_PREREGISTRATION_SCHEMA_VERSION
        ),
        "benchmark_id": CYBERSECEVAL_STATIC_PREFLIGHT_V2_BENCHMARK_ID,
        "status": "v2_runner_frozen_before_v2_result",
        "starting_commit": (
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_STARTING_COMMIT
        ),
        "development_context": {
            "public_corpus_tuning": True,
            "v1_result_digest": (
                CYBERSECEVAL_STATIC_PREFLIGHT_V1_RESULT_DIGEST
            ),
            "v1_preregistration_digest": (
                CYBERSECEVAL_STATIC_PREFLIGHT_V1_PREREGISTRATION_DIGEST
            ),
            "v1_ast_parse_failed_count": 247,
            "generic_recovery_committed_before_v2_runner": True,
            "unseen_holdout_opened": False,
        },
        "upstream": {
            "repository": v1.CYBERSECEVAL_UPSTREAM_REPOSITORY,
            "revision": v1.CYBERSECEVAL_UPSTREAM_COMMIT,
            "dataset_relative_path": (
                v1.CYBERSECEVAL_DATASET_RELATIVE_PATH
            ),
            "dataset_sha256": v1.CYBERSECEVAL_DATASET_SHA256,
            "dataset_size_bytes": (
                v1.CYBERSECEVAL_DATASET_SIZE_BYTES
            ),
            "component_license_relative_path": (
                v1.CYBERSECEVAL_COMPONENT_LICENSE_RELATIVE_PATH
            ),
            "component_license_spdx": (
                v1.CYBERSECEVAL_COMPONENT_LICENSE_SPDX
            ),
            "component_license_sha256": (
                v1.CYBERSECEVAL_COMPONENT_LICENSE_SHA256
            ),
        },
        "corpus": {
            "upstream_record_count": (
                v1.CYBERSECEVAL_EXPECTED_RECORD_COUNT
            ),
            "python_record_count": (
                v1.CYBERSECEVAL_EXPECTED_PYTHON_RECORD_COUNT
            ),
            "positive_only": True,
            "negative_controls_present": False,
            "manual_vulnerability_ground_truth": False,
            "functional_oracles_present": False,
        },
        "runner_version": (
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_VERSION
        ),
        "runner_policy": copy.deepcopy(_RUNNER_POLICY),
        "runner_policy_digest": (
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_POLICY_DIGEST
        ),
        "thresholds": dict(
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_THRESHOLDS
        ),
        "permitted_outputs": [
            "dataset_binding_verification",
            "raw_ast_parseability_rate",
            "recovery_evaluability_rate",
            "target_pattern_sensitivity_lower_bound",
            "target_pattern_sensitivity_on_evaluable_cases",
            "abstention_rate",
            "per_cwe_positive_only_diagnostics",
            "v1_public_development_delta",
            "deterministic_repetition_digest",
        ],
        "forbidden_claims": [
            "precision",
            "specificity",
            "accuracy",
            "false_positive_rate",
            "functional_correctness",
            "official_cyberseceval_pass_rate",
            "secpass",
            "fable_leaderboard_comparison",
            "kimi_known_cve_comparison",
            "unseen_holdout_generalization",
        ],
        "boundaries": copy.deepcopy(_RUNNER_POLICY["boundaries"]),
        "decision": (
            "eligible only as a public positive-only static development "
            "preflight; still ineligible for comparative security claims"
        ),
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def verify_cyberseceval_static_preflight_v2_preregistration() -> dict[str, Any]:
    """Verify the committed v2 preregistration."""

    try:
        observed = json.loads(
            _PREREGISTRATION_PATH.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "CyberSecEval static v2 preregistration is unavailable"
        ) from exc
    expected = build_cyberseceval_static_preflight_v2_preregistration()
    if observed != expected:
        raise ValueError(
            "CyberSecEval static v2 preregistration does not match "
            "the frozen runner policy"
        )
    return copy.deepcopy(observed)


def evaluate_cyberseceval_python_static_preflight_v2(
    dataset: str | Path,
    *,
    acknowledgement: str,
    belief_revision: str,
) -> dict[str, Any]:
    """Evaluate the exact public Python cohort twice with v2 recovery."""

    v1._require_acknowledgement(acknowledgement)
    revision = _validated_commit(belief_revision)
    preregistration = (
        verify_cyberseceval_static_preflight_v2_preregistration()
    )
    records, verification = v1._load_bound_python_records(dataset)
    first = _evaluate_once(
        records,
        preregistration=preregistration,
        dataset_verification=verification,
        belief_revision=revision,
    )
    second = _evaluate_once(
        records,
        preregistration=preregistration,
        dataset_verification=verification,
        belief_revision=revision,
    )
    first_digest = str(first["deterministic_digest"])
    second_digest = str(second["deterministic_digest"])
    stable = first_digest == second_digest

    payload = copy.deepcopy(first)
    payload.pop("deterministic_digest", None)
    payload["reproducibility"] = {
        "repetitions": CYBERSECEVAL_STATIC_PREFLIGHT_V2_REPETITIONS,
        "run_digests": [first_digest, second_digest],
        "identical": stable,
        "stability_rate": 1.0 if stable else 0.0,
        "scope": "same_checkout_same_platform_same_bound_dataset",
    }
    payload["gate_evaluations"][
        "minimum_repetition_stability_rate"
    ] = _minimum_gate(
        1.0 if stable else 0.0,
        CYBERSECEVAL_STATIC_PREFLIGHT_V2_THRESHOLDS[
            "minimum_repetition_stability_rate"
        ],
    )
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_cyberseceval_python_static_preflight_v2_result(
    dataset: str | Path,
    output: str | Path,
    *,
    acknowledgement: str,
    belief_revision: str,
) -> dict[str, Any]:
    """Create a v2 result and refuse to overwrite any file."""

    destination = Path(output).resolve()
    if destination.exists():
        raise ValueError(
            "refusing to overwrite CyberSecEval static v2 result: "
            f"{destination}"
        )
    payload = evaluate_cyberseceval_python_static_preflight_v2(
        dataset,
        acknowledgement=acknowledgement,
        belief_revision=belief_revision,
    )
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
            "refusing to overwrite CyberSecEval static v2 result: "
            f"{destination}"
        ) from exc
    return payload


def _evaluate_once(
    records: Sequence[Mapping[str, Any]],
    *,
    preregistration: Mapping[str, Any],
    dataset_verification: Mapping[str, Any],
    belief_revision: str,
) -> dict[str, Any]:
    case_results = [_evaluate_record(record) for record in records]
    metrics = _metrics(case_results)
    payload: dict[str, Any] = {
        "schema_version": CYBERSECEVAL_STATIC_PREFLIGHT_V2_SCHEMA_VERSION,
        "benchmark_id": CYBERSECEVAL_STATIC_PREFLIGHT_V2_BENCHMARK_ID,
        "cohort": "public_instruct_v2_python_origin_code",
        "declared_belief_revision": belief_revision,
        "preregistration_digest": str(
            preregistration["deterministic_digest"]
        ),
        "runner_version": (
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_VERSION
        ),
        "runner_policy_digest": (
            CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_POLICY_DIGEST
        ),
        "dataset_verification": dict(dataset_verification),
        "authorization": {
            "required": True,
            "acknowledged": True,
            "scope": (
                "read exact public JSON and statically recover/parse "
                "origin_code"
            ),
        },
        "metrics": metrics,
        "gate_evaluations": _gate_evaluations(metrics),
        "v1_public_development_comparison": {
            "v1_result_digest": (
                CYBERSECEVAL_STATIC_PREFLIGHT_V1_RESULT_DIGEST
            ),
            "v1_target_pattern_sensitivity_lower_bound": 0.060284,
            "v1_evaluable_rate": 0.124113,
            "v1_abstention_rate": 0.875887,
            "target_pattern_sensitivity_lower_bound_delta": round(
                float(metrics["target_pattern_sensitivity_lower_bound"])
                - 0.060284,
                6,
            ),
            "evaluable_rate_delta": round(
                float(metrics["recovery_evaluability_rate"]) - 0.124113,
                6,
            ),
            "abstention_rate_delta": round(
                float(metrics["abstention_rate"]) - 0.875887,
                6,
            ),
            "scope": "same_public_development_corpus_not_holdout",
        },
        "case_results": case_results,
        "execution_boundaries": {
            "public_external_json_read": True,
            "external_source_compiled_for_validation_only": True,
            "external_source_imported": False,
            "external_source_executed": False,
            "external_module_imported": False,
            "network_used": False,
            "subprocess_used": False,
            "shell_used": False,
            "docker_used": False,
            "model_invoked": False,
            "source_text_retained": False,
            "recovered_source_retained": False,
            "test_case_prompt_retained": False,
            "line_text_retained": False,
            "external_input_path_retained": False,
            "susvibes_artifacts_opened": False,
            "reserved_web_corpus_opened": False,
            "public_development_tuned": True,
            "unseen_holdout": False,
            "official_cyberseceval_metric": False,
            "secpass_equivalent": False,
            "leaderboard_comparable": False,
        },
        "unavailable_metrics": [
            "precision",
            "specificity",
            "accuracy",
            "false_positive_rate",
            "functional_correctness",
            "official_cyberseceval_pass_rate",
            "secpass",
        ],
        "limitations": [
            (
                "This v2 runner was developed against the same public "
                "positive-only corpus and is not an unseen evaluation."
            ),
            (
                "Synthetic wrapper parameters conservatively model otherwise "
                "unbound names as boundary inputs."
            ),
            (
                "The upstream ICD labels are not manually verified "
                "exploitable vulnerabilities and include no safe controls."
            ),
            (
                "Recovery improves static evaluability only; no source is "
                "imported, executed, or checked by a functional oracle."
            ),
        ],
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def _evaluate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    source = str(record["origin_code"])
    line_text = str(record["line_text"])
    expected_cwe = str(record["cwe_identifier"])
    prompt_id = int(record["prompt_id"])
    raw_ast_parseable = _raw_ast_parseable(source)
    base = {
        "case_id": f"cse4-instruct-v2-python-{prompt_id:04d}",
        "upstream_prompt_id": prompt_id,
        "expected_cwe": expected_cwe,
        "declared_overlap_supported": (
            expected_cwe in v1.CYBERSECEVAL_DECLARED_OVERLAP_CWES
        ),
        "source_sha256": v1._text_sha256(source),
        "line_text_sha256": v1._text_sha256(line_text),
        "repository_sha256": v1._text_sha256(str(record["repo"])),
        "file_path_sha256": v1._text_sha256(
            str(record["file_path"])
        ),
        "pattern_id_sha256": v1._text_sha256(
            str(record["pattern_id"])
        ),
        "target_line_match_count": 0,
        "raw_ast_parseable": raw_ast_parseable,
        "recovery_available": False,
        "recovery_methods": [],
        "projection_count": 0,
        "maximum_window_span": 0,
        "maximum_synthetic_parameter_count": 0,
        "analysis_exception": False,
        "classification": "abstain",
        "abstention_reason": "",
        "security_finding_count": 0,
        "taint_path_count": 0,
        "mapped_cwe_finding_count": 0,
        "target_aligned_finding_count": 0,
        "matched_findings": [],
    }
    try:
        projections = recover_targeted_python_projections(
            source,
            line_text,
            max_window_lines=DEFAULT_MAX_WINDOW_LINES,
            max_synthetic_parameters=(
                DEFAULT_MAX_SYNTHETIC_PARAMETERS
            ),
        )
    except (TypeError, ValueError):
        projections = ()
    if not projections:
        base["abstention_reason"] = "partial_recovery_failed"
        return base

    target_lines = set(projections[0].target_original_lines)
    base["target_line_match_count"] = len(target_lines)
    base["recovery_available"] = True
    base["recovery_methods"] = [
        projection.method for projection in projections
    ]
    base["projection_count"] = len(projections)
    base["maximum_window_span"] = max(
        projection.window_end_line
        - projection.window_start_line
        + 1
        for projection in projections
    )
    base["maximum_synthetic_parameter_count"] = max(
        len(projection.synthetic_parameters)
        for projection in projections
    )

    try:
        observations = _projection_observations(projections)
    except Exception:
        base["analysis_exception"] = True
        base["abstention_reason"] = "analysis_exception"
        return base

    mapped_cwes = set(
        v1.CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES[expected_cwe]
    )
    mapped = [
        item
        for item in observations
        if item["cwe"] in mapped_cwes
    ]
    aligned = [
        item
        for item in mapped
        if set(item["lines"]) & target_lines
    ]
    base["security_finding_count"] = sum(
        item["category"] == "security"
        for item in observations
    )
    base["taint_path_count"] = sum(
        item["category"] == "taint"
        for item in observations
    )
    base["mapped_cwe_finding_count"] = len(mapped)
    base["target_aligned_finding_count"] = len(aligned)
    base["matched_findings"] = aligned
    base["classification"] = "detected" if aligned else "missed"
    return base


def _projection_observations(
    projections: Sequence[PythonFragmentRecovery],
) -> list[dict[str, Any]]:
    observations: set[tuple[str, str, tuple[int, ...]]] = set()
    for projection in projections:
        security_beliefs = SecurityPatternExtractor().extract(
            projection.source,
            "cyberseceval_fragment.py",
        )
        for belief in security_beliefs:
            cwe = v1._normalized_cwe(getattr(belief, "cwe", ""))
            if not cwe:
                continue
            predicate = getattr(belief, "predicate", None)
            transformed = v1._normalized_lines(
                getattr(predicate, "anchor_lines", ()) or ()
            )
            if not transformed:
                scope = getattr(belief, "scope", None)
                transformed = v1._normalized_lines(
                    (getattr(scope, "line_start", None),)
                )
            original = projection.map_lines(transformed)
            if original:
                observations.add(("security", cwe, original))

        taint_paths = TaintEngine().analyze(
            projection.source,
            "cyberseceval_fragment.py",
        )
        for path in taint_paths:
            sink = getattr(path, "sink", None)
            cwe = v1._normalized_cwe(getattr(sink, "cwe", ""))
            transformed = v1._normalized_lines(
                (getattr(path, "sink_line", None),)
            )
            original = projection.map_lines(transformed)
            if cwe and original:
                observations.add(("taint", cwe, original))
    return [
        {
            "category": category,
            "cwe": cwe,
            "lines": list(lines),
        }
        for category, cwe, lines in sorted(observations)
    ]


def _metrics(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    classes = Counter(str(row["classification"]) for row in rows)
    total = len(rows)
    evaluable = classes["detected"] + classes["missed"]
    raw_parseable = sum(bool(row["raw_ast_parseable"]) for row in rows)
    recovered = sum(bool(row["recovery_available"]) for row in rows)
    analysis_exceptions = sum(
        bool(row["analysis_exception"]) for row in rows
    )
    supported = [
        row
        for row in rows
        if bool(row["declared_overlap_supported"])
    ]
    supported_detected = sum(
        row["classification"] == "detected"
        for row in supported
    )
    supported_evaluable = sum(
        row["classification"] in {"detected", "missed"}
        for row in supported
    )
    methods = Counter(
        method
        for row in rows
        for method in row["recovery_methods"]
    )
    per_cwe_rows: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in rows:
        per_cwe_rows[str(row["expected_cwe"])].append(row)

    return {
        "case_count": total,
        "classification_counts": {
            key: classes[key]
            for key in ("detected", "missed", "abstain")
        },
        "evaluable_case_count": evaluable,
        "raw_ast_parseable_case_count": raw_parseable,
        "recovery_available_case_count": recovered,
        "analysis_exception_count": analysis_exceptions,
        "raw_ast_parseability_rate": _rate(raw_parseable, total),
        "recovery_evaluability_rate": _rate(evaluable, total),
        "abstention_rate": _rate(classes["abstain"], total),
        "target_pattern_sensitivity_lower_bound": _rate(
            classes["detected"],
            total,
        ),
        "target_pattern_sensitivity_on_evaluable_cases": _rate(
            classes["detected"],
            evaluable,
        ),
        "declared_overlap_case_count": len(supported),
        "declared_overlap_evaluable_case_count": supported_evaluable,
        "declared_overlap_detected_case_count": supported_detected,
        "declared_overlap_target_sensitivity_lower_bound": _rate(
            supported_detected,
            len(supported),
        ),
        "declared_overlap_target_sensitivity_on_evaluable_cases": (
            _rate(supported_detected, supported_evaluable)
        ),
        "projection_count": sum(
            int(row["projection_count"]) for row in rows
        ),
        "recovery_method_counts": dict(sorted(methods.items())),
        "per_cwe": {
            cwe: _positive_only_cwe_metrics(cwe_rows)
            for cwe, cwe_rows in sorted(per_cwe_rows.items())
        },
    }


def _positive_only_cwe_metrics(
    rows: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    counts = Counter(str(row["classification"]) for row in rows)
    total = len(rows)
    evaluable = counts["detected"] + counts["missed"]
    return {
        "case_count": total,
        "detected": counts["detected"],
        "missed": counts["missed"],
        "abstain": counts["abstain"],
        "evaluable_rate": _rate(evaluable, total),
        "sensitivity_lower_bound": _rate(counts["detected"], total),
        "sensitivity_on_evaluable_cases": _rate(
            counts["detected"],
            evaluable,
        ),
    }


def _gate_evaluations(
    metrics: Mapping[str, Any],
) -> dict[str, Any]:
    thresholds = CYBERSECEVAL_STATIC_PREFLIGHT_V2_THRESHOLDS
    return {
        "exact_dataset_binding": {
            "actual": True,
            "expected": True,
            "status": "pass",
        },
        "minimum_recovery_evaluability_rate": _minimum_gate(
            float(metrics["recovery_evaluability_rate"]),
            thresholds["minimum_recovery_evaluability_rate"],
        ),
        "maximum_abstention_rate": _maximum_gate(
            float(metrics["abstention_rate"]),
            thresholds["maximum_abstention_rate"],
        ),
        "maximum_analysis_exception_rate": _maximum_gate(
            _rate(
                int(metrics["analysis_exception_count"]),
                int(metrics["case_count"]),
            ),
            thresholds["maximum_analysis_exception_rate"],
        ),
        "minimum_all_case_target_sensitivity_lower_bound": _minimum_gate(
            float(metrics["target_pattern_sensitivity_lower_bound"]),
            thresholds[
                "minimum_all_case_target_sensitivity_lower_bound"
            ],
        ),
        "minimum_evaluable_target_sensitivity": _minimum_gate(
            float(
                metrics[
                    "target_pattern_sensitivity_on_evaluable_cases"
                ]
            ),
            thresholds["minimum_evaluable_target_sensitivity"],
        ),
        "minimum_supported_cwe_target_sensitivity_lower_bound": (
            _minimum_gate(
                float(
                    metrics[
                        "declared_overlap_target_sensitivity_lower_bound"
                    ]
                ),
                thresholds[
                    "minimum_supported_cwe_target_sensitivity_lower_bound"
                ],
            )
        ),
    }


def _raw_ast_parseable(source: str) -> bool:
    try:
        ast.parse(source)
    except (SyntaxError, TypeError, ValueError):
        return False
    return True


def _validated_commit(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _COMMIT_RE.fullmatch(normalized):
        raise ValueError("belief_revision must be a full lowercase Git SHA")
    return normalized


def _runner_policy() -> dict[str, Any]:
    return copy.deepcopy(_RUNNER_POLICY)


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round(numerator / denominator, 6)


def _minimum_gate(actual: float, expected: float) -> dict[str, Any]:
    return {
        "actual": actual,
        "expected_minimum": expected,
        "status": "pass" if actual >= expected else "fail",
    }


def _maximum_gate(actual: float, expected: float) -> dict[str, Any]:
    return {
        "actual": actual,
        "expected_maximum": expected,
        "status": "pass" if actual <= expected else "fail",
    }


__all__ = [
    "CYBERSECEVAL_STATIC_PREFLIGHT_V2_BENCHMARK_ID",
    "CYBERSECEVAL_STATIC_PREFLIGHT_V2_PREREGISTRATION_SCHEMA_VERSION",
    "CYBERSECEVAL_STATIC_PREFLIGHT_V2_REPETITIONS",
    "CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_POLICY_DIGEST",
    "CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_VERSION",
    "CYBERSECEVAL_STATIC_PREFLIGHT_V2_SCHEMA_VERSION",
    "build_cyberseceval_static_preflight_v2_preregistration",
    "evaluate_cyberseceval_python_static_preflight_v2",
    "verify_cyberseceval_static_preflight_v2_preregistration",
    "write_cyberseceval_python_static_preflight_v2_result",
]
