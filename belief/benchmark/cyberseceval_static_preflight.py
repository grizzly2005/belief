"""Frozen, positive-only CyberSecEval 4 static preflight for BELIEF.

This adapter reads one exact public dataset revision as inert JSON and analyzes
only its Python ``origin_code`` strings. It never imports or executes external
code. The upstream corpus contains examples selected by Meta's Insecure Code
Detector, not manually verified vulnerable/safe pairs, so this module reports a
target-pattern sensitivity proxy and abstention. It cannot measure precision,
specificity, functional correctness, SecPass, or an official CyberSecEval
metric.
"""

from __future__ import annotations

import ast
import copy
import hashlib
import json
import re
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from belief.security_patterns import SecurityPatternExtractor
from belief.taint import TaintEngine
from belief.validation.plan_models import canonical_digest


CYBERSECEVAL_STATIC_PREFLIGHT_BENCHMARK_ID = (
    "belief-cyberseceval4-python-static-preflight-v1"
)
CYBERSECEVAL_STATIC_PREFLIGHT_SCHEMA_VERSION = (
    "belief.cyberseceval_static_preflight.v1"
)
CYBERSECEVAL_STATIC_PREFLIGHT_PREREGISTRATION_SCHEMA_VERSION = (
    "belief.cyberseceval_static_preflight_preregistration.v1"
)
CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_VERSION = (
    "belief.cyberseceval_static_preflight_runner.v1"
)
CYBERSECEVAL_STATIC_PREFLIGHT_REPETITIONS = 2
CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT = (
    "public_external_code_static_analysis_acknowledged"
)

CYBERSECEVAL_UPSTREAM_REPOSITORY = (
    "https://github.com/meta-llama/PurpleLlama.git"
)
CYBERSECEVAL_UPSTREAM_COMMIT = (
    "acfdd58f7c605eec53af4eed3f7ecf302267f0f8"
)
CYBERSECEVAL_DATASET_RELATIVE_PATH = (
    "CybersecurityBenchmarks/datasets/instruct/instruct-v2.json"
)
CYBERSECEVAL_DATASET_FILENAME = "instruct-v2.json"
CYBERSECEVAL_DATASET_SHA256 = (
    "fa583f17875a7822355f0e29a21b5169eba445f9cfe24d87afcdc23adb270f82"
)
CYBERSECEVAL_DATASET_SIZE_BYTES = 3_033_298
CYBERSECEVAL_COMPONENT_LICENSE_RELATIVE_PATH = (
    "CybersecurityBenchmarks/LICENSE"
)
CYBERSECEVAL_COMPONENT_LICENSE_SPDX = "MIT"
CYBERSECEVAL_COMPONENT_LICENSE_SHA256 = (
    "63e8210e6bf3e8c032dc0c69b1d1d2e3ab72c14b02cabcc0dada2618bb188b97"
)
CYBERSECEVAL_EXPECTED_RECORD_COUNT = 1_681
CYBERSECEVAL_EXPECTED_PYTHON_RECORD_COUNT = 282
CYBERSECEVAL_EXPECTED_PYTHON_REPOSITORY_COUNT = 279
CYBERSECEVAL_EXPECTED_PYTHON_UNIQUE_SOURCE_COUNT = 281
CYBERSECEVAL_PREREGISTRATION_STARTING_COMMIT = (
    "236bcdb36e859e4432f71f8a2da1d56dbfa14843"
)

CYBERSECEVAL_MAX_SOURCE_CHARS = 100_000
CYBERSECEVAL_MAX_METADATA_CHARS = 8_192

CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES: Mapping[
    str,
    tuple[str, ...],
] = {
    "CWE-78": ("CWE-78",),
    "CWE-89": ("CWE-89",),
    "CWE-94": ("CWE-94", "CWE-95"),
    "CWE-312": ("CWE-312",),
    "CWE-328": ("CWE-327", "CWE-328"),
    "CWE-338": ("CWE-330", "CWE-338"),
    "CWE-502": ("CWE-502",),
    "CWE-798": ("CWE-798",),
}
CYBERSECEVAL_DECLARED_OVERLAP_CWES = frozenset(
    set(CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES) - {"CWE-312"}
)

CYBERSECEVAL_STATIC_PREFLIGHT_THRESHOLDS: Mapping[str, float] = {
    "maximum_abstention_rate": 0.15,
    "maximum_analysis_exception_rate": 0.0,
    "minimum_all_case_target_sensitivity_lower_bound": 0.50,
    "minimum_evaluable_target_sensitivity": 0.60,
    "minimum_python_ast_parseability_rate": 0.85,
    "minimum_repetition_stability_rate": 1.0,
    "minimum_supported_cwe_target_sensitivity_lower_bound": 0.55,
}

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_PREREGISTRATION_PATH = (
    _REPOSITORY_ROOT
    / "benchmark_cyberseceval"
    / "preregistration.json"
)

_RUNNER_POLICY: dict[str, Any] = {
    "adapter": "exact_public_json_dataset",
    "repetitions": CYBERSECEVAL_STATIC_PREFLIGHT_REPETITIONS,
    "dataset_binding": {
        "repository": CYBERSECEVAL_UPSTREAM_REPOSITORY,
        "revision": CYBERSECEVAL_UPSTREAM_COMMIT,
        "relative_path": CYBERSECEVAL_DATASET_RELATIVE_PATH,
        "sha256": CYBERSECEVAL_DATASET_SHA256,
        "size_bytes": CYBERSECEVAL_DATASET_SIZE_BYTES,
    },
    "selection": {
        "dataset_variant": "instruct-v2",
        "language": "python",
        "expected_dataset_records": CYBERSECEVAL_EXPECTED_RECORD_COUNT,
        "expected_selected_records": (
            CYBERSECEVAL_EXPECTED_PYTHON_RECORD_COUNT
        ),
        "selection_uses_belief_outcomes": False,
    },
    "analysis": {
        "source_field": "origin_code",
        "target_field": "line_text",
        "target_alignment": "trimmed_exact_line_match",
        "parser": "python_ast_parse_only",
        "fixed_analyzers": [
            "belief.security_patterns.default",
            "belief.taint.default",
        ],
        "external_source_imported": False,
        "external_source_executed": False,
    },
    "classification": {
        "detected": (
            "mapped BELIEF CWE anchor intersects an upstream target line"
        ),
        "missed": (
            "source is evaluable but no mapped BELIEF CWE anchor intersects "
            "an upstream target line"
        ),
        "abstain": [
            "python_ast_parse_failed",
            "target_line_not_located",
            "analysis_exception",
        ],
        "cwe_mapping": {
            key: list(value)
            for key, value in sorted(
                CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES.items()
            )
        },
        "declared_overlap_cwes": sorted(
            CYBERSECEVAL_DECLARED_OVERLAP_CWES
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
    },
    "retention": {
        "source_text_in_result": False,
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
CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_POLICY_DIGEST = canonical_digest(
    _RUNNER_POLICY
)


def build_cyberseceval_static_preflight_preregistration() -> dict[str, Any]:
    """Return the frozen protocol written before any BELIEF corpus outcome."""

    payload: dict[str, Any] = {
        "schema_version": (
            CYBERSECEVAL_STATIC_PREFLIGHT_PREREGISTRATION_SCHEMA_VERSION
        ),
        "benchmark_id": CYBERSECEVAL_STATIC_PREFLIGHT_BENCHMARK_ID,
        "status": "protocol_frozen_before_belief_outcomes",
        "starting_commit": CYBERSECEVAL_PREREGISTRATION_STARTING_COMMIT,
        "upstream": {
            "repository": CYBERSECEVAL_UPSTREAM_REPOSITORY,
            "revision": CYBERSECEVAL_UPSTREAM_COMMIT,
            "dataset_relative_path": (
                CYBERSECEVAL_DATASET_RELATIVE_PATH
            ),
            "dataset_sha256": CYBERSECEVAL_DATASET_SHA256,
            "dataset_size_bytes": CYBERSECEVAL_DATASET_SIZE_BYTES,
            "component_license_relative_path": (
                CYBERSECEVAL_COMPONENT_LICENSE_RELATIVE_PATH
            ),
            "component_license_spdx": (
                CYBERSECEVAL_COMPONENT_LICENSE_SPDX
            ),
            "component_license_sha256": (
                CYBERSECEVAL_COMPONENT_LICENSE_SHA256
            ),
        },
        "corpus": {
            "upstream_record_count": (
                CYBERSECEVAL_EXPECTED_RECORD_COUNT
            ),
            "python_record_count": (
                CYBERSECEVAL_EXPECTED_PYTHON_RECORD_COUNT
            ),
            "python_repository_count": (
                CYBERSECEVAL_EXPECTED_PYTHON_REPOSITORY_COUNT
            ),
            "python_unique_source_count": (
                CYBERSECEVAL_EXPECTED_PYTHON_UNIQUE_SOURCE_COUNT
            ),
            "label_semantics": (
                "positive proxy: upstream ICD observed an insecure coding "
                "practice used to derive the prompt"
            ),
            "negative_controls_present": False,
            "manual_vulnerability_ground_truth": False,
            "functional_oracles_present": False,
        },
        "runner_version": (
            CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_VERSION
        ),
        "runner_policy": copy.deepcopy(_RUNNER_POLICY),
        "runner_policy_digest": (
            CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_POLICY_DIGEST
        ),
        "thresholds": dict(
            CYBERSECEVAL_STATIC_PREFLIGHT_THRESHOLDS
        ),
        "permitted_outputs": [
            "dataset_binding_verification",
            "python_ast_parseability_rate",
            "target_pattern_sensitivity_lower_bound",
            "target_pattern_sensitivity_on_evaluable_cases",
            "abstention_rate",
            "per_cwe_positive_only_diagnostics",
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
            "eligible for an external positive-only static sensitivity "
            "preflight; ineligible for a primary comparative security score"
        ),
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def verify_cyberseceval_static_preflight_preregistration() -> dict[str, Any]:
    """Verify that the committed preregistration exactly matches the code."""

    try:
        observed = json.loads(
            _PREREGISTRATION_PATH.read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "CyberSecEval static preregistration is unavailable"
        ) from exc
    expected = build_cyberseceval_static_preflight_preregistration()
    if observed != expected:
        raise ValueError(
            "CyberSecEval static preregistration does not match "
            "the frozen runner policy"
        )
    return copy.deepcopy(observed)


def evaluate_cyberseceval_python_static_preflight(
    dataset: str | Path,
    *,
    acknowledgement: str,
    belief_revision: str,
) -> dict[str, Any]:
    """Evaluate the exact bound public dataset twice without executing it."""

    _require_acknowledgement(acknowledgement)
    revision = _validated_commit(belief_revision)
    preregistration = (
        verify_cyberseceval_static_preflight_preregistration()
    )
    records, verification = _load_bound_python_records(dataset)

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
        "repetitions": CYBERSECEVAL_STATIC_PREFLIGHT_REPETITIONS,
        "run_digests": [first_digest, second_digest],
        "identical": stable,
        "stability_rate": 1.0 if stable else 0.0,
        "scope": "same_checkout_same_platform_same_bound_dataset",
    }
    payload["gate_evaluations"][
        "minimum_repetition_stability_rate"
    ] = _minimum_gate(
        1.0 if stable else 0.0,
        CYBERSECEVAL_STATIC_PREFLIGHT_THRESHOLDS[
            "minimum_repetition_stability_rate"
        ],
    )
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_cyberseceval_python_static_preflight_result(
    dataset: str | Path,
    output: str | Path,
    *,
    acknowledgement: str,
    belief_revision: str,
) -> dict[str, Any]:
    """Create one result document and refuse to overwrite any file."""

    destination = Path(output).resolve()
    if destination.exists():
        raise ValueError(
            "refusing to overwrite CyberSecEval static preflight result: "
            f"{destination}"
        )
    payload = evaluate_cyberseceval_python_static_preflight(
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
            "refusing to overwrite CyberSecEval static preflight result: "
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
    case_results = [
        _evaluate_record(record)
        for record in records
    ]
    metrics = _metrics(case_results)
    payload: dict[str, Any] = {
        "schema_version": (
            CYBERSECEVAL_STATIC_PREFLIGHT_SCHEMA_VERSION
        ),
        "benchmark_id": CYBERSECEVAL_STATIC_PREFLIGHT_BENCHMARK_ID,
        "cohort": "public_instruct_v2_python_origin_code",
        "declared_belief_revision": belief_revision,
        "preregistration_digest": str(
            preregistration["deterministic_digest"]
        ),
        "runner_version": CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_VERSION,
        "runner_policy_digest": (
            CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_POLICY_DIGEST
        ),
        "dataset_verification": dict(dataset_verification),
        "authorization": {
            "required": True,
            "acknowledged": True,
            "scope": (
                "read exact public JSON and statically parse origin_code"
            ),
        },
        "metrics": metrics,
        "gate_evaluations": _gate_evaluations(metrics),
        "case_results": case_results,
        "execution_boundaries": {
            "public_external_json_read": True,
            "external_source_imported": False,
            "external_source_executed": False,
            "external_module_imported": False,
            "network_used": False,
            "subprocess_used": False,
            "shell_used": False,
            "docker_used": False,
            "model_invoked": False,
            "source_text_retained": False,
            "test_case_prompt_retained": False,
            "line_text_retained": False,
            "external_input_path_retained": False,
            "susvibes_artifacts_opened": False,
            "reserved_web_corpus_opened": False,
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
                "Every selected row is a positive proxy produced from an "
                "upstream ICD match; there are no safe negative controls."
            ),
            (
                "The upstream label identifies an insecure coding practice, "
                "not a manually verified exploitable vulnerability."
            ),
            (
                "Target sensitivity measures BELIEF findings aligned to the "
                "upstream line and a frozen CWE equivalence map."
            ),
            (
                "Public origin code may overlap model or analyzer development "
                "data and is not an unseen holdout."
            ),
        ],
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def _load_bound_python_records(
    dataset: str | Path,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    requested = Path(dataset)
    if requested.name != CYBERSECEVAL_DATASET_FILENAME:
        raise ValueError(
            "CyberSecEval input must use the exact bound dataset filename"
        )
    try:
        resolved = requested.resolve(strict=True)
    except OSError as exc:
        raise ValueError(
            "CyberSecEval bound dataset is unavailable"
        ) from exc
    if not resolved.is_file():
        raise ValueError("CyberSecEval bound dataset is not a regular file")
    try:
        raw = resolved.read_bytes()
    except OSError as exc:
        raise ValueError("failed to read CyberSecEval bound dataset") from exc
    if len(raw) != CYBERSECEVAL_DATASET_SIZE_BYTES:
        raise ValueError("CyberSecEval bound dataset size mismatch")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != CYBERSECEVAL_DATASET_SHA256:
        raise ValueError("CyberSecEval bound dataset digest mismatch")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            "CyberSecEval bound dataset is not valid UTF-8 JSON"
        ) from exc
    if not isinstance(payload, list):
        raise ValueError("CyberSecEval bound dataset must be a JSON list")
    if len(payload) != CYBERSECEVAL_EXPECTED_RECORD_COUNT:
        raise ValueError("CyberSecEval bound dataset record count mismatch")

    records = _validated_python_records(payload)
    verification = {
        "repository": CYBERSECEVAL_UPSTREAM_REPOSITORY,
        "revision": CYBERSECEVAL_UPSTREAM_COMMIT,
        "relative_path": CYBERSECEVAL_DATASET_RELATIVE_PATH,
        "filename": CYBERSECEVAL_DATASET_FILENAME,
        "sha256": digest,
        "size_bytes": len(raw),
        "upstream_record_count": len(payload),
        "selected_python_record_count": len(records),
        "component_license_spdx": (
            CYBERSECEVAL_COMPONENT_LICENSE_SPDX
        ),
        "component_license_sha256": (
            CYBERSECEVAL_COMPONENT_LICENSE_SHA256
        ),
        "exact_binding_verified": True,
        "input_path_retained": False,
    }
    return records, verification


def _validated_python_records(
    payload: Sequence[Any],
) -> list[dict[str, Any]]:
    selected = []
    for raw in payload:
        if not isinstance(raw, Mapping):
            raise ValueError("CyberSecEval dataset row must be an object")
        if raw.get("language") != "python":
            continue
        prompt_id = raw.get("prompt_id")
        if isinstance(prompt_id, bool) or not isinstance(prompt_id, int):
            raise ValueError("CyberSecEval Python prompt_id must be an integer")
        source = _bounded_text(raw.get("origin_code"), "origin_code")
        if len(source) > CYBERSECEVAL_MAX_SOURCE_CHARS:
            raise ValueError("CyberSecEval Python origin_code exceeds limit")
        line_text = _bounded_text(raw.get("line_text"), "line_text")
        if "\n" in line_text or "\r" in line_text:
            raise ValueError("CyberSecEval Python line_text must be one line")
        cwe = _bounded_text(raw.get("cwe_identifier"), "cwe_identifier")
        if cwe not in CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES:
            raise ValueError("CyberSecEval Python CWE is outside frozen map")
        variant = _bounded_text(raw.get("variant"), "variant")
        if variant != "instruct":
            raise ValueError("CyberSecEval Python variant is not instruct")
        selected.append({
            "prompt_id": prompt_id,
            "repo": _bounded_text(raw.get("repo"), "repo"),
            "file_path": _bounded_text(
                raw.get("file_path"),
                "file_path",
            ),
            "pattern_id": _bounded_text(
                raw.get("pattern_id"),
                "pattern_id",
            ),
            "cwe_identifier": cwe,
            "line_number": _positive_int(
                raw.get("line_number"),
                "line_number",
            ),
            "line_text": line_text,
            "origin_code": source,
        })

    if len(selected) != CYBERSECEVAL_EXPECTED_PYTHON_RECORD_COUNT:
        raise ValueError(
            "CyberSecEval selected Python record count mismatch"
        )
    prompt_ids = [record["prompt_id"] for record in selected]
    if len(set(prompt_ids)) != len(prompt_ids):
        raise ValueError("CyberSecEval Python prompt IDs are not unique")
    repository_count = len({
        record["repo"] for record in selected
    })
    if repository_count != CYBERSECEVAL_EXPECTED_PYTHON_REPOSITORY_COUNT:
        raise ValueError(
            "CyberSecEval Python repository count mismatch"
        )
    unique_source_count = len({
        record["origin_code"] for record in selected
    })
    if (
        unique_source_count
        != CYBERSECEVAL_EXPECTED_PYTHON_UNIQUE_SOURCE_COUNT
    ):
        raise ValueError(
            "CyberSecEval Python unique source count mismatch"
        )
    return sorted(selected, key=lambda item: int(item["prompt_id"]))


def _evaluate_record(record: Mapping[str, Any]) -> dict[str, Any]:
    source = str(record["origin_code"])
    line_text = str(record["line_text"])
    expected_cwe = str(record["cwe_identifier"])
    prompt_id = int(record["prompt_id"])
    target_lines = _target_lines(source, line_text)
    base = {
        "case_id": f"cse4-instruct-v2-python-{prompt_id:04d}",
        "upstream_prompt_id": prompt_id,
        "expected_cwe": expected_cwe,
        "declared_overlap_supported": (
            expected_cwe in CYBERSECEVAL_DECLARED_OVERLAP_CWES
        ),
        "source_sha256": _text_sha256(source),
        "line_text_sha256": _text_sha256(line_text),
        "repository_sha256": _text_sha256(str(record["repo"])),
        "file_path_sha256": _text_sha256(str(record["file_path"])),
        "pattern_id_sha256": _text_sha256(str(record["pattern_id"])),
        "target_line_match_count": len(target_lines),
        "ast_parseable": False,
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
        ast.parse(source)
    except (SyntaxError, TypeError, ValueError):
        base["abstention_reason"] = "python_ast_parse_failed"
        return base
    base["ast_parseable"] = True
    if not target_lines:
        base["abstention_reason"] = "target_line_not_located"
        return base

    try:
        security_beliefs = SecurityPatternExtractor().extract(
            source,
            f"cyberseceval_{prompt_id}.py",
        )
        taint_paths = TaintEngine().analyze(
            source,
            f"cyberseceval_{prompt_id}.py",
        )
    except Exception:
        base["analysis_exception"] = True
        base["abstention_reason"] = "analysis_exception"
        return base

    observations = _finding_observations(
        security_beliefs,
        taint_paths,
    )
    mapped_cwes = set(
        CYBERSECEVAL_SOURCE_CWE_TO_BELIEF_CWES[expected_cwe]
    )
    mapped = [
        item
        for item in observations
        if item["cwe"] in mapped_cwes
    ]
    aligned = [
        item
        for item in mapped
        if set(item["lines"]) & set(target_lines)
    ]
    base["security_finding_count"] = sum(
        1 for item in observations if item["category"] == "security"
    )
    base["taint_path_count"] = sum(
        1 for item in observations if item["category"] == "taint"
    )
    base["mapped_cwe_finding_count"] = len(mapped)
    base["target_aligned_finding_count"] = len(aligned)
    base["matched_findings"] = aligned
    base["classification"] = "detected" if aligned else "missed"
    return base


def _finding_observations(
    security_beliefs: Sequence[Any],
    taint_paths: Sequence[Any],
) -> list[dict[str, Any]]:
    observations: set[tuple[str, str, tuple[int, ...]]] = set()
    for belief in security_beliefs:
        cwe = _normalized_cwe(getattr(belief, "cwe", ""))
        if not cwe:
            continue
        predicate = getattr(belief, "predicate", None)
        anchors = getattr(predicate, "anchor_lines", ()) or ()
        lines = _normalized_lines(anchors)
        if not lines:
            scope = getattr(belief, "scope", None)
            lines = _normalized_lines(
                (getattr(scope, "line_start", None),)
            )
        observations.add(("security", cwe, lines))
    for path in taint_paths:
        sink = getattr(path, "sink", None)
        cwe = _normalized_cwe(getattr(sink, "cwe", ""))
        lines = _normalized_lines(
            (getattr(path, "sink_line", None),)
        )
        if cwe and lines:
            observations.add(("taint", cwe, lines))
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
    ast_parseable = sum(bool(row["ast_parseable"]) for row in rows)
    target_located = sum(
        int(row["target_line_match_count"]) > 0
        for row in rows
    )
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
        "ast_parseable_case_count": ast_parseable,
        "target_line_located_case_count": target_located,
        "analysis_exception_count": analysis_exceptions,
        "python_ast_parseability_rate": _rate(ast_parseable, total),
        "target_line_location_rate": _rate(target_located, total),
        "evaluable_rate": _rate(evaluable, total),
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
    thresholds = CYBERSECEVAL_STATIC_PREFLIGHT_THRESHOLDS
    return {
        "exact_dataset_binding": {
            "actual": True,
            "expected": True,
            "status": "pass",
        },
        "minimum_python_ast_parseability_rate": _minimum_gate(
            float(metrics["python_ast_parseability_rate"]),
            thresholds["minimum_python_ast_parseability_rate"],
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


def _runner_policy() -> dict[str, Any]:
    return copy.deepcopy(_RUNNER_POLICY)


def _target_lines(source: str, line_text: str) -> tuple[int, ...]:
    target = line_text.strip()
    if not target:
        return ()
    return tuple(
        index
        for index, line in enumerate(source.splitlines(), start=1)
        if line.strip() == target
    )


def _normalized_lines(values: Sequence[Any]) -> tuple[int, ...]:
    result = set()
    for value in values:
        if isinstance(value, bool):
            continue
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            continue
        if parsed > 0:
            result.add(parsed)
    return tuple(sorted(result))


def _normalized_cwe(value: Any) -> str:
    match = re.search(r"CWE-\d+", str(value or "").upper())
    return match.group(0) if match else ""


def _bounded_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"CyberSecEval Python {field} must be text")
    if len(value) > CYBERSECEVAL_MAX_METADATA_CHARS and field != "origin_code":
        raise ValueError(f"CyberSecEval Python {field} exceeds limit")
    return value


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"CyberSecEval Python {field} must be an integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            f"CyberSecEval Python {field} must be an integer"
        ) from exc
    if parsed <= 0:
        raise ValueError(
            f"CyberSecEval Python {field} must be positive"
        )
    return parsed


def _validated_commit(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _COMMIT_RE.fullmatch(normalized):
        raise ValueError("belief_revision must be a full lowercase Git SHA")
    return normalized


def _require_acknowledgement(value: str) -> None:
    if value != CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT:
        raise ValueError(
            "explicit public external-code static-analysis "
            "acknowledgement is required"
        )


def _text_sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
    "CYBERSECEVAL_COMPONENT_LICENSE_SHA256",
    "CYBERSECEVAL_DATASET_SHA256",
    "CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT",
    "CYBERSECEVAL_STATIC_PREFLIGHT_BENCHMARK_ID",
    "CYBERSECEVAL_STATIC_PREFLIGHT_PREREGISTRATION_SCHEMA_VERSION",
    "CYBERSECEVAL_STATIC_PREFLIGHT_REPETITIONS",
    "CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_POLICY_DIGEST",
    "CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_VERSION",
    "CYBERSECEVAL_STATIC_PREFLIGHT_SCHEMA_VERSION",
    "build_cyberseceval_static_preflight_preregistration",
    "evaluate_cyberseceval_python_static_preflight",
    "verify_cyberseceval_static_preflight_preregistration",
    "write_cyberseceval_python_static_preflight_result",
]
