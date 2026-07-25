"""Evaluator-side failure-attribution schema for generalization work.

This module validates diagnostic artifacts. It is not imported by the
candidate reviewer and it contains no benchmark identifiers, project names,
reference patches, or outcome-specific production rules.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION = (
    "belief.generalization_failure_report.v1"
)

FAILURE_CATEGORIES = (
    "candidate_reconstruction_failure",
    "parse_failure",
    "unsupported_language_or_syntax",
    "changed_file_not_selected",
    "changed_function_not_selected",
    "source_not_recognized",
    "sink_not_recognized",
    "local_flow_missing",
    "interprocedural_flow_missing",
    "receiver_or_field_flow_missing",
    "alias_flow_missing",
    "callback_or_decorator_flow_missing",
    "guard_not_recognized",
    "guard_wrong_value",
    "guard_wrong_resource",
    "guard_after_sink",
    "guard_not_dominating",
    "sanitizer_return_unused",
    "sanitizer_wrong_context",
    "state_transition_not_modeled",
    "finding_focus_mismatch",
    "finding_identity_mismatch",
    "vulnerable_and_secure_same_warning",
    "secure_candidate_false_positive",
    "vulnerable_candidate_false_negative",
    "inconclusive_evidence",
    "evaluator_or_infrastructure_failure",
)

_FAILURE_CATEGORY_SET = frozenset(FAILURE_CATEGORIES)
_RISK_LEVELS = frozenset({"low", "medium", "high"})
_COST_LEVELS = frozenset({"low", "medium", "high"})


@dataclass(frozen=True)
class FailureCaseAttribution:
    """Benchmark-independent description of one failed analysis stage."""

    primary_category: str
    first_failed_stage: str
    blocked_stages: tuple[str, ...]
    available_evidence: tuple[str, ...]
    missing_evidence: tuple[str, ...]
    semantic_primitive: str
    general_fix_possible: bool
    overfit_risk: str
    estimated_cost: str

    def __post_init__(self) -> None:
        if self.primary_category not in _FAILURE_CATEGORY_SET:
            raise ValueError(
                f"unknown generalization failure category: "
                f"{self.primary_category}"
            )
        if not self.first_failed_stage.strip():
            raise ValueError("first_failed_stage must not be empty")
        if not self.semantic_primitive.strip():
            raise ValueError("semantic_primitive must not be empty")
        _validate_string_tuple("blocked_stages", self.blocked_stages)
        _validate_string_tuple("available_evidence", self.available_evidence)
        _validate_string_tuple("missing_evidence", self.missing_evidence)
        if self.overfit_risk not in _RISK_LEVELS:
            raise ValueError("overfit_risk must be low, medium, or high")
        if self.estimated_cost not in _COST_LEVELS:
            raise ValueError("estimated_cost must be low, medium, or high")

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        for key in (
            "blocked_stages",
            "available_evidence",
            "missing_evidence",
        ):
            value[key] = list(value[key])
        return value


def validate_generalization_failure_report(
    payload: Mapping[str, Any],
    *,
    expected_case_count: int | None = None,
    expected_development_ids_sha256: str | None = None,
) -> dict[str, Any]:
    """Validate and return a detached v1 failure-attribution artifact."""

    if payload.get("schema_version") != (
        GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION
    ):
        raise ValueError("unsupported generalization failure report schema")
    if payload.get("mode") != (
        "evaluator_only_development_failure_attribution"
    ):
        raise ValueError("invalid generalization failure report mode")

    cohort = _mapping(payload, "development_cohort")
    case_count = _non_negative_integer(payload, "case_count")
    cohort_count = _non_negative_integer(cohort, "case_count")
    if expected_case_count is not None and case_count != expected_case_count:
        raise ValueError("generalization failure report case count mismatch")
    if cohort_count != case_count:
        raise ValueError("development cohort count disagrees with case count")
    ordered_ids_sha256 = _sha256(
        cohort.get("ordered_ids_sha256"),
        "development ordered-ID digest",
    )
    if (
        expected_development_ids_sha256 is not None
        and ordered_ids_sha256 != expected_development_ids_sha256
    ):
        raise ValueError("development ordered-ID digest mismatch")

    cases = payload.get("cases")
    if not isinstance(cases, list) or len(cases) != case_count:
        raise ValueError("failure report cases disagree with case count")
    observed_ids: set[str] = set()
    observed_numbers: set[int] = set()
    category_frequency: Counter[str] = Counter()
    outcome_frequency: Counter[str] = Counter()
    for row in cases:
        if not isinstance(row, Mapping):
            raise ValueError("failure report case must be an object")
        instance_id = _non_empty_string(row, "id")
        if instance_id in observed_ids:
            raise ValueError("failure report case IDs must be unique")
        observed_ids.add(instance_id)
        number = _positive_integer(row, "development_case_number")
        if number in observed_numbers:
            raise ValueError(
                "development case numbers must be present and unique"
            )
        observed_numbers.add(number)
        category = _non_empty_string(row, "primary_category")
        attribution = FailureCaseAttribution(
            primary_category=category,
            first_failed_stage=_non_empty_string(
                row,
                "first_failed_stage",
            ),
            blocked_stages=_string_tuple(row, "blocked_stages"),
            available_evidence=_string_tuple(row, "available_evidence"),
            missing_evidence=_string_tuple(row, "missing_evidence"),
            semantic_primitive=_non_empty_string(
                row,
                "semantic_primitive",
            ),
            general_fix_possible=_boolean(row, "general_fix_possible"),
            overfit_risk=_non_empty_string(row, "overfit_risk"),
            estimated_cost=_non_empty_string(row, "estimated_cost"),
        )
        if attribution.primary_category != category:
            raise ValueError("failure category normalization mismatch")
        _sha256(row.get("security_patch_sha256"), "security patch digest")
        _sha256(row.get("root_cause_identity"), "root-cause identity")
        _string_tuple(row, "files", allow_empty=True)
        _string_tuple(row, "functions", allow_empty=True)
        observation = _mapping(row, "baseline_observation")
        _boolean(observation, "analysis_succeeded")
        _boolean(observation, "vulnerable_warned")
        _boolean(observation, "secure_warning_false_positive")
        _boolean(observation, "paired_warning_discriminated")
        _non_negative_integer(
            observation,
            "vulnerable_actionable_count",
        )
        _non_negative_integer(
            observation,
            "secure_actionable_count",
        )
        _string_tuple(observation, "errors", allow_empty=True)
        outcome = _non_empty_string(row, "outcome")
        category_frequency[category] += 1
        outcome_frequency[outcome] += 1

    if observed_numbers != set(range(1, case_count + 1)):
        raise ValueError(
            "development case numbers must form a contiguous one-based range"
        )

    aggregate = _mapping(payload, "aggregate")
    if _integer_mapping(aggregate, "category_frequency") != dict(
        sorted(category_frequency.items())
    ):
        raise ValueError("aggregate category frequency mismatch")
    if _integer_mapping(aggregate, "outcome_frequency") != dict(
        sorted(outcome_frequency.items())
    ):
        raise ValueError("aggregate outcome frequency mismatch")
    clusters = aggregate.get("clusters")
    if not isinstance(clusters, list) or not clusters:
        raise ValueError("aggregate clusters must be a non-empty array")
    cluster_categories: set[str] = set()
    for cluster in clusters:
        if not isinstance(cluster, Mapping):
            raise ValueError("aggregate cluster must be an object")
        category = _non_empty_string(cluster, "category")
        if category in cluster_categories:
            raise ValueError("aggregate cluster categories must be unique")
        cluster_categories.add(category)
        if category not in category_frequency:
            raise ValueError("aggregate cluster category has no cases")
        if _positive_integer(cluster, "case_count") != (
            category_frequency[category]
        ):
            raise ValueError("aggregate cluster count mismatch")
        _positive_integer(cluster, "project_count")
        _positive_integer(cluster, "cwe_count")
        _non_negative_integer(cluster, "evaluable_case_count")
        _non_negative_integer(cluster, "paired_gain_ceiling_count")
        _non_negative_integer(cluster, "general_fix_candidate_count")
        _non_negative_integer(cluster, "transversality_score")
        _string_tuple(cluster, "semantic_primitives")
    if cluster_categories != set(category_frequency):
        raise ValueError("aggregate clusters do not cover every category")

    top_three = _string_tuple(aggregate, "top_three_categories")
    if len(top_three) > 3 or len(set(top_three)) != len(top_three):
        raise ValueError("top-three categories must be unique and bounded")
    if any(category not in cluster_categories for category in top_three):
        raise ValueError("top-three category is absent from clusters")
    _non_negative_integer(aggregate, "top_three_case_count")
    _non_negative_integer(aggregate, "top_three_project_union_count")
    _non_negative_integer(aggregate, "top_three_cwe_union_count")

    inputs = _mapping(payload, "inputs")
    for key in (
        "dataset_sha256",
        "manifest_sha256",
        "manifest_digest",
        "baseline_sha256",
        "baseline_digest",
        "reviewer_source_sha256",
        "manual_attribution_sha256",
    ):
        _sha256(inputs.get(key), f"input {key}")
    _mapping(payload, "baseline_metrics")
    boundaries = _mapping(payload, "boundaries")
    required_false = (
        "reserved_test_case_ids_emitted_or_used",
        "reserved_test_case_details_inspected",
        "reference_security_delta_forwarded_to_reviewer",
        "benchmark_labels_forwarded_to_reviewer",
        "manual_attribution_is_production_rule_input",
        "report_is_static_secpass_equivalent",
    )
    required_true = (
        "development_cases_only",
        "reference_security_delta_used_by_evaluator",
    )
    for key in required_false:
        if _boolean(boundaries, key):
            raise ValueError(f"failure report boundary must be false: {key}")
    for key in required_true:
        if not _boolean(boundaries, key):
            raise ValueError(f"failure report boundary must be true: {key}")

    recorded_digest = _sha256(
        payload.get("deterministic_digest"),
        "failure report deterministic digest",
    )
    semantic = {
        key: value
        for key, value in payload.items()
        if key != "deterministic_digest"
    }
    if recorded_digest != _semantic_digest(semantic):
        raise ValueError("generalization failure report digest mismatch")
    return json.loads(json.dumps(payload))


def load_generalization_failure_report(
    path: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Load a JSON report and enforce the complete v1 contract."""

    report_path = Path(path)
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"invalid generalization failure report: {report_path}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ValueError("generalization failure report must be an object")
    return validate_generalization_failure_report(payload, **kwargs)


def write_generalization_failure_report(
    payload: Mapping[str, Any],
    output: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Validate and create a report without replacing an existing artifact."""

    prepared = dict(payload)
    prepared.pop("deterministic_digest", None)
    prepared["deterministic_digest"] = _semantic_digest(prepared)
    validated = validate_generalization_failure_report(prepared, **kwargs)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open(
            "x",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(validated, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite generalization failure report: "
            f"{output_path}"
        ) from exc
    return validated


def _semantic_digest(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ValueError(f"{key} must be an object")
    return selected


def _non_empty_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return selected


def _boolean(value: Mapping[str, Any], key: str) -> bool:
    selected = value.get(key)
    if not isinstance(selected, bool):
        raise ValueError(f"{key} must be boolean")
    return selected


def _positive_integer(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool) or selected <= 0:
        raise ValueError(f"{key} must be a positive integer")
    return selected


def _non_negative_integer(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool) or selected < 0:
        raise ValueError(f"{key} must be a non-negative integer")
    return selected


def _string_tuple(
    value: Mapping[str, Any],
    key: str,
    *,
    allow_empty: bool = False,
) -> tuple[str, ...]:
    selected = value.get(key)
    if (
        not isinstance(selected, Sequence)
        or isinstance(selected, (str, bytes))
    ):
        raise ValueError(f"{key} must be an array of strings")
    result = tuple(selected)
    _validate_string_tuple(key, result, allow_empty=allow_empty)
    return result


def _validate_string_tuple(
    name: str,
    value: tuple[str, ...],
    *,
    allow_empty: bool = False,
) -> None:
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{name} must contain non-empty strings")


def _sha256(value: Any, label: str) -> str:
    selected = str(value or "")
    if (
        len(selected) != 64
        or any(character not in "0123456789abcdef" for character in selected)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return selected


def _integer_mapping(
    value: Mapping[str, Any],
    key: str,
) -> dict[str, int]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ValueError(f"{key} must be an object")
    result: dict[str, int] = {}
    for raw_key, raw_value in selected.items():
        normalized_key = str(raw_key)
        if (
            not normalized_key
            or not isinstance(raw_value, int)
            or isinstance(raw_value, bool)
            or raw_value < 0
        ):
            raise ValueError(
                f"{key} must map non-empty strings to non-negative integers"
            )
        result[normalized_key] = raw_value
    return dict(sorted(result.items()))


__all__ = [
    "FAILURE_CATEGORIES",
    "GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION",
    "FailureCaseAttribution",
    "load_generalization_failure_report",
    "validate_generalization_failure_report",
    "write_generalization_failure_report",
]
