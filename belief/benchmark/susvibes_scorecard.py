"""Validated scorecards for official SusVibes evaluator summaries."""

from __future__ import annotations

import hashlib
import json
import math
import os
from datetime import datetime, timezone
from pathlib import Path
from statistics import fmean
from typing import Any, Mapping, Sequence

from .susvibes_experiment import load_experiment_cohort


SUSVIBES_SCORECARD_SCHEMA_VERSION = "belief.susvibes_official_scorecard.v1"
SECURITY_COMPARATORS_SCHEMA_VERSION = "belief.security_comparators.v1"

_RATE_TOLERANCE = 1e-12
_WILSON_Z_95 = 1.959963984540054


def build_susvibes_official_scorecard(
    *,
    experiment_manifest: str | Path,
    dataset: str | Path,
    cohort: str,
    summaries: Sequence[str | Path],
    labels: Sequence[str] = (),
    comparators: str | Path | None = None,
) -> dict[str, Any]:
    """Validate official summaries and build an honest multi-run scorecard."""

    if not summaries:
        raise ValueError("at least one official summary is required")
    if labels and len(labels) != len(summaries):
        raise ValueError("labels must match the number of summaries")
    normalized_labels = (
        [str(value).strip() for value in labels]
        if labels
        else [f"run-{index + 1:02d}" for index in range(len(summaries))]
    )
    if any(not value for value in normalized_labels):
        raise ValueError("summary labels must not be empty")
    if len(normalized_labels) != len(set(normalized_labels)):
        raise ValueError("summary labels must be unique")

    manifest_path = Path(experiment_manifest).resolve()
    selected_ids, selection = load_experiment_cohort(
        manifest_path,
        cohort,
        dataset=Path(dataset).resolve(),
    )
    manifest_payload = _read_json_object(
        manifest_path,
        artifact_name="experiment manifest",
    )
    cohorts = manifest_payload.get("cohorts")
    if not isinstance(cohorts, Mapping):
        raise ValueError("experiment manifest cohorts are missing")
    cohort_payload = cohorts.get(cohort)
    if not isinstance(cohort_payload, Mapping):
        raise ValueError(f"experiment cohort is invalid: {cohort}")

    selected = frozenset(selected_ids)
    run_payloads = []
    seen_summary_paths: set[Path] = set()
    for label, raw_path in zip(normalized_labels, summaries):
        summary_path = Path(raw_path).resolve()
        if summary_path in seen_summary_paths:
            raise ValueError("official summary paths must be unique")
        seen_summary_paths.add(summary_path)
        summary = _read_json_object(
            summary_path,
            artifact_name="official SusVibes summary",
        )
        run_payloads.append(
            _validate_official_summary(
                summary,
                selected_ids=selected,
                ordered_ids=selected_ids,
                label=label,
                path=summary_path,
            )
        )

    comparator_payload = _load_comparators(comparators)
    stability = _stability_payload(run_payloads, selected_ids)
    comparisons = [
        _comparison_payload(
            reference,
            runs=run_payloads,
            cohort=cohort,
            case_count=len(selected_ids),
        )
        for reference in comparator_payload["references"]
    ]
    full_run = cohort == "full"
    two_full_artifacts = full_run and len(run_payloads) >= 2
    no_indeterminate = all(
        run["counts"]["indeterminate"] == 0
        for run in run_payloads
    )
    complete_submissions = all(
        run["counts"]["submitted"] == len(selected_ids)
        for run in run_payloads
    )

    report: dict[str, Any] = {
        "schema_version": SUSVIBES_SCORECARD_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "official_susvibes_summary_validation",
        "experiment": {
            "manifest": str(manifest_path),
            "dataset": str(Path(dataset).resolve()),
            **selection,
            "susvibes_commit": str(
                manifest_payload.get("dataset", {}).get(
                    "susvibes_commit",
                    "",
                )
            ),
            "cohort": cohort,
            "cohort_purpose": str(cohort_payload.get("purpose") or ""),
            "case_count": len(selected_ids),
        },
        "runs": run_payloads,
        "stability": stability,
        "comparators": {
            "schema_version": comparator_payload["schema_version"],
            "as_of": comparator_payload["as_of"],
            "source_path": comparator_payload["source_path"],
            "source_sha256": comparator_payload["source_sha256"],
            "numerical_secpass_references": comparisons,
            "non_comparable_context": comparator_payload["context"],
        },
        "claim_boundary": {
            "official_summary_contract_validated": True,
            "security_test_execution": "reported_by_official_summary",
            "full_public_v1_cohort": full_run,
            "two_full_summary_artifacts_available": two_full_artifacts,
            "independent_run_provenance_validated": False,
            "all_predictions_submitted": complete_submissions,
            "all_runs_without_indeterminate": no_indeterminate,
            "canary_is_score_bearing": False,
            "direct_agent_security_league_win_established": False,
            "kimi_known_cve_win_established": False,
            "external_anti_cheating_adjudication_completed": False,
            "leaderboard_claim_allowed": False,
            "wilson_intervals_are_descriptive_not_run_variance": True,
        },
    }
    report["report_digest"] = _semantic_digest(report)
    return report


def write_susvibes_official_scorecard(
    output: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Create a scorecard without overwriting an existing artifact."""

    payload = build_susvibes_official_scorecard(**kwargs)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite SusVibes scorecard: {output_path}"
        ) from exc
    return payload


def _validate_official_summary(
    payload: Mapping[str, Any],
    *,
    selected_ids: frozenset[str],
    ordered_ids: list[str],
    label: str,
    path: Path,
) -> dict[str, Any]:
    candidate_count = _integer(payload, "num_candidates")
    submitted = _integer(payload, "num_submitted")
    if candidate_count != len(selected_ids):
        raise ValueError(
            f"{label}: official candidate count does not match cohort"
        )
    if not 0 <= submitted <= candidate_count:
        raise ValueError(f"{label}: invalid submitted count")

    details = payload.get("details")
    if not isinstance(details, Mapping):
        raise ValueError(f"{label}: official summary details are missing")
    completed = details.get("completed")
    if not isinstance(completed, Mapping):
        raise ValueError(f"{label}: completed details are missing")
    groups = {
        "empty_model_patch": _id_list(
            details.get("empty_model_patch"),
            label=label,
            field="empty_model_patch",
        ),
        "model_patch_error": _id_list(
            details.get("model_patch_error"),
            label=label,
            field="model_patch_error",
        ),
        "indeterminate": _id_list(
            details.get("indeterminate"),
            label=label,
            field="indeterminate",
        ),
        "func_pass": _id_list(
            completed.get("func_pass"),
            label=label,
            field="completed.func_pass",
        ),
        "sec_pass": _id_list(
            completed.get("sec_pass"),
            label=label,
            field="completed.sec_pass",
        ),
    }
    for field, values in groups.items():
        outside = sorted(set(values) - selected_ids)
        if outside:
            raise ValueError(
                f"{label}: {field} contains IDs outside the cohort"
            )
    func_ids = set(groups["func_pass"])
    sec_ids = set(groups["sec_pass"])
    if not sec_ids <= func_ids:
        raise ValueError(f"{label}: SecPass must be a subset of FuncPass")
    failure_groups = [
        set(groups["empty_model_patch"]),
        set(groups["model_patch_error"]),
        set(groups["indeterminate"]),
    ]
    for index, first in enumerate(failure_groups):
        if first & func_ids:
            raise ValueError(
                f"{label}: failed instances overlap FuncPass"
            )
        if any(first & other for other in failure_groups[index + 1:]):
            raise ValueError(
                f"{label}: failure status groups overlap"
            )

    expected_counts = {
        "empty_model_patch": _integer(
            payload,
            "num_empty_model_patch",
        ),
        "model_patch_error": _integer(
            payload,
            "num_model_patch_errors",
        ),
        "indeterminate": _integer(payload, "num_indeterminate"),
    }
    for field, expected in expected_counts.items():
        if expected != len(groups[field]):
            raise ValueError(f"{label}: {field} count mismatch")
    accounted_ids = set().union(*failure_groups, func_ids)
    if len(accounted_ids) > submitted:
        raise ValueError(
            f"{label}: summary accounts for more IDs than submitted"
        )

    func_rate = _rate(payload, "func_pass")
    sec_rate = _rate(payload, "sec_pass")
    expected_func_rate = len(func_ids) / candidate_count
    expected_sec_rate = len(sec_ids) / candidate_count
    if not math.isclose(
        func_rate,
        expected_func_rate,
        rel_tol=0.0,
        abs_tol=_RATE_TOLERANCE,
    ):
        raise ValueError(f"{label}: FuncPass ratio mismatch")
    if not math.isclose(
        sec_rate,
        expected_sec_rate,
        rel_tol=0.0,
        abs_tol=_RATE_TOLERANCE,
    ):
        raise ValueError(f"{label}: SecPass ratio mismatch")

    order = {instance_id: index for index, instance_id in enumerate(ordered_ids)}
    normalized_groups = {
        key: sorted(values, key=order.__getitem__)
        for key, values in groups.items()
    }
    return {
        "label": label,
        "summary_path": str(path),
        "summary_sha256": _file_sha256(
            path,
            allowed_root=path.parent,
        ),
        "counts": {
            "candidates": candidate_count,
            "submitted": submitted,
            "missing_predictions": candidate_count - submitted,
            "empty_model_patch": expected_counts["empty_model_patch"],
            "model_patch_error": expected_counts["model_patch_error"],
            "indeterminate": expected_counts["indeterminate"],
            "completed_without_pass": submitted - len(accounted_ids),
            "func_pass": len(func_ids),
            "sec_pass": len(sec_ids),
        },
        "rates": {
            "func_pass": func_rate,
            "sec_pass": sec_rate,
            "func_pass_percent": round(func_rate * 100, 4),
            "sec_pass_percent": round(sec_rate * 100, 4),
            "secure_given_functional": (
                round(len(sec_ids) / len(func_ids), 6)
                if func_ids
                else 0.0
            ),
        },
        "wilson_95": {
            "func_pass": _wilson_interval(
                len(func_ids),
                candidate_count,
            ),
            "sec_pass": _wilson_interval(
                len(sec_ids),
                candidate_count,
            ),
        },
        "details": normalized_groups,
    }


def _stability_payload(
    runs: list[dict[str, Any]],
    ordered_ids: list[str],
) -> dict[str, Any]:
    sec_sets = [
        set(run["details"]["sec_pass"])
        for run in runs
    ]
    union = set().union(*sec_sets)
    intersection = set.intersection(*sec_sets)
    threshold = len(runs) // 2 + 1
    frequencies = {
        instance_id: sum(instance_id in values for values in sec_sets)
        for instance_id in ordered_ids
    }
    strict_majority = {
        instance_id
        for instance_id, frequency in frequencies.items()
        if frequency >= threshold
    }
    order = {instance_id: index for index, instance_id in enumerate(ordered_ids)}
    pairwise = []
    for left_index, left in enumerate(runs):
        for right_index in range(left_index + 1, len(runs)):
            right = runs[right_index]
            left_set = sec_sets[left_index]
            right_set = sec_sets[right_index]
            denominator = len(left_set | right_set)
            pairwise.append({
                "left": left["label"],
                "right": right["label"],
                "sec_pass_jaccard": (
                    round(len(left_set & right_set) / denominator, 6)
                    if denominator
                    else 1.0
                ),
            })
    case_count = len(ordered_ids)
    return {
        "run_count": len(runs),
        "func_pass": _rate_distribution(
            [run["rates"]["func_pass"] for run in runs]
        ),
        "sec_pass": _rate_distribution(
            [run["rates"]["sec_pass"] for run in runs]
        ),
        "sec_pass_union_diagnostic": {
            "count": len(union),
            "rate": round(len(union) / case_count, 6),
            "instance_ids": sorted(union, key=order.__getitem__),
            "leaderboard_metric": False,
        },
        "sec_pass_intersection": {
            "count": len(intersection),
            "rate": round(len(intersection) / case_count, 6),
            "instance_ids": sorted(intersection, key=order.__getitem__),
        },
        "sec_pass_strict_majority": {
            "minimum_runs": threshold,
            "count": len(strict_majority),
            "rate": round(len(strict_majority) / case_count, 6),
            "instance_ids": sorted(
                strict_majority,
                key=order.__getitem__,
            ),
        },
        "per_instance_sec_pass_frequency": frequencies,
        "pairwise": pairwise,
    }


def _comparison_payload(
    reference: Mapping[str, Any],
    *,
    runs: list[dict[str, Any]],
    cohort: str,
    case_count: int,
) -> dict[str, Any]:
    reference_id = str(reference.get("id") or "")
    target = float(reference.get("sec_pass", -1))
    if not reference_id or not 0.0 <= target <= 1.0:
        raise ValueError("invalid SecPass comparator")
    minimum_count = math.floor(target * case_count + 1e-12) + 1
    observed_rates = [run["rates"]["sec_pass"] for run in runs]
    direct = bool(
        reference.get("directly_comparable_to_public_susvibes_v1")
    )
    if cohort != "full":
        status = "engineering_cohort_not_score_bearing"
    elif not direct:
        status = "numerical_only_different_protocol"
    else:
        status = "direct_comparison_requires_external_adjudication"
    return {
        **dict(reference),
        "comparison_status": status,
        "public_v1_case_count": case_count,
        "minimum_sec_pass_count_to_numerically_exceed": minimum_count,
        "minimum_sec_pass_count_for_wilson_lower_bound_to_exceed": (
            _minimum_wilson_count(target, case_count)
        ),
        "per_run_delta_percentage_points": [
            round((value - target) * 100, 4)
            for value in observed_rates
        ],
        "all_runs_numerically_exceed": all(
            value > target for value in observed_rates
        ),
        "any_run_numerically_exceeds": any(
            value > target for value in observed_rates
        ),
        "all_run_wilson_lower_bounds_exceed": all(
            run["wilson_95"]["sec_pass"]["lower"] > target
            for run in runs
        ),
        "direct_win_claim_allowed": False,
    }


def _load_comparators(
    comparators: str | Path | None,
) -> dict[str, Any]:
    if comparators is None:
        return {
            "schema_version": SECURITY_COMPARATORS_SCHEMA_VERSION,
            "as_of": "",
            "source_path": "",
            "source_sha256": "",
            "references": [],
            "context": [],
        }
    path = Path(comparators).resolve()
    payload = _read_json_object(
        path,
        artifact_name="security comparator snapshot",
    )
    if payload.get("schema_version") != SECURITY_COMPARATORS_SCHEMA_VERSION:
        raise ValueError("unsupported security comparator schema")
    references = payload.get("references")
    context = payload.get("context")
    if not isinstance(references, list) or not all(
        isinstance(value, Mapping)
        and value.get("metric") == "susvibes_secpass"
        for value in references
    ):
        raise ValueError("invalid SecPass comparator references")
    if not isinstance(context, list) or not all(
        isinstance(value, Mapping)
        for value in context
    ):
        raise ValueError("invalid non-comparable context")
    return {
        "schema_version": payload["schema_version"],
        "as_of": str(payload.get("as_of") or ""),
        "source_path": str(path),
        "source_sha256": _file_sha256(
            path,
            allowed_root=path.parent,
        ),
        "references": [dict(value) for value in references],
        "context": [dict(value) for value in context],
    }


def _read_json_object(
    path: Path,
    *,
    artifact_name: str,
) -> Mapping[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {artifact_name}: {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{artifact_name} must be a JSON object")
    return payload


def _integer(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"official summary field must be an integer: {key}")
    return value


def _rate(payload: Mapping[str, Any], key: str) -> float:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"official summary field must be numeric: {key}")
    normalized = float(value)
    if not math.isfinite(normalized) or not 0.0 <= normalized <= 1.0:
        raise ValueError(f"official summary rate is invalid: {key}")
    return normalized


def _id_list(value: Any, *, label: str, field: str) -> list[str]:
    if not isinstance(value, list):
        raise ValueError(f"{label}: {field} must be a list")
    normalized = [str(item) for item in value]
    if any(not item for item in normalized):
        raise ValueError(f"{label}: {field} contains an empty ID")
    if len(normalized) != len(set(normalized)):
        raise ValueError(f"{label}: {field} contains duplicate IDs")
    return normalized


def _wilson_interval(successes: int, total: int) -> dict[str, float]:
    lower, upper = _wilson_bounds(successes, total)
    return {
        "lower": round(lower, 6),
        "upper": round(upper, 6),
    }


def _wilson_bounds(successes: int, total: int) -> tuple[float, float]:
    proportion = successes / total
    z_squared = _WILSON_Z_95 ** 2
    denominator = 1 + z_squared / total
    center = (
        proportion + z_squared / (2 * total)
    ) / denominator
    margin = (
        _WILSON_Z_95
        * math.sqrt(
            proportion * (1 - proportion) / total
            + z_squared / (4 * total ** 2)
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _minimum_wilson_count(target: float, total: int) -> int:
    for successes in range(total + 1):
        lower, _upper = _wilson_bounds(successes, total)
        if lower > target:
            return successes
    return total + 1


def _rate_distribution(values: list[float]) -> dict[str, float]:
    return {
        "minimum": round(min(values), 6),
        "mean": round(fmean(values), 6),
        "maximum": round(max(values), 6),
        "range": round(max(values) - min(values), 6),
    }


def _file_sha256(path: Path, *, allowed_root: Path) -> str:
    candidate = path.resolve()
    root = allowed_root.resolve()
    try:
        common_path = os.path.commonpath((candidate, root))
    except ValueError as exc:
        raise ValueError(
            f"scorecard artifact crosses a storage boundary: {path}"
        ) from exc
    if Path(common_path) != root:
        raise ValueError(
            f"scorecard artifact escapes its allowed root: {path}"
        )
    if not candidate.is_file():
        raise ValueError(f"scorecard artifact does not exist: {path}")
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key != "report_digest"
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "SECURITY_COMPARATORS_SCHEMA_VERSION",
    "SUSVIBES_SCORECARD_SCHEMA_VERSION",
    "build_susvibes_official_scorecard",
    "write_susvibes_official_scorecard",
]
