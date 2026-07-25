"""Freeze a nested SusVibes development/test split before case inspection.

The parent cohort is split using only instance IDs, evaluator-side primary CWE
strata, and the baseline ``analysis_succeeded`` flag. Reconstruction failures
are forced into development so the reserved test measures reviewer behavior
rather than already-known evaluator failures. Security outcomes, findings,
patches, task text, and source code do not influence allocation.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from collections import Counter, defaultdict
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from belief.benchmark.susvibes_experiment import load_experiment_cohort


NESTED_SPLIT_ALGORITHM = "artifact_unseen_cwe_balanced_nested_split_v1"
PARENT_COHORT = "holdout"
DEV_COHORT = "canary"
TEST_COHORT = "holdout"
PARENT_AUDIT_COHORT = "artifact_unseen_parent"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a deterministic nested development/test split from an "
            "artifact-unseen SusVibes cohort."
        )
    )
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--parent-manifest", required=True)
    parser.add_argument(
        "--baseline-result",
        required=True,
        help=(
            "Frozen candidate-review result used only for IDs and the "
            "analysis_succeeded flag"
        ),
    )
    parser.add_argument(
        "--dev-size",
        type=int,
        default=0,
        help="Development size (default: half of the parent cohort)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=12,
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only nested experiment manifest",
    )
    return parser.parse_args()


def build_nested_split_manifest(
    dataset: str | Path,
    parent_manifest: str | Path,
    baseline_result: str | Path,
    *,
    dev_size: int = 0,
    batch_size: int = 12,
) -> dict[str, Any]:
    """Build a nested split without consulting per-case security outcomes."""

    if batch_size <= 0:
        raise ValueError("batch_size must be positive")
    dataset_path = Path(dataset).resolve()
    parent_path = Path(parent_manifest).resolve()
    baseline_path = Path(baseline_result).resolve()
    parent = _read_json_object(parent_path, label="parent manifest")
    parent_ids, _ = load_experiment_cohort(
        parent_path,
        PARENT_COHORT,
        dataset=dataset_path,
    )
    parent_count = len(parent_ids)
    selected_dev_size = dev_size or parent_count // 2
    if not 1 <= selected_dev_size < parent_count:
        raise ValueError(
            "dev_size must be between one and parent cohort size minus one"
        )
    selected_test_size = parent_count - selected_dev_size

    baseline = _read_json_object(
        baseline_path,
        label="baseline candidate-review result",
    )
    failed_ids, baseline_provenance = _validate_baseline(
        baseline,
        baseline_path=baseline_path,
        parent=parent,
        parent_ids=parent_ids,
    )
    if len(failed_ids) > selected_dev_size:
        raise ValueError(
            "known reconstruction failures exceed development capacity"
        )

    metadata = parent.get("evaluator_metadata")
    if not isinstance(metadata, Mapping):
        raise ValueError("parent evaluator metadata is missing")
    primary_cwes = {
        instance_id: _primary_cwe(metadata, instance_id)
        for instance_id in parent_ids
    }
    dev_ids, test_ids = _allocate(
        parent_ids,
        primary_cwes=primary_cwes,
        forced_dev=failed_ids,
        dev_size=selected_dev_size,
        test_size=selected_test_size,
        seed=str(parent.get("deterministic_digest") or ""),
    )

    derived = copy.deepcopy(parent)
    original_parent = copy.deepcopy(derived["cohorts"][PARENT_COHORT])
    original_parent["purpose"] = (
        "artifact-unseen parent retained for split audit only"
    )
    derived["cohorts"][PARENT_AUDIT_COHORT] = original_parent
    derived["cohorts"][DEV_COHORT] = _cohort_payload(
        dev_ids,
        metadata,
        purpose=(
            "nested development cohort; case details may be inspected and "
            "reviewer behavior may be tuned"
        ),
    )
    derived["cohorts"][TEST_COHORT] = _cohort_payload(
        test_ids,
        metadata,
        purpose=(
            "nested reserved test cohort; case details must remain "
            "uninspected until the reviewer is frozen"
        ),
    )
    smoke_ids = dev_ids[:min(3, len(dev_ids))]
    derived["cohorts"]["smoke"] = _cohort_payload(
        smoke_ids,
        metadata,
        purpose="nested development pipeline smoke only",
    )
    derived["nested_dev_batches"] = _batch_rows(
        dev_ids,
        batch_size,
        prefix="nested-dev",
    )
    derived["nested_test_batches"] = _batch_rows(
        test_ids,
        batch_size,
        prefix="nested-test",
    )
    derived["holdout_batches"] = copy.deepcopy(
        derived["nested_test_batches"]
    )
    derived["selection_algorithm"] = (
        f"{parent.get('selection_algorithm', '')}+"
        f"{NESTED_SPLIT_ALGORITHM}"
    )
    parameters = derived.setdefault("parameters", {})
    parameters.update(
        {
            "nested_dev_size": selected_dev_size,
            "nested_test_size": selected_test_size,
            "nested_batch_size": batch_size,
        }
    )
    derived["nested_split_audit"] = {
        "algorithm": NESTED_SPLIT_ALGORITHM,
        "parent_manifest_name": parent_path.name,
        "parent_manifest_sha256": _file_sha256(
            parent_path,
            allowed_root=parent_path.parent,
        ),
        "parent_manifest_digest": str(
            parent.get("deterministic_digest") or ""
        ),
        "parent_cohort": PARENT_COHORT,
        "parent_case_count": parent_count,
        "parent_ids_sha256": _ids_sha256(parent_ids),
        "baseline_result_name": baseline_path.name,
        **baseline_provenance,
        "forced_development_reconstruction_failure_count": len(
            failed_ids
        ),
        "development_case_count": len(dev_ids),
        "development_ids_sha256": _ids_sha256(dev_ids),
        "test_case_count": len(test_ids),
        "test_ids_sha256": _ids_sha256(test_ids),
        "allocation_inputs": [
            "instance_id",
            "primary_cwe_stratum",
            "analysis_succeeded",
        ],
        "baseline_json_loaded": True,
        "baseline_security_outcomes_used": False,
        "baseline_findings_used": False,
        "task_text_used": False,
        "source_code_used": False,
        "parent_aggregate_metrics_known_before_split": True,
        "individual_security_outcomes_inspected_before_split": False,
        "reconstruction_failures_forced_to_development": True,
    }
    boundaries = derived.setdefault("boundaries", {})
    boundaries.update(
        {
            "nested_development_may_be_tuned": True,
            "nested_test_case_details_inspected_before_split": False,
            "nested_test_security_outcomes_used_for_allocation": False,
            "nested_test_requires_frozen_reviewer": True,
            "nested_test_is_leaderboard_comparable": False,
        }
    )
    derived.pop("deterministic_digest", None)
    derived["deterministic_digest"] = _semantic_digest(derived)
    return derived


def write_nested_split_manifest(
    dataset: str | Path,
    parent_manifest: str | Path,
    baseline_result: str | Path,
    output: str | Path,
    *,
    dev_size: int = 0,
    batch_size: int = 12,
) -> dict[str, Any]:
    """Create the nested manifest without overwriting an artifact."""

    payload = build_nested_split_manifest(
        dataset,
        parent_manifest,
        baseline_result,
        dev_size=dev_size,
        batch_size=batch_size,
    )
    output_path = Path(output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite nested split manifest: {output_path}"
        ) from exc
    return payload


def _validate_baseline(
    baseline: Mapping[str, Any],
    *,
    baseline_path: Path,
    parent: Mapping[str, Any],
    parent_ids: list[str],
) -> tuple[set[str], dict[str, Any]]:
    if baseline.get("schema_version") != (
        "belief.susvibes_candidate_review.v1"
    ):
        raise ValueError("unsupported baseline candidate-review schema")
    parent_dataset = parent.get("dataset")
    if not isinstance(parent_dataset, Mapping):
        raise ValueError("parent dataset metadata is missing")
    if str(baseline.get("dataset_sha256") or "") != str(
        parent_dataset.get("sha256") or ""
    ):
        raise ValueError("baseline dataset hash mismatch")
    rows = baseline.get("cases")
    if not isinstance(rows, list):
        raise ValueError("baseline result has no case rows")
    if int(baseline.get("case_count", -1)) != len(rows):
        raise ValueError("baseline result case count mismatch")

    expected_ids_sha = _ids_sha256(parent_ids)
    selection = baseline.get("selection")
    if not isinstance(selection, Mapping):
        raise ValueError("baseline selection provenance is missing")
    if str(selection.get("instance_ids_sha256") or "") != expected_ids_sha:
        raise ValueError("baseline selection ID hash mismatch")

    observed: set[str] = set()
    failed: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            raise ValueError("baseline case row must be an object")
        instance_id = str(row.get("id") or "")
        if not instance_id or instance_id in observed:
            raise ValueError("baseline case IDs must be present and unique")
        succeeded = row.get("analysis_succeeded")
        if not isinstance(succeeded, bool):
            raise ValueError(
                "baseline analysis_succeeded must be boolean"
            )
        observed.add(instance_id)
        if not succeeded:
            failed.add(instance_id)
    if observed != set(parent_ids):
        raise ValueError("baseline case IDs do not match parent cohort")

    reviewer = baseline.get("reviewer_provenance")
    reviewer_source_sha = ""
    if isinstance(reviewer, Mapping):
        reviewer_source_sha = str(
            reviewer.get("belief_python_source_sha256") or ""
        )
    return failed, {
        "baseline_result_sha256": _file_sha256(
            baseline_path,
            allowed_root=baseline_path.parent,
        ),
        "baseline_result_digest": str(
            baseline.get("deterministic_digest") or ""
        ),
        "baseline_reviewer_source_sha256": reviewer_source_sha,
    }


def _allocate(
    parent_ids: list[str],
    *,
    primary_cwes: Mapping[str, str],
    forced_dev: set[str],
    dev_size: int,
    test_size: int,
    seed: str,
) -> tuple[list[str], list[str]]:
    parent_set = set(parent_ids)
    if not forced_dev <= parent_set:
        raise ValueError("forced development IDs are outside parent cohort")

    assignments: dict[str, str] = {
        instance_id: "dev"
        for instance_id in forced_dev
    }
    totals = Counter({"dev": len(forced_dev), "test": 0})
    strata: dict[str, Counter[str]] = defaultdict(Counter)
    for instance_id in forced_dev:
        strata[primary_cwes[instance_id]]["dev"] += 1

    remaining = sorted(
        parent_set - forced_dev,
        key=lambda instance_id: (
            sum(
                primary_cwes[value] == primary_cwes[instance_id]
                for value in parent_ids
            ),
            _rank(seed, "case", instance_id),
            instance_id,
        ),
    )
    targets = {"dev": dev_size, "test": test_size}
    for instance_id in remaining:
        cwe = primary_cwes[instance_id]
        available = [
            split
            for split in ("dev", "test")
            if totals[split] < targets[split]
        ]
        if not available:
            raise ValueError("nested split allocation exhausted capacity")
        selected = min(
            available,
            key=lambda split: (
                strata[cwe][split],
                totals[split] / targets[split],
                _rank(seed, f"assign-{split}", instance_id),
                split,
            ),
        )
        assignments[instance_id] = selected
        totals[selected] += 1
        strata[cwe][selected] += 1

    if totals != Counter({"dev": dev_size, "test": test_size}):
        raise ValueError("nested split allocation count mismatch")
    dev_ids = [
        instance_id
        for instance_id in parent_ids
        if assignments[instance_id] == "dev"
    ]
    test_ids = [
        instance_id
        for instance_id in parent_ids
        if assignments[instance_id] == "test"
    ]
    if set(dev_ids) & set(test_ids) or (
        set(dev_ids) | set(test_ids)
    ) != parent_set:
        raise ValueError("nested split is not a partition")
    return dev_ids, test_ids


def _primary_cwe(
    metadata: Mapping[str, Any],
    instance_id: str,
) -> str:
    row = metadata.get(instance_id)
    if not isinstance(row, Mapping):
        raise ValueError(
            f"missing evaluator metadata for case: {instance_id}"
        )
    return str(row.get("primary_cwe_stratum") or "unknown")


def _cohort_payload(
    instance_ids: list[str],
    metadata: Mapping[str, Any],
    *,
    purpose: str,
) -> dict[str, Any]:
    projects: set[str] = set()
    primary_cwes: set[str] = set()
    all_cwes: set[str] = set()
    for instance_id in instance_ids:
        row = metadata.get(instance_id)
        if not isinstance(row, Mapping):
            raise ValueError(
                f"missing evaluator metadata for case: {instance_id}"
            )
        project = str(row.get("project") or "")
        if project:
            projects.add(project)
        primary_cwes.add(
            str(row.get("primary_cwe_stratum") or "unknown")
        )
        raw_cwes = row.get("cwe_ids")
        if isinstance(raw_cwes, list):
            all_cwes.update(str(value) for value in raw_cwes)
    return {
        "purpose": purpose,
        "case_count": len(instance_ids),
        "instance_ids": list(instance_ids),
        "coverage": {
            "project_count": len(projects),
            "primary_cwe_strata_count": len(primary_cwes),
            "all_cwe_count": len(all_cwes),
        },
    }


def _batch_rows(
    instance_ids: list[str],
    size: int,
    *,
    prefix: str,
) -> list[dict[str, Any]]:
    return [
        {
            "batch_id": f"{prefix}-{index // size + 1:03d}",
            "start_index": index,
            "case_count": len(instance_ids[index:index + size]),
            "instance_ids": instance_ids[index:index + size],
        }
        for index in range(0, len(instance_ids), size)
    ]


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _rank(seed: str, namespace: str, value: str) -> str:
    return hashlib.sha256(
        f"{seed}\0{namespace}\0{value}".encode("utf-8")
    ).hexdigest()


def _ids_sha256(instance_ids: list[str]) -> str:
    encoded = json.dumps(
        instance_ids,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path, *, allowed_root: Path) -> str:
    candidate = path.resolve()
    root = allowed_root.resolve()
    try:
        common_path = os.path.commonpath((candidate, root))
    except ValueError as exc:
        raise ValueError(
            f"artifact crosses a storage boundary: {path}"
        ) from exc
    if Path(common_path) != root:
        raise ValueError(
            f"artifact escapes its allowed root: {path}"
        )
    if not candidate.is_file():
        raise ValueError(f"artifact does not exist: {path}")
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key != "deterministic_digest"
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def main() -> int:
    args = _arguments()
    try:
        payload = write_nested_split_manifest(
            args.dataset,
            args.parent_manifest,
            args.baseline_result,
            args.output,
            dev_size=int(args.dev_size),
            batch_size=int(args.batch_size),
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    audit = payload["nested_split_audit"]
    print(
        json.dumps(
            {
                "development_case_count": audit[
                    "development_case_count"
                ],
                "forced_development_reconstruction_failure_count": audit[
                    "forced_development_reconstruction_failure_count"
                ],
                "manifest": str(Path(args.output).resolve()),
                "semantic_digest": payload["deterministic_digest"],
                "test_case_count": audit["test_case_count"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
