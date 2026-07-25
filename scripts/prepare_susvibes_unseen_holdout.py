"""Derive an artifact-unseen SusVibes holdout from a frozen experiment.

Prior result artifacts are parsed as JSON, but only their case identifiers are
used by the derivation. Candidate findings, patches, tests, and task text do
not influence selection. The output is create-only and remains compatible
with ``load_experiment_cohort``.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from belief.benchmark.susvibes_experiment import load_experiment_cohort


DERIVATION_ALGORITHM = "prior_result_case_id_exclusion_v1"
DERIVED_COHORT = "holdout"
PARENT_HOLDOUT_COHORT = "parent_holdout"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a frozen SusVibes holdout that excludes every case ID "
            "present in prior result artifacts."
        )
    )
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--experiment-manifest", required=True)
    parser.add_argument(
        "--results-dir",
        required=True,
        help="Directory containing immutable prior JSON result artifacts",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="New create-only derived experiment manifest",
    )
    parser.add_argument(
        "--replay-artifact-index",
        default="",
        help=(
            "Existing derived manifest whose recorded prior-artifact names "
            "and hashes must be replayed exactly"
        ),
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=12,
        help="Derived holdout batch size (default: 12)",
    )
    return parser.parse_args()


def derive_unseen_holdout_manifest(
    dataset: str | Path,
    experiment_manifest: str | Path,
    results_dir: str | Path,
    *,
    batch_size: int = 12,
    replay_artifact_index: str | Path | None = None,
) -> dict[str, Any]:
    """Return a verified manifest excluding all previously evaluated IDs."""

    if batch_size <= 0:
        raise ValueError("batch_size must be positive")

    dataset_path = Path(dataset).resolve()
    parent_path = Path(experiment_manifest).resolve()
    result_root = Path(results_dir).resolve()
    if not result_root.is_dir():
        raise ValueError(f"results directory does not exist: {result_root}")

    parent = _read_json_object(parent_path, label="experiment manifest")
    parent_holdout, _ = load_experiment_cohort(
        parent_path,
        "holdout",
        dataset=dataset_path,
    )
    parent_full, _ = load_experiment_cohort(
        parent_path,
        "full",
        dataset=dataset_path,
    )
    full_ids = set(parent_full)
    holdout_ids = set(parent_holdout)

    observed_full: set[str] = set()
    artifact_rows: list[dict[str, Any]] = []
    artifact_paths = _prior_artifact_paths(
        result_root,
        replay_artifact_index=replay_artifact_index,
    )
    for artifact_path in artifact_paths:
        artifact = _read_json_object(
            artifact_path,
            label="result artifact",
        )
        case_ids = _case_ids(artifact)
        matched = sorted(case_ids & full_ids)
        if not matched:
            continue
        observed_full.update(matched)
        artifact_rows.append(
            {
                "name": artifact_path.name,
                "sha256": _file_sha256(
                    artifact_path,
                    allowed_root=result_root,
                ),
                "mode": str(artifact.get("mode") or ""),
                "case_count": len(case_ids),
                "matched_parent_full_count": len(matched),
            }
        )

    if not artifact_rows:
        raise ValueError(
            "no prior SusVibes result artifact with case IDs was found"
        )

    observed_holdout = observed_full & holdout_ids
    unseen_ids = [
        instance_id
        for instance_id in parent_holdout
        if instance_id not in observed_holdout
    ]
    if not unseen_ids:
        raise ValueError("prior artifacts exhaust the parent holdout")

    derived = copy.deepcopy(parent)
    metadata = derived.get("evaluator_metadata")
    if not isinstance(metadata, Mapping):
        raise ValueError("experiment evaluator metadata is missing")
    derived["selection_algorithm"] = (
        f"{parent.get('selection_algorithm', '')}+{DERIVATION_ALGORITHM}"
    )
    derived["cohorts"][PARENT_HOLDOUT_COHORT] = copy.deepcopy(
        derived["cohorts"]["holdout"]
    )
    derived["cohorts"][PARENT_HOLDOUT_COHORT]["purpose"] = (
        "historical parent holdout retained for audit only; contains IDs "
        "seen in prior local result artifacts"
    )
    derived["cohorts"][DERIVED_COHORT] = _cohort_payload(
        unseen_ids,
        metadata,
    )
    unseen_batches = [
        {
            "batch_id": f"artifact-unseen-batch-{index + 1:03d}",
            "start_index": index * batch_size,
            "case_count": len(batch),
            "instance_ids": batch,
        }
        for index, batch in enumerate(_chunks(unseen_ids, batch_size))
    ]
    derived["holdout_batches"] = unseen_batches
    derived["artifact_unseen_holdout_batches"] = copy.deepcopy(
        unseen_batches
    )

    artifact_set_sha = _semantic_digest({"artifacts": artifact_rows})
    novelty_audit = {
        "algorithm": DERIVATION_ALGORITHM,
        "parent_manifest_name": parent_path.name,
        "parent_manifest_sha256": _file_sha256(
            parent_path,
            allowed_root=parent_path.parent,
        ),
        "parent_manifest_digest": str(
            parent.get("deterministic_digest") or ""
        ),
        "prior_artifact_count": len(artifact_rows),
        "prior_artifact_set_sha256": artifact_set_sha,
        "prior_artifacts": artifact_rows,
        "observed_parent_full_case_count": len(observed_full),
        "observed_parent_full_ids_sha256": _ids_sha256(
            sorted(observed_full)
        ),
        "observed_parent_holdout_case_count": len(observed_holdout),
        "observed_parent_holdout_ids_sha256": _ids_sha256(
            sorted(observed_holdout)
        ),
        "artifact_unseen_holdout_case_count": len(unseen_ids),
        "artifact_unseen_holdout_ids_sha256": _ids_sha256(unseen_ids),
        "dataset_case_records_loaded": False,
        "prior_result_json_loaded": True,
        "prior_result_case_fields_used": ["id", "instance_id"],
        "prior_result_findings_used": False,
    }
    derived["novelty_audit"] = novelty_audit

    boundaries = derived.setdefault("boundaries", {})
    boundaries.update(
        {
            "holdout_excludes_prior_result_ids": True,
            "holdout_is_leaderboard_comparable": False,
            "holdout_requires_frozen_reviewer": True,
            "parent_holdout_is_audit_only": True,
        }
    )
    derived.pop("deterministic_digest", None)
    derived["deterministic_digest"] = _semantic_digest(derived)
    return derived


def write_unseen_holdout_manifest(
    dataset: str | Path,
    experiment_manifest: str | Path,
    results_dir: str | Path,
    output: str | Path,
    *,
    batch_size: int = 12,
    replay_artifact_index: str | Path | None = None,
) -> dict[str, Any]:
    """Create a derived manifest without overwriting any artifact."""

    payload = derive_unseen_holdout_manifest(
        dataset,
        experiment_manifest,
        results_dir,
        batch_size=batch_size,
        replay_artifact_index=replay_artifact_index,
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
            f"refusing to overwrite derived manifest: {output_path}"
        ) from exc
    return payload


def _read_json_object(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object: {path}")
    return payload


def _case_ids(payload: Mapping[str, Any]) -> set[str]:
    rows = payload.get("cases")
    if not isinstance(rows, list):
        return set()
    instance_ids: set[str] = set()
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        value = row.get("id") or row.get("instance_id")
        if value:
            instance_ids.add(str(value))
    return instance_ids


def _prior_artifact_paths(
    result_root: Path,
    *,
    replay_artifact_index: str | Path | None,
) -> list[Path]:
    if replay_artifact_index is None:
        return sorted(
            path
            for path in result_root.glob("*.json")
            if path.is_file()
        )

    index_path = Path(replay_artifact_index).resolve()
    index = _read_json_object(index_path, label="replay artifact index")
    audit = index.get("novelty_audit")
    if not isinstance(audit, Mapping):
        raise ValueError("replay artifact index has no novelty audit")
    raw_rows = audit.get("prior_artifacts")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise ValueError("replay artifact index has no prior artifacts")

    paths: list[Path] = []
    observed_names: set[str] = set()
    for row in raw_rows:
        if not isinstance(row, Mapping):
            raise ValueError("invalid prior artifact index row")
        name = str(row.get("name") or "")
        expected_sha = str(row.get("sha256") or "").lower()
        if (
            not name
            or Path(name).name != name
            or "/" in name
            or "\\" in name
        ):
            raise ValueError("unsafe prior artifact name in replay index")
        if name in observed_names:
            raise ValueError("duplicate prior artifact in replay index")
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha):
            raise ValueError("invalid prior artifact hash in replay index")
        observed_names.add(name)
        candidate = (result_root / name).resolve()
        if candidate.parent != result_root or not candidate.is_file():
            raise ValueError(
                f"replay prior artifact does not exist: {name}"
            )
        if _file_sha256(
            candidate,
            allowed_root=result_root,
        ) != expected_sha:
            raise ValueError(
                f"replay prior artifact hash mismatch: {name}"
            )
        paths.append(candidate)
    return paths


def _cohort_payload(
    instance_ids: list[str],
    metadata: Mapping[str, Any],
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
        projects.add(str(row.get("project") or ""))
        primary_cwes.add(str(row.get("primary_cwe_stratum") or "unknown"))
        raw_cwes = row.get("cwe_ids")
        if isinstance(raw_cwes, list):
            all_cwes.update(str(value) for value in raw_cwes)
    projects.discard("")
    return {
        "purpose": (
            "parent holdout cases absent from every prior local result "
            "artifact at derivation time; static generalization only"
        ),
        "case_count": len(instance_ids),
        "instance_ids": list(instance_ids),
        "coverage": {
            "project_count": len(projects),
            "primary_cwe_strata_count": len(primary_cwes),
            "all_cwe_count": len(all_cwes),
        },
    }


def _chunks(values: list[str], size: int) -> list[list[str]]:
    return [
        values[index:index + size]
        for index in range(0, len(values), size)
    ]


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
        payload = write_unseen_holdout_manifest(
            args.dataset,
            args.experiment_manifest,
            args.results_dir,
            args.output,
            batch_size=int(args.batch_size),
            replay_artifact_index=(
                args.replay_artifact_index or None
            ),
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True))
        return 2
    audit = payload["novelty_audit"]
    print(
        json.dumps(
            {
                "cohort": DERIVED_COHORT,
                "deterministic_digest": payload["deterministic_digest"],
                "manifest": str(Path(args.output).resolve()),
                "observed_parent_holdout_case_count": audit[
                    "observed_parent_holdout_case_count"
                ],
                "prior_artifact_count": audit["prior_artifact_count"],
                "unseen_case_count": audit[
                    "artifact_unseen_holdout_case_count"
                ],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
