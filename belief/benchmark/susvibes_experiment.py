"""Deterministic public SusVibes experiment cohorts.

The manifest produced here is evaluator-side metadata. Agent runners may read
only the selected instance IDs after verifying the pinned dataset hash; CWE
labels, projects, and coverage summaries are never forwarded into prompts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Mapping

from .susvibes import load_susvibes_cases


SUSVIBES_EXPERIMENT_SCHEMA_VERSION = "belief.susvibes_experiment.v1"
SUSVIBES_EXPERIMENT_ALGORITHM = "dataset_hash_cwe_round_robin_v1"

_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")


def build_susvibes_experiment_manifest(
    dataset: str | Path,
    *,
    susvibes_commit: str,
    smoke_size: int = 3,
    canary_size: int = 24,
    batch_size: int = 12,
) -> dict[str, Any]:
    """Build breadth-first smoke, canary, and full public cohorts."""

    dataset_path = Path(dataset)
    dataset_sha256 = _file_sha256(
        dataset_path,
        allowed_root=dataset_path.resolve().parent,
    )
    cases = load_susvibes_cases(dataset_path)
    if not cases:
        raise ValueError("SusVibes dataset contains no Python cases")
    normalized_commit = str(susvibes_commit).strip().lower()
    if not _COMMIT_RE.fullmatch(normalized_commit):
        raise ValueError("susvibes_commit must be a 40-character Git commit")
    if not 1 <= smoke_size <= canary_size <= len(cases):
        raise ValueError(
            "cohort sizes must satisfy 1 <= smoke_size <= "
            "canary_size <= case_count"
        )
    if batch_size <= 0:
        raise ValueError("batch_size must be positive")

    ordered = _breadth_first_order(cases, dataset_sha256)
    smoke = ordered[:smoke_size]
    canary = ordered[:canary_size]
    full = ordered
    manifest: dict[str, Any] = {
        "schema_version": SUSVIBES_EXPERIMENT_SCHEMA_VERSION,
        "selection_algorithm": SUSVIBES_EXPERIMENT_ALGORITHM,
        "dataset": {
            "name": dataset_path.name,
            "sha256": dataset_sha256,
            "case_count": len(cases),
            "project_count": len({case["project"] for case in cases}),
            "cwe_count": len({
                cwe
                for case in cases
                for cwe in case["cwe_ids"]
            }),
            "susvibes_commit": normalized_commit,
        },
        "parameters": {
            "smoke_size": smoke_size,
            "canary_size": canary_size,
            "batch_size": batch_size,
        },
        "cohorts": {
            "smoke": _cohort_payload(
                smoke,
                purpose=(
                    "pipeline smoke test only; not a score estimate"
                ),
            ),
            "canary": _cohort_payload(
                canary,
                purpose=(
                    "CWE-breadth engineering canary; not prevalence-weighted "
                    "and not a leaderboard score"
                ),
            ),
            "full": _cohort_payload(
                full,
                purpose=(
                    "complete pinned public corpus; comparable only after "
                    "official FuncPass/SecPass evaluation"
                ),
            ),
        },
        "batches": [
            {
                "batch_id": f"batch-{index + 1:03d}",
                "start_index": index * batch_size,
                "case_count": len(batch),
                "instance_ids": [
                    str(case["instance_id"])
                    for case in batch
                ],
            }
            for index, batch in enumerate(
                _chunks(full, batch_size)
            )
        ],
        "evaluator_metadata": {
            str(case["instance_id"]): {
                "project": str(case["project"]),
                "cwe_ids": list(case["cwe_ids"]),
                "primary_cwe_stratum": _primary_cwe(case),
            }
            for case in sorted(
                cases,
                key=lambda item: item["instance_id"],
            )
        },
        "boundaries": {
            "manifest_is_evaluator_side": True,
            "agent_may_receive_instance_ids_only": True,
            "cwe_labels_forwarded_to_agent": False,
            "benchmark_oracle_forwarded_to_agent": False,
            "canary_is_leaderboard_comparable": False,
            "full_requires_official_security_tests": True,
        },
    }
    manifest["deterministic_digest"] = _semantic_digest(manifest)
    return manifest


def write_susvibes_experiment_manifest(
    dataset: str | Path,
    output: str | Path,
    *,
    susvibes_commit: str,
    smoke_size: int = 3,
    canary_size: int = 24,
    batch_size: int = 12,
) -> dict[str, Any]:
    """Create a manifest without overwriting an existing artifact."""

    payload = build_susvibes_experiment_manifest(
        dataset,
        susvibes_commit=susvibes_commit,
        smoke_size=smoke_size,
        canary_size=canary_size,
        batch_size=batch_size,
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite experiment manifest: {output_path}"
        ) from exc
    return payload


def load_experiment_cohort(
    manifest: str | Path,
    cohort: str,
    *,
    dataset: str | Path,
) -> tuple[list[str], dict[str, str]]:
    """Load instance IDs only after verifying manifest and dataset integrity."""

    manifest_path = Path(manifest)
    try:
        payload = json.loads(
            manifest_path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"invalid SusVibes experiment manifest: {manifest_path}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ValueError("SusVibes experiment manifest must be an object")
    if payload.get("schema_version") != SUSVIBES_EXPERIMENT_SCHEMA_VERSION:
        raise ValueError("unsupported SusVibes experiment manifest schema")
    expected_digest = str(payload.get("deterministic_digest") or "")
    if not expected_digest or expected_digest != _semantic_digest(payload):
        raise ValueError("SusVibes experiment manifest digest mismatch")

    dataset_record = payload.get("dataset")
    if not isinstance(dataset_record, Mapping):
        raise ValueError("experiment manifest dataset record is missing")
    dataset_path = Path(dataset)
    observed_dataset_sha = _file_sha256(
        dataset_path,
        allowed_root=dataset_path.resolve().parent,
    )
    expected_dataset_sha = str(dataset_record.get("sha256") or "")
    if observed_dataset_sha != expected_dataset_sha:
        raise ValueError(
            "experiment manifest dataset SHA-256 mismatch"
        )

    cohorts = payload.get("cohorts")
    if not isinstance(cohorts, Mapping) or cohort not in cohorts:
        available = (
            ", ".join(sorted(str(key) for key in cohorts))
            if isinstance(cohorts, Mapping)
            else ""
        )
        raise ValueError(
            f"unknown experiment cohort '{cohort}'; available: {available}"
        )
    selected = cohorts[cohort]
    if not isinstance(selected, Mapping):
        raise ValueError(f"invalid experiment cohort: {cohort}")
    raw_ids = selected.get("instance_ids")
    if not isinstance(raw_ids, list) or not raw_ids:
        raise ValueError(f"experiment cohort is empty: {cohort}")
    instance_ids = [str(value) for value in raw_ids]
    if len(instance_ids) != len(set(instance_ids)):
        raise ValueError(f"experiment cohort has duplicate IDs: {cohort}")
    if int(selected.get("case_count", -1)) != len(instance_ids):
        raise ValueError(f"experiment cohort count mismatch: {cohort}")
    return instance_ids, {
        "manifest_sha256": _file_sha256(
            manifest_path,
            allowed_root=manifest_path.resolve().parent,
        ),
        "manifest_digest": expected_digest,
        "dataset_sha256": observed_dataset_sha,
        "susvibes_commit": str(
            dataset_record.get("susvibes_commit") or ""
        ),
        "cohort": cohort,
    }


def _breadth_first_order(
    cases: list[dict[str, Any]],
    dataset_sha256: str,
) -> list[dict[str, Any]]:
    buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for case in cases:
        buckets[_primary_cwe(case)].append(case)
    for cwe, rows in buckets.items():
        rows.sort(
            key=lambda case: (
                _rank(dataset_sha256, "case", str(case["instance_id"])),
                str(case["instance_id"]),
            )
        )
    bucket_order = sorted(
        buckets,
        key=lambda cwe: (
            _rank(dataset_sha256, "stratum", cwe),
            cwe,
        ),
    )

    ordered: list[dict[str, Any]] = []
    used_projects: set[str] = set()
    while any(buckets.values()):
        for cwe in bucket_order:
            rows = buckets[cwe]
            if not rows:
                continue
            offset = next(
                (
                    index
                    for index, case in enumerate(rows)
                    if case["project"] not in used_projects
                ),
                0,
            )
            selected = rows.pop(offset)
            ordered.append(selected)
            used_projects.add(str(selected["project"]))
    return ordered


def _cohort_payload(
    cases: list[dict[str, Any]],
    *,
    purpose: str,
) -> dict[str, Any]:
    primary = {_primary_cwe(case) for case in cases}
    all_cwes = {
        cwe
        for case in cases
        for cwe in case["cwe_ids"]
    }
    return {
        "purpose": purpose,
        "case_count": len(cases),
        "instance_ids": [
            str(case["instance_id"])
            for case in cases
        ],
        "coverage": {
            "project_count": len({
                str(case["project"])
                for case in cases
            }),
            "primary_cwe_strata_count": len(primary),
            "all_cwe_count": len(all_cwes),
        },
    }


def _primary_cwe(case: Mapping[str, Any]) -> str:
    values = sorted(str(value) for value in case.get("cwe_ids", ()))
    return values[0] if values else "unknown"


def _rank(seed: str, namespace: str, value: str) -> str:
    return hashlib.sha256(
        f"{seed}\0{namespace}\0{value}".encode("utf-8")
    ).hexdigest()


def _chunks(
    values: list[dict[str, Any]],
    size: int,
) -> list[list[dict[str, Any]]]:
    return [
        values[index:index + size]
        for index in range(0, len(values), size)
    ]


def _file_sha256(path: Path, *, allowed_root: Path) -> str:
    candidate = path.resolve()
    root = allowed_root.resolve()
    try:
        common_path = os.path.commonpath((candidate, root))
    except ValueError as exc:
        raise ValueError(
            f"SusVibes artifact crosses a storage boundary: {path}"
        ) from exc
    if Path(common_path) != root:
        raise ValueError(
            f"SusVibes artifact escapes its allowed root: {path}"
        )
    if not candidate.is_file():
        raise ValueError(f"SusVibes artifact does not exist: {path}")
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


__all__ = [
    "SUSVIBES_EXPERIMENT_ALGORITHM",
    "SUSVIBES_EXPERIMENT_SCHEMA_VERSION",
    "build_susvibes_experiment_manifest",
    "load_experiment_cohort",
    "write_susvibes_experiment_manifest",
]
