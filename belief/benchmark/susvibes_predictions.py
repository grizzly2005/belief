"""Merge validated BELIEF SusVibes batch runs into official predictions."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from .susvibes_experiment import load_experiment_cohort


SUSVIBES_PREDICTION_MERGE_SCHEMA_VERSION = (
    "belief.susvibes_prediction_merge.v1"
)

_PLAN_SCHEMA = "belief.susvibes_agent_plan.v1"
_RUN_SCHEMA = "belief.susvibes_agent_run.v1"
_RESULT_SCHEMA = "belief.susvibes_agent_result.v1"
_PREDICTION_FIELDS = frozenset({
    "instance_id",
    "model_name_or_path",
    "model_patch",
})
_INSTANCE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_PREDICTIONS_BYTES = 512 * 1024 * 1024
_MAX_PATCH_BYTES = 10 * 1024 * 1024


def write_merged_susvibes_predictions(
    output: str | Path,
    provenance_output: str | Path,
    *,
    experiment_manifest: str | Path,
    dataset: str | Path,
    cohort: str,
    run_dirs: Sequence[str | Path],
    require_complete: bool = True,
) -> dict[str, Any]:
    """Validate batch artifacts and create ordered prediction/provenance files."""

    if not run_dirs:
        raise ValueError("at least one BELIEF run directory is required")
    manifest_path = Path(experiment_manifest).resolve()
    dataset_path = Path(dataset).resolve()
    selected_ids, selection = load_experiment_cohort(
        manifest_path,
        cohort,
        dataset=dataset_path,
    )
    selected_set = frozenset(selected_ids)
    if any(not _INSTANCE_ID_RE.fullmatch(value) for value in selected_ids):
        raise ValueError("experiment cohort contains unsafe instance IDs")

    normalized_dirs = [Path(value).resolve() for value in run_dirs]
    if len(normalized_dirs) != len(set(normalized_dirs)):
        raise ValueError("BELIEF run directories must be unique")
    output_path = Path(output).resolve()
    provenance_path = Path(provenance_output).resolve()
    if output_path == provenance_path:
        raise ValueError("prediction and provenance outputs must differ")
    for run_dir in normalized_dirs:
        if _is_relative_to(output_path, run_dir) or _is_relative_to(
            provenance_path,
            run_dir,
        ):
            raise ValueError(
                "merged outputs must be outside input run directories"
            )
    for candidate in (output_path, provenance_path):
        if candidate.exists():
            raise ValueError(f"refusing to overwrite merge output: {candidate}")

    batch_payloads = [
        _load_batch_run(
            run_dir,
            selection=selection,
            selected_ids=selected_ids,
            selected_set=selected_set,
        )
        for run_dir in normalized_dirs
    ]
    consistency_fields = (
        "model",
        "model_name_or_path",
        "claude_code_version",
        "max_stop_blocks",
    )
    baseline = batch_payloads[0]
    for batch in batch_payloads[1:]:
        mismatches = [
            field
            for field in consistency_fields
            if batch[field] != baseline[field]
        ]
        if mismatches:
            raise ValueError(
                "BELIEF batches use inconsistent execution settings: "
                + ", ".join(mismatches)
            )

    by_id: dict[str, dict[str, str]] = {}
    source_by_id: dict[str, str] = {}
    for batch in batch_payloads:
        for record in batch["predictions"]:
            instance_id = record["instance_id"]
            if instance_id in by_id:
                raise ValueError(
                    f"duplicate prediction across batches: {instance_id}"
                )
            by_id[instance_id] = record
            source_by_id[instance_id] = batch["run_dir"]
    missing = [
        instance_id
        for instance_id in selected_ids
        if instance_id not in by_id
    ]
    if require_complete and missing:
        raise ValueError(
            "merged predictions do not cover the complete cohort: "
            f"{len(missing)} missing"
        )
    ordered_records = [
        by_id[instance_id]
        for instance_id in selected_ids
        if instance_id in by_id
    ]
    encoded_predictions = "".join(
        json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n"
        for record in ordered_records
    ).encode("utf-8")
    predictions_sha256 = hashlib.sha256(encoded_predictions).hexdigest()
    suspected = sum(
        batch["policy_violation_suspected_count"]
        for batch in batch_payloads
    )
    failed_agents = sum(
        batch["task_count"] - batch["successful_agent_runs"]
        for batch in batch_payloads
    )
    payload: dict[str, Any] = {
        "schema_version": SUSVIBES_PREDICTION_MERGE_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "mode": "validated_belief_susvibes_batch_merge",
        "experiment": {
            "manifest": str(manifest_path),
            "dataset": str(dataset_path),
            **selection,
            "cohort": cohort,
            "cohort_case_count": len(selected_ids),
        },
        "execution": {
            field: baseline[field]
            for field in consistency_fields
        },
        "coverage": {
            "required_complete": bool(require_complete),
            "observed_case_count": len(ordered_records),
            "missing_case_count": len(missing),
            "missing_instance_ids": missing,
            "duplicate_case_count": 0,
            "complete": not missing,
        },
        "quality_flags": {
            "failed_agent_run_count": failed_agents,
            "policy_violation_suspected_count": suspected,
            "anti_cheating_adjudication_required": suspected > 0,
            "suspected_cases_removed": False,
        },
        "inputs": [
            {
                key: value
                for key, value in batch.items()
                if key not in {"predictions"}
            }
            for batch in batch_payloads
        ],
        "output": {
            "predictions": str(output_path),
            "provenance": str(provenance_path),
            "predictions_sha256": predictions_sha256,
            "prediction_count": len(ordered_records),
            "ordered_by_frozen_cohort": True,
            "source_run_by_instance": {
                instance_id: source_by_id[instance_id]
                for instance_id in selected_ids
                if instance_id in source_by_id
            },
        },
        "boundaries": {
            "benchmark_oracle_forwarded": False,
            "reference_patch_forwarded": False,
            "hidden_tests_forwarded": False,
            "incomplete_runs_silently_dropped": False,
            "suspected_policy_cases_silently_dropped": False,
            "official_security_tests_executed_by_merge": False,
        },
    }
    payload["report_digest"] = _semantic_digest(payload)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    provenance_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("xb") as handle:
            handle.write(encoded_predictions)
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite merge output: {output_path}"
        ) from exc
    try:
        with provenance_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite merge output: {provenance_path}"
        ) from exc
    return payload


def _load_batch_run(
    run_dir: Path,
    *,
    selection: Mapping[str, str],
    selected_ids: list[str],
    selected_set: frozenset[str],
) -> dict[str, Any]:
    if not run_dir.is_dir():
        raise ValueError(f"BELIEF run directory does not exist: {run_dir}")
    plan_path = run_dir / "plan.json"
    summary_path = run_dir / "summary.json"
    predictions_path = run_dir / "predictions.jsonl"
    plan = _read_json_object(
        plan_path,
        allowed_root=run_dir,
        artifact_name="BELIEF run plan",
    )
    summary = _read_json_object(
        summary_path,
        allowed_root=run_dir,
        artifact_name="BELIEF run summary",
    )
    if plan.get("schema_version") != _PLAN_SCHEMA:
        raise ValueError(f"unsupported BELIEF plan schema: {run_dir}")
    if summary.get("schema_version") != _RUN_SCHEMA:
        raise ValueError(f"unsupported BELIEF run summary schema: {run_dir}")
    if Path(str(plan.get("results_dir") or "")).resolve() != run_dir:
        raise ValueError(f"BELIEF plan results directory mismatch: {run_dir}")
    if plan.get("dataset_sha256") != selection["dataset_sha256"]:
        raise ValueError(f"BELIEF plan dataset hash mismatch: {run_dir}")
    if plan.get("susvibes_commit") != selection["susvibes_commit"]:
        raise ValueError(f"BELIEF plan commit mismatch: {run_dir}")

    plan_selection = plan.get("selection")
    if not isinstance(plan_selection, Mapping):
        raise ValueError(f"BELIEF plan selection is missing: {run_dir}")
    if set(plan_selection) != set(selection):
        raise ValueError(
            f"BELIEF plan selection fields are invalid: {run_dir}"
        )
    selection_mismatches = [
        key
        for key, value in selection.items()
        if plan_selection.get(key) != value
    ]
    if selection_mismatches:
        raise ValueError(
            "BELIEF plan does not match frozen experiment: "
            + ", ".join(selection_mismatches)
        )
    preflight = plan.get("preflight")
    if not isinstance(preflight, Mapping) or preflight.get(
        "status"
    ) != "verified_ready":
        raise ValueError(
            f"BELIEF batch lacks a verified ready preflight: {run_dir}"
        )
    for key in ("report_sha256", "report_digest"):
        if not _SHA256_RE.fullmatch(str(preflight.get(key) or "")):
            raise ValueError(
                f"BELIEF batch preflight {key} is invalid: {run_dir}"
            )
    if preflight.get("cohort") != selection["cohort"]:
        raise ValueError(f"BELIEF batch preflight cohort mismatch: {run_dir}")
    if _integer(preflight, "cohort_case_count") != len(selected_ids):
        raise ValueError(
            f"BELIEF batch preflight cohort count mismatch: {run_dir}"
        )
    boundaries = plan.get("boundaries")
    required_boundaries = {
        "benchmark_oracle_forwarded": False,
        "reference_patch_forwarded": False,
        "hidden_tests_forwarded": False,
        "workspace_git_history_removed": True,
        "git_history_lookup_blocked": True,
        "web_tools_blocked": True,
    }
    if not isinstance(boundaries, Mapping) or any(
        boundaries.get(key) is not value
        for key, value in required_boundaries.items()
    ):
        raise ValueError(
            f"BELIEF plan trust boundaries are invalid: {run_dir}"
        )

    raw_tasks = plan.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ValueError(f"BELIEF plan tasks are missing: {run_dir}")
    task_ids = []
    for task in raw_tasks:
        if not isinstance(task, Mapping):
            raise ValueError(f"BELIEF plan task is invalid: {run_dir}")
        if set(task) != {
            "agent_visible_fields",
            "image_name",
            "instance_id",
            "problem_statement_sha256",
        }:
            raise ValueError(
                f"BELIEF plan task fields are invalid: {run_dir}"
            )
        instance_id = str(task.get("instance_id") or "")
        if (
            not _INSTANCE_ID_RE.fullmatch(instance_id)
            or instance_id not in selected_set
        ):
            raise ValueError(
                f"BELIEF plan task is outside the cohort: {instance_id}"
            )
        if task.get("agent_visible_fields") != [
            "image_name",
            "instance_id",
            "problem_statement",
        ]:
            raise ValueError(
                f"BELIEF plan exposes unexpected agent fields: {instance_id}"
            )
        task_ids.append(instance_id)
    if len(task_ids) != len(set(task_ids)):
        raise ValueError(f"BELIEF plan contains duplicate tasks: {run_dir}")
    if _integer(plan, "task_count") != len(task_ids):
        raise ValueError(f"BELIEF plan task count mismatch: {run_dir}")
    preflight_start = _integer(preflight, "start_index")
    preflight_count = _integer(preflight, "num_instances")
    if preflight_start < 0 or preflight_count <= 0:
        raise ValueError(f"BELIEF preflight slice is invalid: {run_dir}")
    if preflight_count != len(task_ids):
        raise ValueError(f"BELIEF preflight task count mismatch: {run_dir}")
    if selected_ids[
        preflight_start:preflight_start + preflight_count
    ] != task_ids:
        raise ValueError(f"BELIEF preflight task slice mismatch: {run_dir}")
    if preflight.get("selected_instance_ids_sha256") != (
        _instance_ids_digest(task_ids)
    ):
        raise ValueError(f"BELIEF preflight task digest mismatch: {run_dir}")

    records = _read_prediction_jsonl(
        predictions_path,
        allowed_root=run_dir,
    )
    prediction_ids = [record["instance_id"] for record in records]
    if prediction_ids != task_ids:
        raise ValueError(
            f"BELIEF predictions do not match plan order: {run_dir}"
        )
    if _integer(summary, "task_count") != len(task_ids):
        raise ValueError(f"BELIEF summary task count mismatch: {run_dir}")
    successful = _integer(summary, "successful_agent_runs")
    suspected = _integer(summary, "policy_violation_suspected_count")
    if not 0 <= successful <= len(task_ids):
        raise ValueError(f"invalid successful agent count: {run_dir}")
    if not 0 <= suspected <= len(task_ids):
        raise ValueError(f"invalid suspected policy count: {run_dir}")
    if Path(str(summary.get("predictions") or "")).resolve() != (
        predictions_path.resolve()
    ):
        raise ValueError(f"BELIEF summary prediction path mismatch: {run_dir}")

    model = str(plan.get("model") or "")
    claude_version = str(plan.get("claude_code_version") or "")
    max_stop_blocks = _integer(plan, "max_stop_blocks")
    if not 0 <= max_stop_blocks <= 3:
        raise ValueError(f"BELIEF feedback budget is invalid: {run_dir}")
    expected_model_path = f"belief-claude-hook/{model}"
    if not model or any(
        record["model_name_or_path"] != expected_model_path
        for record in records
    ):
        raise ValueError(f"BELIEF prediction model mismatch: {run_dir}")
    observed_successful = 0
    observed_suspected = 0
    for task_id, record in zip(task_ids, records):
        result_path = _safe_child(run_dir, task_id) / "result.json"
        result = _read_json_object(
            result_path,
            allowed_root=run_dir,
            artifact_name="BELIEF task result",
        )
        if result.get("schema_version") != _RESULT_SCHEMA:
            raise ValueError(f"unsupported BELIEF task result: {task_id}")
        if result.get("instance_id") != task_id:
            raise ValueError(f"BELIEF task result ID mismatch: {task_id}")
        if result.get("model") != model:
            raise ValueError(f"BELIEF task result model mismatch: {task_id}")
        if result.get("claude_code_version") != claude_version:
            raise ValueError(
                f"BELIEF task result Claude version mismatch: {task_id}"
            )
        if result.get("prediction") != record:
            raise ValueError(
                f"BELIEF task result prediction mismatch: {task_id}"
            )
        patch_bytes = record["model_patch"].encode("utf-8")
        if result.get("model_patch_sha256") != hashlib.sha256(
            patch_bytes
        ).hexdigest():
            raise ValueError(f"BELIEF task patch hash mismatch: {task_id}")
        if result.get("model_patch_bytes") != len(patch_bytes):
            raise ValueError(f"BELIEF task patch size mismatch: {task_id}")
        if not isinstance(result.get("agent_success"), bool):
            raise ValueError(f"BELIEF task success flag is invalid: {task_id}")
        if not isinstance(
            result.get("policy_violation_suspected"),
            bool,
        ):
            raise ValueError(f"BELIEF task policy flag is invalid: {task_id}")
        observed_successful += int(result["agent_success"])
        observed_suspected += int(result["policy_violation_suspected"])
    if successful != observed_successful:
        raise ValueError(f"BELIEF successful agent count mismatch: {run_dir}")
    if suspected != observed_suspected:
        raise ValueError(f"BELIEF suspected policy count mismatch: {run_dir}")

    return {
        "run_dir": str(run_dir),
        "plan_sha256": _file_sha256(
            plan_path,
            allowed_root=run_dir,
        ),
        "summary_sha256": _file_sha256(
            summary_path,
            allowed_root=run_dir,
        ),
        "predictions_sha256": _file_sha256(
            predictions_path,
            allowed_root=run_dir,
        ),
        "task_count": len(task_ids),
        "successful_agent_runs": successful,
        "policy_violation_suspected_count": suspected,
        "instance_ids_sha256": _instance_ids_digest(task_ids),
        "model": model,
        "model_name_or_path": expected_model_path,
        "claude_code_version": claude_version,
        "max_stop_blocks": max_stop_blocks,
        "preflight_report_sha256": str(preflight["report_sha256"]),
        "preflight_report_digest": str(preflight["report_digest"]),
        "predictions": records,
    }


def _read_prediction_jsonl(
    path: Path,
    *,
    allowed_root: Path,
) -> list[dict[str, str]]:
    candidate = cleanup_path(path, allowed_root=allowed_root)
    if candidate.stat().st_size > _MAX_PREDICTIONS_BYTES:
        raise ValueError(f"BELIEF predictions file is too large: {path}")
    records = []
    for line_number, line in enumerate(
        candidate.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{path}:{line_number}: invalid prediction JSON"
            ) from exc
        if not isinstance(raw, Mapping) or set(raw) != _PREDICTION_FIELDS:
            raise ValueError(
                f"{path}:{line_number}: prediction fields are invalid"
            )
        if any(
            not isinstance(raw[key], str)
            for key in _PREDICTION_FIELDS
        ):
            raise ValueError(
                f"{path}:{line_number}: prediction values must be strings"
            )
        record = {
            key: str(raw[key])
            for key in sorted(_PREDICTION_FIELDS)
        }
        if not _INSTANCE_ID_RE.fullmatch(record["instance_id"]):
            raise ValueError(
                f"{path}:{line_number}: unsafe prediction instance ID"
            )
        if (
            not record["model_name_or_path"]
            or len(record["model_name_or_path"]) > 256
            or any(
                character in record["model_name_or_path"]
                for character in "\r\n\0"
            )
        ):
            raise ValueError(
                f"{path}:{line_number}: invalid prediction model"
            )
        if len(record["model_patch"].encode("utf-8")) > _MAX_PATCH_BYTES:
            raise ValueError(
                f"{path}:{line_number}: model patch is too large"
            )
        records.append(record)
    if not records:
        raise ValueError(f"BELIEF predictions file is empty: {path}")
    return records


def _read_json_object(
    path: Path,
    *,
    allowed_root: Path,
    artifact_name: str,
) -> Mapping[str, Any]:
    candidate = cleanup_path(path, allowed_root=allowed_root)
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {artifact_name}: {path}: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{artifact_name} must be a JSON object")
    return payload


def cleanup_path(path: Path, *, allowed_root: Path) -> Path:
    """Resolve an existing artifact while enforcing its run-directory root."""
    candidate = path.resolve()
    root = allowed_root.resolve()
    try:
        common_path = os.path.commonpath((candidate, root))
    except ValueError as exc:
        raise ValueError(
            f"BELIEF artifact crosses a storage boundary: {path}"
        ) from exc
    if Path(common_path) != root:
        raise ValueError(f"BELIEF artifact escapes run directory: {path}")
    if not candidate.is_file():
        raise ValueError(f"BELIEF artifact does not exist: {path}")
    return candidate


def _safe_child(root: Path, name: str) -> Path:
    candidate = (root / name).resolve()
    if not _is_relative_to(candidate, root.resolve()):
        raise ValueError(f"unsafe BELIEF task artifact path: {name}")
    return candidate


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _integer(payload: Mapping[str, Any], key: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"BELIEF artifact field must be an integer: {key}")
    return value


def _file_sha256(path: Path, *, allowed_root: Path) -> str:
    candidate = cleanup_path(path, allowed_root=allowed_root)
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _instance_ids_digest(instance_ids: list[str]) -> str:
    encoded = json.dumps(
        instance_ids,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


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
    "SUSVIBES_PREDICTION_MERGE_SCHEMA_VERSION",
    "write_merged_susvibes_predictions",
]
