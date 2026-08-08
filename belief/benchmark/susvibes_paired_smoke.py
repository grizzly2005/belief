"""Create-only preregistration for a paired SusVibes agent smoke."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from .susvibes_experiment import load_experiment_cohort


SUSVIBES_PAIRED_SMOKE_SCHEMA_VERSION = (
    "belief.susvibes_paired_agent_preregistration.v1"
)


def build_susvibes_paired_smoke_preregistration(
    *,
    susvibes_root: str | Path,
    dataset: str | Path,
    experiment_manifest: str | Path,
    belief_root: str | Path,
    runner_path: str | Path,
    baseline_results_dir: str | Path,
    belief_results_dir: str | Path,
    baseline_preflight_report: str | Path,
    belief_preflight_report: str | Path,
    model: str,
    claude_version: str,
    start_index: int = 0,
    num_instances: int = 3,
) -> dict[str, Any]:
    """Freeze a same-task no-feedback/BELIEF development comparison."""

    source_root = Path(susvibes_root).resolve()
    dataset_path = Path(dataset).resolve()
    manifest_path = Path(experiment_manifest).resolve()
    project_root = Path(belief_root).resolve()
    runner = Path(runner_path).resolve()
    baseline_results = Path(baseline_results_dir).resolve()
    feedback_results = Path(belief_results_dir).resolve()
    baseline_preflight = Path(baseline_preflight_report).resolve()
    feedback_preflight = Path(belief_preflight_report).resolve()

    if not _is_relative_to(dataset_path, source_root):
        raise ValueError("SusVibes dataset must be inside the pinned checkout")
    if not _is_relative_to(runner, project_root) or not runner.is_file():
        raise ValueError("paired smoke runner must be inside BELIEF")
    source_commit = _clean_git_commit(source_root, "SusVibes")
    project_commit = _clean_git_commit(project_root, "BELIEF")
    instance_ids, selection = load_experiment_cohort(
        manifest_path,
        "smoke",
        dataset=dataset_path,
    )
    if source_commit != selection["susvibes_commit"]:
        raise ValueError(
            "SusVibes checkout commit does not match experiment manifest"
        )
    if start_index < 0:
        raise ValueError("start_index must be non-negative")
    if num_instances <= 0:
        raise ValueError("num_instances must be positive")
    selected = instance_ids[start_index:start_index + num_instances]
    if len(selected) != num_instances:
        raise ValueError("paired smoke slice is incomplete")
    normalized_model = str(model or "").strip()
    normalized_version = str(claude_version or "").strip()
    if not normalized_model:
        raise ValueError("model must be an exact non-empty identifier")
    if not normalized_version:
        raise ValueError("claude_version must be non-empty")

    future_paths = (
        baseline_results,
        feedback_results,
        baseline_preflight,
        feedback_preflight,
    )
    if len(set(future_paths)) != len(future_paths):
        raise ValueError("paired smoke output paths must be distinct")
    for path in future_paths:
        if _is_relative_to(path, source_root) or _is_relative_to(
            path,
            project_root,
        ):
            raise ValueError(
                "paired smoke outputs must be outside source checkouts"
            )
    for path in (baseline_results, feedback_results):
        if path.exists() and (
            not path.is_dir() or any(path.iterdir())
        ):
            raise ValueError(
                f"paired smoke results directory is not fresh: {path}"
            )
    for path in (baseline_preflight, feedback_preflight):
        if path.exists():
            raise ValueError(
                f"paired smoke preflight output already exists: {path}"
            )

    task_digest = _instance_ids_digest(selected)
    payload: dict[str, Any] = {
        "schema_version": SUSVIBES_PAIRED_SMOKE_SCHEMA_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "preregistered_not_executed",
        "experiment": {
            "cohort": "smoke",
            "cohort_case_count": len(instance_ids),
            "start_index": start_index,
            "num_instances": num_instances,
            "selected_instance_ids_sha256": task_digest,
            "instance_ids_recorded": False,
            "dataset": str(dataset_path),
            "experiment_manifest": str(manifest_path),
            **selection,
        },
        "implementation": {
            "belief_root": str(project_root),
            "belief_commit": project_commit,
            "runner": str(runner),
            "runner_sha256": _file_sha256(
                runner,
                allowed_root=project_root,
            ),
            "model": normalized_model,
            "claude_code_version": normalized_version,
        },
        "arms": [
            {
                "arm": "A",
                "label": "claude_code_baseline",
                "feedback_mode": "none",
                "max_stop_blocks": 0,
                "prediction_model_name": (
                    f"claude-code-baseline/{normalized_model}"
                ),
                "results_dir": str(baseline_results),
                "preflight_report": str(baseline_preflight),
            },
            {
                "arm": "B",
                "label": "claude_code_with_belief",
                "feedback_mode": "belief",
                "max_stop_blocks": 1,
                "prediction_model_name": (
                    f"belief-claude-hook/{normalized_model}"
                ),
                "results_dir": str(feedback_results),
                "preflight_report": str(feedback_preflight),
            },
        ],
        "protocol": {
            "pass_at_k": 1,
            "same_ordered_tasks": True,
            "same_model": True,
            "same_claude_code_version": True,
            "same_agent_prompt": True,
            "same_anti_cheating_policy": True,
            "same_task_timeout_seconds": 3000,
            "parallel_workers": 1,
            "container_network_mode": "bridge",
            "container_cpu_limit": "4",
            "container_memory_limit": "8g",
            "container_pids_limit": "512",
            "container_capabilities_dropped": "ALL",
            "container_no_new_privileges": True,
            "arm_union_is_score": False,
            "official_funcpass_required": True,
            "official_secpass_required": True,
            "primary_effects": [
                "delta_funcpass",
                "delta_secpass",
                "delta_duration",
                "delta_cost",
                "delta_patch_bytes",
                "delta_regressions",
                "delta_timeouts",
            ],
            "third_arm_preregistered": False,
        },
        "boundaries": {
            "development_smoke_only": True,
            "static_holdout_consumed": False,
            "docker_started": False,
            "model_called": False,
            "official_tests_executed": False,
            "benchmark_result_claimed": False,
            "task_ids_disclosed": False,
            "preflight_reports_create_only": True,
            "run_outputs_create_only": True,
        },
        "comparability": {
            "result_before_official_evaluation": "NOT_TESTED",
            "static_metric_is_secpass": False,
            "three_task_smoke_is_leaderboard_comparable": False,
            "same_200_task_league_cohort_required_for_leaderboard_claim": True,
        },
    }
    payload["preregistration_digest"] = _semantic_digest(payload)
    return payload


def write_susvibes_paired_smoke_preregistration(
    output: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    """Create the preregistration without overwriting an existing artifact."""

    output_path = Path(output).resolve()
    payload = build_susvibes_paired_smoke_preregistration(**kwargs)
    source_roots = (
        Path(kwargs["susvibes_root"]).resolve(),
        Path(kwargs["belief_root"]).resolve(),
    )
    if any(_is_relative_to(output_path, root) for root in source_roots):
        raise ValueError(
            "paired smoke preregistration must be outside source checkouts"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite preregistration: {output_path}"
        ) from exc
    return payload


def _clean_git_commit(repository: Path, label: str) -> str:
    if not repository.is_dir() or not (repository / ".git").exists():
        raise ValueError(f"{label} checkout is not a Git repository")
    commit = _git(repository, "rev-parse", "HEAD").strip().lower()
    if not commit or len(commit) != 40:
        raise ValueError(f"{label} checkout commit is invalid")
    if _git(repository, "status", "--porcelain").strip():
        raise ValueError(f"{label} checkout must be clean")
    return commit


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if completed.returncode:
        raise ValueError(
            "Git inspection failed: "
            + completed.stderr.decode("utf-8", errors="replace").strip()
        )
    return completed.stdout.decode("utf-8", errors="replace")


def _file_sha256(path: Path, *, allowed_root: Path) -> str:
    candidate = path.resolve()
    root = allowed_root.resolve()
    if not _is_relative_to(candidate, root) or not candidate.is_file():
        raise ValueError(f"paired smoke input escapes allowed root: {path}")
    digest = hashlib.sha256()
    with candidate.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _instance_ids_digest(instance_ids: list[str]) -> str:
    encoded = json.dumps(
        instance_ids,
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key != "preregistration_digest"
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
    except ValueError:
        return False
    return True


__all__ = [
    "SUSVIBES_PAIRED_SMOKE_SCHEMA_VERSION",
    "build_susvibes_paired_smoke_preregistration",
    "write_susvibes_paired_smoke_preregistration",
]
