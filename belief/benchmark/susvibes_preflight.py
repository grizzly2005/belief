"""Read-only readiness checks for an official SusVibes agent run."""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .susvibes import load_susvibes_cases
from .susvibes_experiment import load_experiment_cohort


SUSVIBES_PREFLIGHT_SCHEMA_VERSION = "belief.susvibes_agent_preflight.v1"

DockerProbe = Callable[[], tuple[bool, str]]
DiskFreeProbe = Callable[[Path], int]

_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9_.-]+)?$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_FABLE_5_MODEL_ID = "claude-fable-5"
_FABLE_5_MODEL_SOURCE = (
    "https://platform.claude.com/docs/en/about-claude/models/overview"
)
_FABLE_5_MINIMUM_CLAUDE_CODE_VERSION = (2, 1, 170)
_FABLE_5_CLAUDE_CODE_SOURCE = (
    "https://github.com/anthropics/claude-code/releases/tag/v2.1.170"
)
_DEFAULT_MINIMUM_FREE_GIB = {
    "smoke": 20.0,
    "canary": 100.0,
    "holdout": 250.0,
    "full": 300.0,
}
_DEFAULT_MAX_REPORT_AGE_SECONDS = 15 * 60


def run_susvibes_agent_preflight(
    *,
    susvibes_root: str | Path,
    dataset: str | Path,
    experiment_manifest: str | Path,
    cohort: str,
    start_index: int = 0,
    num_instances: int = 1,
    results_dir: str | Path,
    model: str,
    claude_version: str = "2.1.218",
    minimum_free_gib: float | None = None,
    acknowledge_agent_network: bool = False,
    environment: Mapping[str, str] | None = None,
    docker_probe: DockerProbe | None = None,
    disk_free_probe: DiskFreeProbe | None = None,
    runner_path: str | Path | None = None,
) -> dict[str, Any]:
    """Inspect execution readiness without starting Docker or calling a model."""

    root = Path(susvibes_root).resolve()
    dataset_path = Path(dataset).resolve()
    manifest_path = Path(experiment_manifest).resolve()
    output_root = Path(results_dir).resolve()
    runner = Path(
        runner_path
        or Path(__file__).resolve().parents[2]
        / "scripts"
        / "run_susvibes_belief_claude.py"
    ).resolve()
    env = dict(os.environ if environment is None else environment)
    checks: list[dict[str, Any]] = []

    def add(
        check_id: str,
        passed: bool,
        *,
        required: bool,
        evidence: Mapping[str, Any],
        warning: bool = False,
    ) -> None:
        status = "passed" if passed else ("warning" if warning else "failed")
        checks.append({
            "id": check_id,
            "status": status,
            "required": required,
            "evidence": dict(evidence),
        })

    checkout_valid = (
        root.is_dir()
        and (root / ".git").exists()
        and (
            root / "evaluation_harness" / "claude_code"
        ).is_dir()
    )
    add(
        "pinned_susvibes_checkout",
        checkout_valid,
        required=True,
        evidence={"path": str(root)},
    )
    dataset_inside_checkout = _is_relative_to(dataset_path, root)
    add(
        "dataset_inside_pinned_checkout",
        dataset_inside_checkout,
        required=True,
        evidence={
            "dataset": str(dataset_path),
            "checkout": str(root),
        },
    )

    selected_ids: list[str] = []
    execution_ids: list[str] = []
    selection: dict[str, str] = {}
    selection_error = ""
    try:
        selected_ids, selection = load_experiment_cohort(
            manifest_path,
            cohort,
            dataset=dataset_path,
        )
        execution_ids = _execution_slice(
            selected_ids,
            start_index=start_index,
            num_instances=num_instances,
        )
    except ValueError as exc:
        selection_error = str(exc)
    add(
        "verified_experiment_selection",
        not selection_error,
        required=True,
        evidence=(
            {
                "cohort": cohort,
                "cohort_case_count": len(selected_ids),
                "execution_case_count": len(execution_ids),
                **selection,
            }
            if not selection_error
            else {"cohort": cohort, "error": selection_error}
        ),
    )

    cases_error = ""
    selected_cases: list[dict[str, Any]] = []
    try:
        cases = {
            str(case["instance_id"]): case
            for case in load_susvibes_cases(dataset_path)
        }
        missing_ids = [
            instance_id
            for instance_id in execution_ids
            if instance_id not in cases
        ]
        if missing_ids:
            raise ValueError(
                "selected IDs missing from dataset: "
                + ", ".join(missing_ids[:3])
            )
        selected_cases = [cases[value] for value in execution_ids]
        incomplete = [
            str(case["instance_id"])
            for case in selected_cases
            if not str(case.get("image_name") or "").strip()
            or not str(case.get("problem_statement") or "").strip()
        ]
        if incomplete:
            raise ValueError(
                "selected cases lack agent fields: "
                + ", ".join(incomplete[:3])
            )
    except ValueError as exc:
        cases_error = str(exc)
    add(
        "selected_agent_fields_available",
        not cases_error and bool(selected_cases),
        required=True,
        evidence=(
            {
                "selected_case_count": len(selected_cases),
                "agent_visible_fields": [
                    "image_name",
                    "instance_id",
                    "problem_statement",
                ],
            }
            if not cases_error
            else {"error": cases_error}
        ),
    )

    head = ""
    clean = False
    git_error = ""
    if checkout_valid:
        try:
            head = _git(root, "rev-parse", "HEAD").strip()
            clean = not _git(root, "status", "--porcelain").strip()
        except ValueError as exc:
            git_error = str(exc)
    expected_commit = (
        selection.get("susvibes_commit", "")
        if not selection_error
        else _manifest_commit(manifest_path)
    )
    add(
        "susvibes_commit_matches_manifest",
        bool(head) and head == expected_commit,
        required=True,
        evidence={
            "observed_commit": head,
            "expected_commit": expected_commit,
            **({"error": git_error} if git_error else {}),
        },
    )
    add(
        "susvibes_checkout_clean",
        clean,
        required=True,
        evidence={"clean": clean},
    )

    results_fresh = (
        not output_root.exists()
        or (
            output_root.is_dir()
            and not any(output_root.iterdir())
        )
    )
    add(
        "isolated_results_directory",
        results_fresh,
        required=True,
        evidence={
            "path": str(output_root),
            "exists": output_root.exists(),
            "empty": (
                output_root.is_dir()
                and not any(output_root.iterdir())
                if output_root.exists()
                else True
            ),
        },
    )
    results_outside_checkout = not _is_relative_to(output_root, root)
    add(
        "results_outside_pinned_checkout",
        results_outside_checkout,
        required=True,
        evidence={
            "results_dir": str(output_root),
            "checkout": str(root),
        },
    )

    threshold = float(
        minimum_free_gib
        if minimum_free_gib is not None
        else _DEFAULT_MINIMUM_FREE_GIB.get(cohort, 300.0)
    )
    if not math.isfinite(threshold) or threshold <= 0:
        raise ValueError("minimum_free_gib must be positive")
    storage_anchor = _nearest_existing_parent(output_root)
    free_bytes = (
        (disk_free_probe or _disk_free_bytes)(storage_anchor)
    )
    free_gib = round(free_bytes / (1024 ** 3), 3)
    add(
        "workspace_storage",
        free_gib >= threshold,
        required=True,
        evidence={
            "path": str(storage_anchor),
            "free_gib": free_gib,
            "minimum_free_gib": threshold,
            "cohort": cohort,
        },
    )

    machine = platform.machine().lower()
    add(
        "x86_64_host",
        machine in {"amd64", "x86_64"},
        required=True,
        evidence={"machine": machine},
    )

    docker_ready, docker_evidence = (
        docker_probe or _probe_docker
    )()
    add(
        "docker_daemon_ready",
        docker_ready,
        required=True,
        evidence={
            "ready": docker_ready,
            "detail": docker_evidence,
            "auto_start_attempted": False,
        },
    )

    credentials = sorted(
        name
        for name in (
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
        )
        if str(env.get(name) or "").strip()
    )
    add(
        "container_agent_credentials",
        bool(credentials),
        required=True,
        evidence={
            "credential_variable_names": credentials,
            "credential_values_read_into_report": False,
            "host_subscription_session_reused": False,
        },
    )

    normalized_model = str(model or "").strip()
    normalized_claude_version = str(claude_version).strip()
    add(
        "exact_model_identifier",
        bool(_MODEL_RE.fullmatch(normalized_model)),
        required=True,
        evidence={
            "model": normalized_model,
        },
    )
    add(
        "provider_model_availability",
        False,
        required=False,
        warning=True,
        evidence={
            "model": normalized_model,
            "published_model_id_verified": (
                normalized_model == _FABLE_5_MODEL_ID
            ),
            "published_general_availability": (
                normalized_model == _FABLE_5_MODEL_ID
            ),
            "published_source": (
                _FABLE_5_MODEL_SOURCE
                if normalized_model == _FABLE_5_MODEL_ID
                else ""
            ),
            "live_credential_access_verified": False,
            "reason": (
                "official documentation can verify the published model ID, "
                "but the offline preflight does not call the provider with "
                "the container credential"
            ),
        },
    )
    add(
        "pinned_claude_code_version",
        bool(_VERSION_RE.fullmatch(normalized_claude_version)),
        required=True,
        evidence={"claude_code_version": normalized_claude_version},
    )
    fable_cli_compatible = (
        normalized_model != _FABLE_5_MODEL_ID
        or _version_core(normalized_claude_version)
        >= _FABLE_5_MINIMUM_CLAUDE_CODE_VERSION
    )
    add(
        "fable_5_claude_code_compatibility",
        fable_cli_compatible,
        required=True,
        evidence={
            "model": normalized_model,
            "claude_code_version": normalized_claude_version,
            "minimum_version": "2.1.170",
            "source": _FABLE_5_CLAUDE_CODE_SOURCE,
        },
    )

    add(
        "explicit_agent_network_acknowledgement",
        bool(acknowledge_agent_network),
        required=True,
        evidence={
            "acknowledged": bool(acknowledge_agent_network),
            "required_for": [
                "Docker image pull",
                "Claude Code npm pin",
                "model API",
            ],
        },
    )

    add(
        "agent_runner_present",
        runner.is_file(),
        required=True,
        evidence={
            "path": str(runner),
            "sha256": (
                _file_sha256(runner, allowed_root=runner.parent)
                if runner.is_file()
                else ""
            ),
        },
    )

    required_failures = [
        item["id"]
        for item in checks
        if item["required"] and item["status"] != "passed"
    ]
    report: dict[str, Any] = {
        "schema_version": SUSVIBES_PREFLIGHT_SCHEMA_VERSION,
        "mode": "read_only_susvibes_agent_preflight",
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "ready_for_execution": not required_failures,
        "status": "ready" if not required_failures else "not_ready",
        "exit_code": 0 if not required_failures else 1,
        "required_failure_count": len(required_failures),
        "required_failures": required_failures,
        "checks": checks,
        "binding": {
            "susvibes_root": str(root),
            "susvibes_commit": head,
            "dataset": str(dataset_path),
            "dataset_sha256": selection.get("dataset_sha256", ""),
            "experiment_manifest": str(manifest_path),
            "experiment_manifest_sha256": selection.get(
                "manifest_sha256",
                "",
            ),
            "experiment_manifest_digest": selection.get(
                "manifest_digest",
                "",
            ),
            "cohort": cohort,
            "cohort_case_count": len(selected_ids),
            "start_index": int(start_index),
            "requested_num_instances": int(num_instances),
            "selected_case_count": len(execution_ids),
            "selected_instance_ids_sha256": _instance_ids_digest(
                execution_ids
            ),
            "results_dir": str(output_root),
            "minimum_free_gib": threshold,
            "free_gib_at_preflight": free_gib,
            "model": normalized_model,
            "claude_code_version": normalized_claude_version,
            "runner": str(runner),
            "runner_sha256": (
                _file_sha256(runner, allowed_root=runner.parent)
                if runner.is_file()
                else ""
            ),
        },
        "boundaries": {
            "docker_started": False,
            "model_called": False,
            "network_called": False,
            "credentials_reported": False,
            "benchmark_filesystem_mutation": False,
            "report_artifact_creation_only": True,
        },
        "comparability": {
            "security_tests_executed": False,
            "susvibes_secpass_measured": False,
            "preflight_is_benchmark_result": False,
        },
    }
    report["report_digest"] = _report_digest(report)
    return report


def write_susvibes_agent_preflight(
    output: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    payload = run_susvibes_agent_preflight(**kwargs)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite preflight report: {output_path}"
        ) from exc
    return payload


def load_ready_susvibes_agent_preflight(
    preflight_report: str | Path,
    *,
    susvibes_root: str | Path,
    dataset: str | Path,
    experiment_manifest: str | Path,
    cohort: str,
    start_index: int = 0,
    num_instances: int = 1,
    results_dir: str | Path,
    model: str,
    claude_version: str,
    runner_path: str | Path,
    max_report_age_seconds: int = _DEFAULT_MAX_REPORT_AGE_SECONDS,
) -> dict[str, Any]:
    """Verify a ready report and bind it to the current execution inputs."""

    report_path = Path(preflight_report).resolve()
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(
            f"invalid SusVibes preflight report: {report_path}: {exc}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise ValueError("SusVibes preflight report must be an object")
    if payload.get("schema_version") != SUSVIBES_PREFLIGHT_SCHEMA_VERSION:
        raise ValueError("unsupported SusVibes preflight report schema")
    expected_digest = str(payload.get("report_digest") or "")
    if not expected_digest or expected_digest != _report_digest(payload):
        raise ValueError("SusVibes preflight report digest mismatch")
    if payload.get("ready_for_execution") is not True:
        failures = payload.get("required_failures")
        detail = (
            ", ".join(str(value) for value in failures)
            if isinstance(failures, list)
            else "unknown"
        )
        raise ValueError(
            f"SusVibes preflight is not ready: {detail}"
        )
    if payload.get("required_failures") != []:
        raise ValueError(
            "ready SusVibes preflight contains required failures"
        )
    if (
        payload.get("status") != "ready"
        or payload.get("exit_code") != 0
        or payload.get("required_failure_count") != 0
    ):
        raise ValueError("SusVibes preflight readiness fields disagree")
    checks = payload.get("checks")
    if not isinstance(checks, list) or any(
        not isinstance(check, Mapping)
        or (
            check.get("required") is True
            and check.get("status") != "passed"
        )
        for check in checks
    ):
        raise ValueError("SusVibes preflight required checks disagree")
    if max_report_age_seconds <= 0:
        raise ValueError("max_report_age_seconds must be positive")
    try:
        created_at = datetime.fromisoformat(
            str(payload.get("created_at_utc") or "")
        )
        if created_at.tzinfo is None:
            raise ValueError
    except ValueError as exc:
        raise ValueError(
            "SusVibes preflight creation time is invalid"
        ) from exc
    age_seconds = (
        datetime.now(timezone.utc) - created_at.astimezone(timezone.utc)
    ).total_seconds()
    if age_seconds < -60 or age_seconds > max_report_age_seconds:
        raise ValueError(
            "SusVibes preflight report is stale or future-dated"
        )

    root = Path(susvibes_root).resolve()
    dataset_path = Path(dataset).resolve()
    manifest_path = Path(experiment_manifest).resolve()
    output_root = Path(results_dir).resolve()
    runner = Path(runner_path).resolve()
    if not _is_relative_to(dataset_path, root):
        raise ValueError(
            "SusVibes dataset is outside the pinned checkout"
        )
    if _is_relative_to(output_root, root):
        raise ValueError(
            "SusVibes results directory is inside the pinned checkout"
        )
    selected_ids, selection = load_experiment_cohort(
        manifest_path,
        cohort,
        dataset=dataset_path,
    )
    execution_ids = _execution_slice(
        selected_ids,
        start_index=start_index,
        num_instances=num_instances,
    )
    current_head = _git(root, "rev-parse", "HEAD").strip()
    if _git(root, "status", "--porcelain").strip():
        raise ValueError(
            "SusVibes checkout changed after preflight: worktree is dirty"
        )
    if output_root.exists() and (
        not output_root.is_dir() or any(output_root.iterdir())
    ):
        raise ValueError(
            "SusVibes results directory changed after preflight"
        )

    expected_binding = {
        "susvibes_root": str(root),
        "susvibes_commit": current_head,
        "dataset": str(dataset_path),
        "dataset_sha256": selection["dataset_sha256"],
        "experiment_manifest": str(manifest_path),
        "experiment_manifest_sha256": selection["manifest_sha256"],
        "experiment_manifest_digest": selection["manifest_digest"],
        "cohort": cohort,
        "cohort_case_count": len(selected_ids),
        "start_index": int(start_index),
        "requested_num_instances": int(num_instances),
        "selected_case_count": len(execution_ids),
        "selected_instance_ids_sha256": _instance_ids_digest(execution_ids),
        "results_dir": str(output_root),
        "model": str(model).strip(),
        "claude_code_version": str(claude_version),
        "runner": str(runner),
        "runner_sha256": _file_sha256(
            runner,
            allowed_root=runner.parent,
        ),
    }
    binding = payload.get("binding")
    if not isinstance(binding, Mapping):
        raise ValueError("SusVibes preflight binding is missing")
    try:
        minimum_free_gib = float(binding.get("minimum_free_gib"))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "SusVibes preflight storage threshold is invalid"
        ) from exc
    if not math.isfinite(minimum_free_gib) or minimum_free_gib <= 0:
        raise ValueError(
            "SusVibes preflight storage threshold is invalid"
        )
    current_free_gib = _disk_free_bytes(
        _nearest_existing_parent(output_root)
    ) / (1024 ** 3)
    if current_free_gib < minimum_free_gib:
        raise ValueError(
            "SusVibes storage readiness changed after preflight"
        )
    mismatches = [
        key
        for key, value in expected_binding.items()
        if binding.get(key) != value
    ]
    if mismatches:
        raise ValueError(
            "SusVibes preflight does not match current execution inputs: "
            + ", ".join(mismatches)
        )

    return {
        "report_sha256": _file_sha256(
            report_path,
            allowed_root=report_path.parent,
        ),
        "report_digest": expected_digest,
        "created_at_utc": str(payload.get("created_at_utc") or ""),
        "cohort": cohort,
        "cohort_case_count": len(selected_ids),
        "start_index": int(start_index),
        "num_instances": int(num_instances),
        "selected_instance_ids_sha256": _instance_ids_digest(execution_ids),
    }


def _probe_docker() -> tuple[bool, str]:
    executable = shutil.which("docker")
    if not executable:
        return False, "docker CLI not found"
    try:
        completed = subprocess.run(
            [
                executable,
                "info",
                "--format",
                "{{.ServerVersion}}|{{.Architecture}}",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if completed.returncode:
        error = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()
        return False, error[:500] or f"exit {completed.returncode}"
    return True, completed.stdout.decode(
        "utf-8",
        errors="replace",
    ).strip()


def _disk_free_bytes(path: Path) -> int:
    return int(shutil.disk_usage(path).free)


def _nearest_existing_parent(path: Path) -> Path:
    candidate = path.resolve()
    root = Path(candidate.anchor).resolve()
    try:
        common_path = os.path.commonpath((candidate, root))
    except ValueError as exc:
        raise ValueError(
            f"results path crosses a storage boundary: {path}"
        ) from exc
    if Path(common_path) != root:
        raise ValueError(
            f"results path escapes its storage boundary: {path}"
        )
    while not candidate.exists():
        parent = candidate.parent
        if parent == candidate:
            raise ValueError(
                f"cannot resolve storage parent for results path: {path}"
            )
        candidate = parent
    return candidate


def _is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def _version_core(value: str) -> tuple[int, int, int]:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        return (0, 0, 0)
    return (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3)),
    )


def _manifest_commit(path: Path) -> str:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    if not isinstance(payload, Mapping):
        return ""
    dataset = payload.get("dataset")
    if not isinstance(dataset, Mapping):
        return ""
    return str(dataset.get("susvibes_commit") or "").strip().lower()


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update({
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=15,
    )
    if completed.returncode:
        error = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()
        raise ValueError(
            f"local Git preflight failed: {error or completed.returncode}"
        )
    return completed.stdout.decode("utf-8", errors="replace")


def _file_sha256(path: Path, *, allowed_root: Path) -> str:
    candidate = path.resolve()
    root = allowed_root.resolve()
    try:
        common_path = os.path.commonpath((candidate, root))
    except ValueError as exc:
        raise ValueError(
            f"preflight artifact crosses a storage boundary: {path}"
        ) from exc
    if Path(common_path) != root:
        raise ValueError(
            f"preflight artifact escapes its allowed root: {path}"
        )
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


def _execution_slice(
    instance_ids: list[str],
    *,
    start_index: int,
    num_instances: int,
) -> list[str]:
    if start_index < 0:
        raise ValueError("start_index must be non-negative")
    if num_instances <= 0:
        raise ValueError("num_instances must be positive")
    selected = instance_ids[start_index:start_index + num_instances]
    if not selected:
        raise ValueError("preflight execution selection is empty")
    return selected


def _report_digest(payload: Mapping[str, Any]) -> str:
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
    "SUSVIBES_PREFLIGHT_SCHEMA_VERSION",
    "load_ready_susvibes_agent_preflight",
    "run_susvibes_agent_preflight",
    "write_susvibes_agent_preflight",
]
