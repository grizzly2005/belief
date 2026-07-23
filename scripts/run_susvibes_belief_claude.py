#!/usr/bin/env python3
"""Run Claude Code on SusVibes with bounded BELIEF security Stop hooks.

The default is a no-network dry run. Real execution additionally requires a
verified experiment cohort, a matching ready preflight report, and explicit
network acknowledgement; it never starts Docker itself. Only ``instance_id``,
``image_name``, and ``problem_statement`` cross the dataset/agent boundary.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable, Mapping


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from belief.claude_hooks import build_claude_hook_settings  # noqa: E402
from belief.benchmark.susvibes_experiment import (  # noqa: E402
    load_experiment_cohort,
)
from belief.benchmark.susvibes_preflight import (  # noqa: E402
    load_ready_susvibes_agent_preflight,
)


ALLOWED_AGENT_FIELDS = frozenset({
    "instance_id",
    "image_name",
    "problem_statement",
})
ALLOWED_TOOLS = (
    "Bash",
    "Edit",
    "Write",
    "Read",
    "Glob",
    "Grep",
    "LS",
    "NotebookEdit",
    "NotebookRead",
    "TodoRead",
    "TodoWrite",
)


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Run a bounded, anti-cheating Claude Code + BELIEF security "
            "feedback attempt on pinned SusVibes tasks."
        )
    )
    parser.add_argument(
        "--susvibes-root",
        required=True,
        help="Pinned SusVibes checkout containing evaluation_harness",
    )
    parser.add_argument(
        "--dataset",
        default="",
        help=(
            "Dataset JSONL (default: "
            "<susvibes-root>/datasets/default/susvibes_dataset.jsonl)"
        ),
    )
    parser.add_argument(
        "--results-dir",
        required=True,
        help="New isolated output directory",
    )
    parser.add_argument(
        "--experiment-manifest",
        default="",
        help=(
            "Verified evaluator-side experiment manifest used only to "
            "select instance IDs"
        ),
    )
    parser.add_argument(
        "--cohort",
        default="",
        help="Manifest cohort name, for example smoke, canary, or full",
    )
    parser.add_argument(
        "--preflight-report",
        default="",
        help=(
            "Matching ready report from preflight_susvibes_agent.py; "
            "required for real execution"
        ),
    )
    parser.add_argument(
        "--workspace-root",
        default="",
        help="Workspace parent (default: <results-dir>/workspaces)",
    )
    parser.add_argument(
        "--instance-id",
        action="append",
        default=[],
        help="Exact instance ID to run (repeatable)",
    )
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument(
        "--num-instances",
        type=int,
        default=1,
        help="Number of selected tasks; intentionally defaults to one",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Exact ANTHROPIC_MODEL identifier (required for execution)",
    )
    parser.add_argument(
        "--claude-version",
        default="2.1.83",
        help="Pinned @anthropic-ai/claude-code version",
    )
    parser.add_argument(
        "--max-stop-blocks",
        type=int,
        default=1,
        choices=[0, 1, 2, 3],
        help="Maximum BELIEF repair continuations in the same attempt",
    )
    parser.add_argument(
        "--keep-workspace",
        action="store_true",
        help="Preserve task workspaces after each run",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Actually pull images and invoke the agent",
    )
    parser.add_argument(
        "--allow-agent-network",
        action="store_true",
        help="Required acknowledgement for Docker pulls and model API access",
    )
    parser.add_argument(
        "--plan-output",
        default="",
        help="Optional JSON path for the sanitized dry-run plan",
    )
    return parser.parse_args()


def load_agent_tasks(
    dataset: Path,
    *,
    instance_ids: Iterable[str] = (),
    start_index: int = 0,
    num_instances: int = 1,
) -> list[dict[str, str]]:
    """Load only fields explicitly allowed to cross into the agent harness."""

    if start_index < 0:
        raise ValueError("start_index must be non-negative")
    if num_instances <= 0:
        raise ValueError("num_instances must be positive")
    wanted_order = [str(value) for value in instance_ids]
    if len(wanted_order) != len(set(wanted_order)):
        raise ValueError("duplicate requested instance IDs")
    wanted = set(wanted_order)
    tasks = []
    for line_number, line in enumerate(
        dataset.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{dataset}:{line_number}: invalid JSON: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise ValueError(
                f"{dataset}:{line_number}: record must be an object"
            )
        missing = sorted(ALLOWED_AGENT_FIELDS - set(raw))
        if missing:
            raise ValueError(
                f"{dataset}:{line_number}: missing fields: "
                + ", ".join(missing)
            )
        task = {
            key: str(raw[key])
            for key in sorted(ALLOWED_AGENT_FIELDS)
        }
        if wanted and task["instance_id"] not in wanted:
            continue
        tasks.append(task)
    if wanted:
        observed = {task["instance_id"] for task in tasks}
        missing_ids = sorted(wanted - observed)
        if missing_ids:
            raise ValueError(
                "unknown instance IDs: " + ", ".join(missing_ids)
            )
        tasks_by_id = {
            task["instance_id"]: task
            for task in tasks
        }
        tasks = [
            tasks_by_id[instance_id]
            for instance_id in wanted_order
        ]
    return tasks[start_index:start_index + num_instances]


def build_sanitized_plan(
    dataset: Path,
    tasks: list[dict[str, str]],
    *,
    susvibes_commit: str,
    model: str,
    claude_version: str,
    max_stop_blocks: int,
    results_dir: Path,
    workspace_root: Path,
    selection: Mapping[str, str] | None = None,
    preflight: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a provenance plan with hashes, not benchmark oracle fields."""

    return {
        "schema_version": "belief.susvibes_agent_plan.v1",
        "mode": "claude_code_with_belief_stop_hook",
        "dataset": dataset.name,
        "dataset_sha256": _sha256_file(dataset),
        "susvibes_commit": susvibes_commit,
        "model": model,
        "claude_code_version": claude_version,
        "max_stop_blocks": max_stop_blocks,
        "results_dir": str(results_dir),
        "workspace_root": str(workspace_root),
        "task_count": len(tasks),
        "selection": dict(selection or {
            "cohort": "direct_or_dataset_order",
        }),
        "preflight": dict(preflight or {
            "status": "not_required_for_dry_run",
        }),
        "tasks": [
            {
                "instance_id": task["instance_id"],
                "image_name": task["image_name"],
                "problem_statement_sha256": hashlib.sha256(
                    task["problem_statement"].encode("utf-8")
                ).hexdigest(),
                "agent_visible_fields": sorted(task),
            }
            for task in tasks
        ],
        "boundaries": {
            "benchmark_oracle_forwarded": False,
            "reference_patch_forwarded": False,
            "hidden_tests_forwarded": False,
            "workspace_git_history_removed": True,
            "git_history_lookup_blocked": True,
            "web_tools_blocked": True,
            "docker_auto_start": False,
            "parallel_workers": 1,
        },
    }


def _run_task(
    task: dict[str, str],
    *,
    susvibes_root: Path,
    results_dir: Path,
    workspace_root: Path,
    model: str,
    claude_version: str,
    max_stop_blocks: int,
    keep_workspace: bool,
) -> dict[str, Any]:
    DockerIntegration, user_prompt_template = _load_official_harness(
        susvibes_root
    )
    task_dir = results_dir / task["instance_id"]
    task_dir.mkdir(parents=True, exist_ok=False)
    started = time.perf_counter()
    integration = DockerIntegration(
        task["image_name"],
        container_work_dir="/project",
        workspace_root=str(workspace_root),
        keep_workspace=keep_workspace,
    )
    workspace: Path | None = None
    try:
        workspace = integration.setup_persistent_workspace()
        container = str(integration.workspace_container or "")
        if not container:
            raise ValueError("official harness did not create a container")
        sanitization = _sanitize_candidate_workspace(Path(workspace))

        harness_dir = (
            susvibes_root / "evaluation_harness" / "claude_code"
        )
        with _working_directory(harness_dir):
            setup = integration.setup_cli_env(
                setup_script_path="setup-env.sh"
            )
        if not setup.get("success"):
            raise ValueError(
                "official Claude setup failed: "
                + str(setup.get("stderr") or "")
            )
        upgrade = _docker_exec(
            container,
            (
                "source /root/.nvm/nvm.sh && "
                "npm install -g "
                f"@anthropic-ai/claude-code@{shlex.quote(claude_version)}"
            ),
            timeout=600,
        )
        if upgrade.returncode:
            raise ValueError(
                "Claude Code pin failed: "
                + upgrade.stderr.decode("utf-8", errors="replace")
            )

        _install_belief_hook_bundle(container)
        settings = build_claude_hook_settings(
            "/opt/belief/scripts/belief_claude_hook.py"
        )
        _copy_json_to_container(
            container,
            settings,
            "/opt/belief/claude-hook-settings.json",
        )
        _write_secret_agent_env(
            container,
            model=model,
            max_stop_blocks=max_stop_blocks,
        )

        prompt = user_prompt_template.format(
            local_work_dir="/project",
            problem_statement=task["problem_statement"],
        )
        command = (
            "source /root/.nvm/nvm.sh && "
            "source /root/.belief_agent_env && "
            + shlex.join([
                "claude",
                "--verbose",
                "--output-format",
                "stream-json",
                "-p",
                prompt,
                "--settings",
                "/opt/belief/claude-hook-settings.json",
                "--allowedTools",
                *ALLOWED_TOOLS,
            ])
        )
        agent = _docker_exec(
            container,
            command,
            timeout=3_000,
        )
        stdout_path = task_dir / "agent.stdout.jsonl"
        stderr_path = task_dir / "agent.stderr.txt"
        stdout_path.write_bytes(agent.stdout)
        stderr_path.write_bytes(agent.stderr)
        _copy_hook_reports(container, task_dir / "hook-reports")

        patch = _prediction_patch(Path(workspace))
        policy_suspected = _trajectory_policy_suspected(
            agent.stdout.decode("utf-8", errors="replace")
        )
        record = {
            "instance_id": task["instance_id"],
            "model_name_or_path": (
                f"belief-claude-hook/{model}"
            ),
            "model_patch": patch,
        }
        provenance = {
            "schema_version": "belief.susvibes_agent_result.v1",
            "instance_id": task["instance_id"],
            "image_name": task["image_name"],
            "model": model,
            "claude_code_version": claude_version,
            "agent_return_code": agent.returncode,
            "agent_success": agent.returncode == 0,
            "policy_violation_suspected": policy_suspected,
            "model_patch_sha256": hashlib.sha256(
                patch.encode("utf-8")
            ).hexdigest(),
            "model_patch_bytes": len(patch.encode("utf-8")),
            "workspace_sanitization": sanitization,
            "duration_seconds": round(
                time.perf_counter() - started,
                6,
            ),
            "prediction": record,
        }
        (task_dir / "result.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return provenance
    finally:
        integration.cleanup()


def _load_official_harness(
    susvibes_root: Path,
) -> tuple[type, str]:
    harness_root = susvibes_root / "evaluation_harness"
    claude_dir = harness_root / "claude_code"
    for path in (str(claude_dir), str(harness_root), str(susvibes_root)):
        if path not in sys.path:
            sys.path.insert(0, path)
    for name in ("run_docker", "prompts"):
        sys.modules.pop(name, None)
    module = importlib.import_module("run_docker")
    prompts = importlib.import_module("prompts")
    return module.DockerIntegration, str(prompts.USER_PROMPT_TEMPLATE)


def _install_belief_hook_bundle(container: str) -> None:
    created = _docker_exec(
        container,
        "mkdir -p /opt/belief/scripts",
        timeout=30,
    )
    if created.returncode:
        raise ValueError("failed to create BELIEF hook directory")
    _docker(
        "cp",
        str(REPOSITORY_ROOT / "belief"),
        f"{container}:/opt/belief/belief",
        timeout=120,
    )
    _docker(
        "cp",
        str(REPOSITORY_ROOT / "scripts" / "belief_claude_hook.py"),
        f"{container}:/opt/belief/scripts/belief_claude_hook.py",
        timeout=30,
    )


def _copy_json_to_container(
    container: str,
    payload: Any,
    destination: str,
) -> None:
    with tempfile.TemporaryDirectory(prefix="belief-hook-settings-") as temp:
        source = Path(temp) / "settings.json"
        source.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        _docker(
            "cp",
            str(source),
            f"{container}:{destination}",
            timeout=30,
        )


def _write_secret_agent_env(
    container: str,
    *,
    model: str,
    max_stop_blocks: int,
) -> None:
    keys = (
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
    )
    values = {
        key: os.environ.get(key, "")
        for key in keys
        if os.environ.get(key)
    }
    if not (
        values.get("ANTHROPIC_API_KEY")
        or values.get("ANTHROPIC_AUTH_TOKEN")
    ):
        raise ValueError(
            "ANTHROPIC_API_KEY or ANTHROPIC_AUTH_TOKEN is required"
        )
    values.update({
        "ANTHROPIC_MODEL": model,
        "PYTHONPATH": "/opt/belief",
        "BELIEF_STOP_HOOK_MAX_BLOCKS": str(max_stop_blocks),
        "BELIEF_HOOK_STATE_DIR": "/tmp/belief-hook-state",
        "BELIEF_HOOK_REPORT_DIR": "/tmp/belief-hook-reports",
    })
    content = "\n".join(
        f"export {key}={shlex.quote(value)}"
        for key, value in sorted(values.items())
    ) + "\n"
    completed = subprocess.run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "bash",
            "-c",
            "umask 077; cat > /root/.belief_agent_env",
        ],
        input=content.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if completed.returncode:
        raise ValueError(
            "failed to inject agent environment: "
            + completed.stderr.decode("utf-8", errors="replace")
        )


def _docker_exec(
    container: str,
    command: str,
    *,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "docker",
            "exec",
            "-w",
            "/project",
            container,
            "bash",
            "-lc",
            command,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )


def _docker(
    *arguments: str,
    timeout: int,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        ["docker", *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=timeout,
    )
    if completed.returncode:
        raise ValueError(
            f"docker {' '.join(arguments[:1])} failed: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return completed


def _copy_hook_reports(container: str, destination: Path) -> None:
    exists = _docker_exec(
        container,
        "test -d /tmp/belief-hook-reports",
        timeout=10,
    )
    if exists.returncode:
        return
    destination.mkdir(parents=True, exist_ok=False)
    _docker(
        "cp",
        f"{container}:/tmp/belief-hook-reports/.",
        str(destination),
        timeout=60,
    )


def _prediction_patch(repository: Path) -> str:
    tracked = _git(repository, "diff", "--binary", "HEAD", "--")
    raw_untracked = _git_bytes(
        repository,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
    )
    chunks = [tracked]
    for raw_path in raw_untracked.split(b"\0"):
        if not raw_path:
            continue
        relative = os.fsdecode(raw_path).replace("\\", "/")
        candidate = repository.joinpath(*Path(relative).parts)
        if not candidate.is_file() or candidate.is_symlink():
            continue
        completed = subprocess.run(
            [
                "git",
                "-C",
                str(repository),
                "diff",
                "--no-index",
                "--binary",
                "--",
                "/dev/null",
                relative,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=_offline_git_env(),
            timeout=30,
        )
        if completed.returncode not in {0, 1}:
            raise ValueError(
                "failed to diff untracked candidate file: "
                + completed.stderr.decode("utf-8", errors="replace")
            )
        chunks.append(
            completed.stdout.decode("utf-8", errors="replace")
        )
    return "".join(chunks)


def _sanitize_candidate_workspace(repository: Path) -> dict[str, Any]:
    """Replace all embedded Git metadata with one history-free baseline."""

    root = repository.resolve()
    if not root.is_dir():
        raise ValueError(f"candidate workspace is not a directory: {root}")

    git_markers = sorted(
        root.rglob(".git"),
        key=lambda item: len(item.parts),
        reverse=True,
    )
    removed = 0
    for marker in git_markers:
        try:
            marker.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"Git metadata escaped candidate workspace: {marker}"
            ) from exc
        if marker.is_symlink() or marker.is_file():
            marker.chmod(stat.S_IWRITE)
            marker.unlink()
        elif marker.is_dir():
            shutil.rmtree(marker, onerror=_remove_readonly_git_metadata)
        else:
            continue
        removed += 1

    _git(root, "init", "--quiet")
    _git(root, "add", "-A")
    _git(
        root,
        "-c",
        "user.name=BELIEF benchmark",
        "-c",
        "user.email=belief-benchmark@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "sanitized benchmark baseline",
    )
    head = _git(root, "rev-parse", "HEAD").strip()
    parents = _git(root, "rev-list", "--parents", "-n", "1", "HEAD").split()
    if len(parents) != 1:
        raise ValueError("sanitized candidate baseline unexpectedly has a parent")
    return {
        "mode": "fresh_history_free_git_baseline",
        "removed_git_metadata_count": removed,
        "baseline_commit": head,
        "baseline_parent_count": 0,
    }


def _remove_readonly_git_metadata(
    function: Any,
    path: str,
    _error: Any,
) -> None:
    Path(path).chmod(stat.S_IWRITE)
    function(path)


def _git(repository: Path, *arguments: str) -> str:
    return _git_bytes(repository, *arguments).decode(
        "utf-8",
        errors="replace",
    )


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=_offline_git_env(),
        timeout=30,
    )
    if completed.returncode:
        raise ValueError(
            f"git {' '.join(arguments[:2])} failed: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return completed.stdout


def _offline_git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
    })
    return env


def _trajectory_policy_suspected(transcript: str) -> bool:
    lowered = transcript.lower()
    indicators = (
        "git show ",
        "git log ",
        "git rev-list ",
        "git fetch ",
        "git clone ",
        "raw.githubusercontent.com",
        "webfetch",
        "websearch",
    )
    return any(value in lowered for value in indicators)


def _docker_available() -> bool:
    completed = subprocess.run(
        ["docker", "info", "--format", "{{.ServerVersion}}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    return completed.returncode == 0


def _git_head(repository: Path) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=15,
    )
    if completed.returncode:
        raise ValueError(
            "cannot resolve SusVibes commit: "
            + completed.stderr.decode("utf-8", errors="replace")
        )
    return completed.stdout.decode("ascii").strip()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@contextmanager
def _working_directory(path: Path):
    previous = Path.cwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _validate_new_output_directory(path: Path) -> None:
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"results path is not a directory: {path}")
        if any(path.iterdir()):
            raise ValueError(
                f"refusing non-empty results directory: {path}"
            )
    else:
        path.mkdir(parents=True)


def _write_new_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValueError(f"refusing to overwrite output file: {path}") from exc


def main() -> int:
    args = _arguments()
    try:
        susvibes_root = Path(args.susvibes_root).resolve()
        if not (
            susvibes_root / "evaluation_harness" / "claude_code"
        ).is_dir():
            raise ValueError(
                f"invalid SusVibes checkout: {susvibes_root}"
            )
        dataset = (
            Path(args.dataset).resolve()
            if args.dataset
            else (
                susvibes_root
                / "datasets"
                / "default"
                / "susvibes_dataset.jsonl"
            )
        )
        results_dir = Path(args.results_dir).resolve()
        workspace_root = (
            Path(args.workspace_root).resolve()
            if args.workspace_root
            else results_dir / "workspaces"
        )
        selection: dict[str, str] = {
            "cohort": "direct_or_dataset_order",
        }
        selected_ids = list(args.instance_id)
        if args.experiment_manifest:
            if args.instance_id:
                raise ValueError(
                    "--instance-id cannot be combined with "
                    "--experiment-manifest"
                )
            if not args.cohort:
                raise ValueError(
                    "--cohort is required with --experiment-manifest"
                )
            selected_ids, selection = load_experiment_cohort(
                Path(args.experiment_manifest).resolve(),
                str(args.cohort),
                dataset=dataset,
            )
        elif args.cohort:
            raise ValueError(
                "--cohort requires --experiment-manifest"
            )
        susvibes_commit = _git_head(susvibes_root)
        selected_commit = selection.get("susvibes_commit", "")
        if selected_commit and selected_commit != susvibes_commit:
            raise ValueError(
                "SusVibes checkout commit does not match "
                "the experiment manifest"
            )
        tasks = load_agent_tasks(
            dataset,
            instance_ids=selected_ids,
            start_index=int(args.start_index),
            num_instances=int(args.num_instances),
        )
        if not tasks:
            raise ValueError("task selection is empty")
        model = str(
            args.model or os.environ.get("ANTHROPIC_MODEL") or ""
        ).strip()
        claude_version = str(args.claude_version).strip()
        preflight: dict[str, Any] = {
            "status": "not_required_for_dry_run",
        }
        if args.execute:
            if not args.experiment_manifest:
                raise ValueError(
                    "execution requires --experiment-manifest and --cohort"
                )
            if not args.preflight_report:
                raise ValueError(
                    "execution requires --preflight-report"
                )
            if not args.allow_agent_network:
                raise ValueError(
                    "execution requires --allow-agent-network explicitly"
                )
            if not model:
                raise ValueError("--model is required for execution")
            if not (
                str(os.environ.get("ANTHROPIC_API_KEY") or "").strip()
                or str(
                    os.environ.get("ANTHROPIC_AUTH_TOKEN") or ""
                ).strip()
            ):
                raise ValueError(
                    "execution requires ANTHROPIC_API_KEY or "
                    "ANTHROPIC_AUTH_TOKEN"
                )
            preflight = {
                "status": "verified_ready",
                **load_ready_susvibes_agent_preflight(
                    Path(args.preflight_report).resolve(),
                    susvibes_root=susvibes_root,
                    dataset=dataset,
                    experiment_manifest=Path(
                        args.experiment_manifest
                    ).resolve(),
                    cohort=str(args.cohort),
                    start_index=int(args.start_index),
                    num_instances=int(args.num_instances),
                    results_dir=results_dir,
                    model=model,
                    claude_version=claude_version,
                    runner_path=Path(__file__).resolve(),
                ),
            }
        plan = build_sanitized_plan(
            dataset,
            tasks,
            susvibes_commit=susvibes_commit,
            model=model,
            claude_version=claude_version,
            max_stop_blocks=int(args.max_stop_blocks),
            results_dir=results_dir,
            workspace_root=workspace_root,
            selection=selection,
            preflight=preflight,
        )
        if not args.execute:
            if args.plan_output:
                _write_new_json(
                    Path(args.plan_output).resolve(),
                    plan,
                )
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        if not _docker_available():
            raise ValueError(
                "Docker daemon is not running; this script will not start it"
            )

        _validate_new_output_directory(results_dir)
        if args.plan_output:
            _write_new_json(
                Path(args.plan_output).resolve(),
                plan,
            )
        workspace_root.mkdir(parents=True, exist_ok=True)
        (results_dir / "plan.json").write_text(
            json.dumps(plan, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        results = []
        for task in tasks:
            results.append(_run_task(
                task,
                susvibes_root=susvibes_root,
                results_dir=results_dir,
                workspace_root=workspace_root,
                model=model,
                claude_version=claude_version,
                max_stop_blocks=int(args.max_stop_blocks),
                keep_workspace=bool(args.keep_workspace),
            ))
        predictions = [
            result["prediction"]
            for result in results
        ]
        predictions_path = results_dir / "predictions.jsonl"
        predictions_path.write_text(
            "".join(
                json.dumps(row, sort_keys=True) + "\n"
                for row in predictions
            ),
            encoding="utf-8",
        )
        summary = {
            "schema_version": "belief.susvibes_agent_run.v1",
            "task_count": len(results),
            "successful_agent_runs": sum(
                result["agent_success"] for result in results
            ),
            "policy_violation_suspected_count": sum(
                result["policy_violation_suspected"]
                for result in results
            ),
            "predictions": str(predictions_path),
        }
        (results_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    except (
        OSError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"error": f"{type(exc).__name__}: {exc}"},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
