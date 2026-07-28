"""Offline contracts for the SusVibes Claude + BELIEF runner."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

import scripts.run_susvibes_belief_claude as runner_module
from belief.benchmark.susvibes_experiment import (
    write_susvibes_experiment_manifest,
)
from belief.benchmark.susvibes_preflight import (
    write_susvibes_agent_preflight,
)
from scripts.run_susvibes_belief_claude import (
    ALLOWED_TOOLS,
    _build_claude_command,
    _model_identity_status,
    _parse_claude_cli_version,
    _sanitize_candidate_workspace,
    _summarize_agent_stream,
    _summarize_belief_feedback,
    _validated_container_identifier,
    load_agent_tasks,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> None:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_EMAIL": "runner@example.invalid",
            "GIT_AUTHOR_NAME": "BELIEF runner",
            "GIT_COMMITTER_EMAIL": "runner@example.invalid",
            "GIT_COMMITTER_NAME": "BELIEF runner",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )


def _fake_susvibes(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "susvibes"
    harness = root / "evaluation_harness" / "claude_code"
    harness.mkdir(parents=True)
    (harness / "placeholder.py").write_text("# fixture\n", encoding="utf-8")
    dataset_dir = root / "datasets" / "default"
    dataset_dir.mkdir(parents=True)
    dataset = dataset_dir / "susvibes_dataset.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "instance_id": "example__project_deadbeef",
                "project": "example/project",
                "base_commit": "a" * 40,
                "language": "python",
                "image_name": "example/susvibes:fixture",
                "problem_statement": "Implement a safe asset reader.",
                "security_patch": "SECRET SECURITY ORACLE",
                "test_patch": "SECRET HIDDEN TEST",
                "golden_patch": "SECRET REFERENCE PATCH",
                "cwe_ids": ["CWE-22"],
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "pinned fixture")
    return root, dataset


def test_task_loader_strips_all_benchmark_oracle_fields(tmp_path):
    _root, dataset = _fake_susvibes(tmp_path)

    tasks = load_agent_tasks(dataset)

    assert tasks == [
        {
            "image_name": "example/susvibes:fixture",
            "instance_id": "example__project_deadbeef",
            "problem_statement": "Implement a safe asset reader.",
        }
    ]
    serialized = json.dumps(tasks)
    assert "SECURITY ORACLE" not in serialized
    assert "HIDDEN TEST" not in serialized
    assert "REFERENCE PATCH" not in serialized
    assert "cwe_ids" not in serialized


def test_task_loader_preserves_verified_selection_order(tmp_path):
    _root, dataset = _fake_susvibes(tmp_path)
    first = json.loads(dataset.read_text(encoding="utf-8"))
    second = {
        **first,
        "instance_id": "example__second_cafebabe",
        "image_name": "example/susvibes:second",
    }
    dataset.write_text(
        json.dumps(first, sort_keys=True)
        + "\n"
        + json.dumps(second, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    tasks = load_agent_tasks(
        dataset,
        instance_ids=[
            "example__second_cafebabe",
            "example__project_deadbeef",
        ],
        num_instances=2,
    )

    assert [task["instance_id"] for task in tasks] == [
        "example__second_cafebabe",
        "example__project_deadbeef",
    ]


def test_runner_dry_run_emits_hashed_sanitized_plan_only(tmp_path):
    susvibes_root, _dataset = _fake_susvibes(tmp_path)
    results = tmp_path / "isolated-results"
    plan_path = tmp_path / "plan.json"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(results),
            "--model",
            "claude-fable-5",
            "--plan-output",
            str(plan_path),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    plan = json.loads(completed.stdout)
    assert json.loads(plan_path.read_text(encoding="utf-8")) == plan
    assert plan["task_count"] == 1
    assert plan["model"] == "claude-fable-5"
    assert plan["model_selection"] == {
        "requested_model": "claude-fable-5",
        "claude_cli_argument": "--model",
        "automatic_fallback_configured": False,
    }
    assert plan["boundaries"]["benchmark_oracle_forwarded"] is False
    assert plan["boundaries"]["docker_auto_start"] is False
    assert plan["boundaries"]["workspace_git_history_removed"] is True
    assert plan["tasks"][0]["agent_visible_fields"] == [
        "image_name",
        "instance_id",
        "problem_statement",
    ]
    serialized = json.dumps(plan)
    assert "Implement a safe asset reader" not in serialized
    assert "SECRET" not in serialized
    assert not results.exists()


def test_runner_dry_run_has_true_no_feedback_control_arm(tmp_path):
    susvibes_root, _dataset = _fake_susvibes(tmp_path)
    results = tmp_path / "baseline-results"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(results),
            "--model",
            "claude-fable-5",
            "--feedback-mode",
            "none",
            "--max-stop-blocks",
            "0",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    plan = json.loads(completed.stdout)
    assert plan["schema_version"] == "belief.susvibes_agent_plan.v3"
    assert plan["mode"] == "claude_code_without_belief_feedback"
    assert plan["feedback_mode"] == "none"
    assert plan["max_stop_blocks"] == 0
    assert plan["boundaries"]["belief_stop_hook_enabled"] is False
    assert not results.exists()


def test_claude_command_pins_model_and_disables_fallback_surfaces():
    command = _build_claude_command(
        prompt="Fix the local task safely.",
        model="claude-fable-5",
    )
    arguments = shlex.split(command.split(" && ", maxsplit=2)[2])

    assert arguments[arguments.index("--model") + 1] == "claude-fable-5"
    assert "--fallback-model" not in arguments
    assert arguments[arguments.index("--tools") + 1].split(",") == list(
        ALLOWED_TOOLS
    )
    assert arguments[arguments.index("--setting-sources") + 1] == ""
    assert "--strict-mcp-config" in arguments
    assert "--disable-slash-commands" in arguments
    assert "--no-chrome" in arguments
    assert "--no-session-persistence" in arguments


def test_agent_stream_records_model_refusal_and_same_model_retries():
    stream = (
        b'{"type":"system","subtype":"api_retry","attempt":1}\n'
        b'{"type":"assistant","message":{"model":"claude-fable-5",'
        b'"stop_reason":null}}\n'
        b'{"type":"result","subtype":"success","is_error":false,'
        b'"stop_reason":"refusal","stop_details":{"category":"cyber"},'
        b'"total_cost_usd":0.125,"duration_ms":1200,'
        b'"duration_api_ms":900,"num_turns":2,'
        b'"usage":{"input_tokens":100,"output_tokens":25,'
        b'"cache_read_input_tokens":50}}\n'
    )

    metadata = _summarize_agent_stream(stream)

    assert metadata == {
        "valid_json_event_count": 3,
        "invalid_json_line_count": 0,
        "assistant_models_observed": ["claude-fable-5"],
        "stop_reasons_observed": ["refusal"],
        "model_refusal_observed": True,
        "refusal_categories_observed": ["cyber"],
        "api_retry_event_count": 1,
        "result_event_count": 1,
        "result_subtypes_observed": ["success"],
        "result_error_observed": False,
        "result_accounting": {
            "total_cost_usd": 0.125,
            "duration_ms": 1200,
            "duration_api_ms": 900,
            "num_turns": 2,
            "usage": {
                "input_tokens": 100,
                "output_tokens": 25,
                "cache_read_input_tokens": 50,
            },
            "invalid_fields": [],
        },
    }
    assert _model_identity_status(
        "claude-fable-5",
        metadata["assistant_models_observed"],
    ) == "matched"
    assert _model_identity_status("claude-fable-5", []) == "not_observed"
    assert _model_identity_status(
        "claude-fable-5",
        ["claude-sonnet-5"],
    ) == "mismatch"


def test_belief_feedback_summary_records_actual_blocks(tmp_path):
    reports = tmp_path / "reports" / "session"
    state = tmp_path / "state"
    reports.mkdir(parents=True)
    state.mkdir()
    (reports / "review-00.json").write_text(
        '{"status":"failed"}\n',
        encoding="utf-8",
    )
    (state / "session.json").write_text(
        json.dumps({
            "block_count": 1,
            "status": "blocked_for_repair",
        }),
        encoding="utf-8",
    )

    summary = _summarize_belief_feedback(
        tmp_path / "reports",
        state,
        configured_max_blocks=1,
    )

    assert summary == {
        "enabled": True,
        "configured_max_blocks": 1,
        "review_count": 1,
        "state_count": 1,
        "feedback_block_count": 1,
        "feedback_delivered": True,
        "terminal_statuses": ["blocked_for_repair"],
    }


def test_claude_cli_version_probe_is_exact():
    assert _parse_claude_cli_version(
        b"2.1.218 (Claude Code)\n"
    ) == "2.1.218"
    assert _parse_claude_cli_version(b"v2.1.218\n") == "2.1.218"
    with pytest.raises(ValueError, match="invalid output"):
        _parse_claude_cli_version(b"latest\n")


def test_docker_container_identifier_is_abortively_validated():
    assert _validated_container_identifier(
        "susvibes-task.123"
    ) == "susvibes-task.123"
    for unsafe in ("", "--context=attacker", "name:tag", "name\nother"):
        with pytest.raises(ValueError, match="container identifier"):
            _validated_container_identifier(unsafe)


def test_runner_refuses_unknown_instance_id(tmp_path):
    susvibes_root, _dataset = _fake_susvibes(tmp_path)

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(tmp_path / "results"),
            "--instance-id",
            "missing__instance",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "unknown instance IDs" in completed.stderr


def test_runner_refuses_to_overwrite_existing_plan(tmp_path):
    susvibes_root, _dataset = _fake_susvibes(tmp_path)
    plan_path = tmp_path / "plan.json"
    plan_path.write_text("keep me\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(tmp_path / "results"),
            "--plan-output",
            str(plan_path),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "refusing to overwrite output file" in completed.stderr
    assert plan_path.read_text(encoding="utf-8") == "keep me\n"


def test_runner_uses_verified_manifest_cohort_for_selection(tmp_path):
    susvibes_root, dataset = _fake_susvibes(tmp_path)
    manifest = tmp_path / "experiment.json"
    commit = subprocess.run(
        ["git", "-C", str(susvibes_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit=commit,
        smoke_size=1,
        canary_size=1,
        batch_size=1,
    )

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(tmp_path / "results"),
            "--experiment-manifest",
            str(manifest),
            "--cohort",
            "smoke",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    plan = json.loads(completed.stdout)
    assert plan["task_count"] == 1
    assert plan["tasks"][0]["instance_id"] == "example__project_deadbeef"
    assert plan["selection"]["cohort"] == "smoke"
    assert plan["selection"]["susvibes_commit"] == commit
    assert len(plan["selection"]["manifest_sha256"]) == 64
    serialized = json.dumps(plan)
    assert "CWE-22" not in serialized
    assert "SECRET" not in serialized


def test_runner_refuses_manifest_checkout_commit_mismatch(tmp_path):
    susvibes_root, dataset = _fake_susvibes(tmp_path)
    manifest = tmp_path / "experiment.json"
    commit = subprocess.run(
        ["git", "-C", str(susvibes_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit=commit,
        smoke_size=1,
        canary_size=1,
        batch_size=1,
    )
    (susvibes_root / "new-commit.txt").write_text(
        "changes checkout identity\n",
        encoding="utf-8",
    )
    _git(susvibes_root, "add", ".")
    _git(susvibes_root, "commit", "--quiet", "-m", "different checkout")

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(tmp_path / "results"),
            "--experiment-manifest",
            str(manifest),
            "--cohort",
            "smoke",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "commit does not match" in completed.stderr


def test_execute_requires_and_records_matching_ready_preflight(
    tmp_path,
    monkeypatch,
    capsys,
):
    susvibes_root, dataset = _fake_susvibes(tmp_path)
    manifest = tmp_path / "experiment.json"
    commit = subprocess.run(
        ["git", "-C", str(susvibes_root), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit=commit,
        smoke_size=1,
        canary_size=1,
        batch_size=1,
    )
    results = tmp_path / "isolated-results"
    report = tmp_path / "ready-preflight.json"
    write_susvibes_agent_preflight(
        report,
        susvibes_root=susvibes_root,
        dataset=dataset,
        experiment_manifest=manifest,
        cohort="smoke",
        results_dir=results,
        model="claude-fable-5",
        claude_version="2.1.218",
        minimum_free_gib=1.0,
        acknowledge_agent_network=True,
        environment={"ANTHROPIC_API_KEY": "test-only-secret"},
        docker_probe=lambda: (True, "fixture|x86_64"),
        disk_free_probe=lambda _path: 500 * 1024 ** 3,
        runner_path=ROOT / "scripts" / "run_susvibes_belief_claude.py",
    )

    def fake_run_task(task, **_kwargs):
        return {
            "instance_id": task["instance_id"],
            "agent_success": True,
            "model_identity_status": "matched",
            "agent_stream": {
                "model_refusal_observed": False,
                "api_retry_event_count": 0,
                "result_accounting": {
                    "total_cost_usd": 0.1,
                    "duration_ms": 1000,
                    "duration_api_ms": 800,
                    "num_turns": 1,
                    "usage": {
                        "input_tokens": 100,
                        "output_tokens": 20,
                    },
                    "invalid_fields": [],
                },
            },
            "policy_violation_suspected": False,
            "belief_feedback": {
                "enabled": True,
                "configured_max_blocks": 1,
                "review_count": 1,
                "state_count": 1,
                "feedback_block_count": 0,
                "feedback_delivered": False,
                "terminal_statuses": ["passed"],
            },
            "prediction": {
                "instance_id": task["instance_id"],
                "model_name_or_path": "belief-test",
                "model_patch": "",
            },
        }

    monkeypatch.setattr(runner_module, "_docker_available", lambda: True)
    monkeypatch.setattr(runner_module, "_run_task", fake_run_task)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-only-secret")
    monkeypatch.setattr(sys, "argv", [
        "run_susvibes_belief_claude.py",
        "--susvibes-root",
        str(susvibes_root),
        "--results-dir",
        str(results),
        "--experiment-manifest",
        str(manifest),
        "--cohort",
        "smoke",
        "--preflight-report",
        str(report),
        "--model",
        "claude-fable-5",
        "--execute",
        "--allow-agent-network",
    ])

    assert runner_module.main() == 0
    plan = json.loads((results / "plan.json").read_text(encoding="utf-8"))
    assert plan["preflight"]["status"] == "verified_ready"
    assert len(plan["preflight"]["report_digest"]) == 64
    assert plan["selection"]["cohort"] == "smoke"
    assert "test-only-secret" not in json.dumps(plan)
    summary = json.loads(capsys.readouterr().out)
    assert summary["successful_agent_runs"] == 1


def test_execute_refuses_unmanifested_selection(tmp_path):
    susvibes_root, _dataset = _fake_susvibes(tmp_path)

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/run_susvibes_belief_claude.py",
            "--susvibes-root",
            str(susvibes_root),
            "--results-dir",
            str(tmp_path / "results"),
            "--model",
            "claude-fable-5",
            "--execute",
            "--allow-agent-network",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "requires --experiment-manifest and --cohort" in completed.stderr


def test_workspace_sanitization_removes_recoverable_git_history(tmp_path):
    repository = tmp_path / "candidate"
    repository.mkdir()
    (repository / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _git(repository, "init", "--quiet")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "upstream secret history")
    old_head = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    (repository / "app.py").write_text("VALUE = 2\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "--quiet", "-m", "visible task state")

    nested = repository / "vendor"
    nested.mkdir()
    (nested / "library.py").write_text("SAFE = True\n", encoding="utf-8")
    _git(nested, "init", "--quiet")
    _git(nested, "add", ".")
    _git(nested, "commit", "--quiet", "-m", "nested history")

    result = _sanitize_candidate_workspace(repository)

    assert result["mode"] == "fresh_history_free_git_baseline"
    assert result["removed_git_metadata_count"] == 2
    assert result["baseline_parent_count"] == 0
    assert (repository / "app.py").read_text(encoding="utf-8") == "VALUE = 2\n"
    assert (nested / "library.py").is_file()
    assert not (nested / ".git").exists()
    count = subprocess.run(
        ["git", "-C", str(repository), "rev-list", "--count", "HEAD"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert count == "1"
    old_object = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "cat-file",
            "-e",
            f"{old_head}^{{commit}}",
        ],
        check=False,
        capture_output=True,
    )
    assert old_object.returncode != 0
