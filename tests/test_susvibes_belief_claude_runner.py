"""Offline contracts for the SusVibes Claude + BELIEF runner."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.run_susvibes_belief_claude import (
    _sanitize_candidate_workspace,
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
