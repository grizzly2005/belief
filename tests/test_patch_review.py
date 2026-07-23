"""Contracts for oracle-free candidate patch security review."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from belief.patch_review import (
    collect_worktree_patch,
    review_candidate_patch,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_EMAIL": "patch-review@example.invalid",
            "GIT_AUTHOR_NAME": "BELIEF patch review",
            "GIT_COMMITTER_EMAIL": "patch-review@example.invalid",
            "GIT_COMMITTER_NAME": "BELIEF patch review",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def _repository(tmp_path: Path, source: str) -> tuple[Path, Path]:
    repository = tmp_path / "candidate"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    target = repository / "assets.py"
    target.write_text(source, encoding="utf-8")
    _git(repository, "add", "assets.py")
    _git(repository, "commit", "--quiet", "-m", "baseline")
    return repository, target


SAFE_SOURCE = """\
import os

def read_asset(root, name):
    path = os.path.abspath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root:
        raise ValueError("outside root")
    return open(path).read()
"""

VULNERABLE_SOURCE = """\
import os

def read_asset(root, name):
    path = os.path.join(root, name)
    return open(path).read()
"""


def test_review_surfaces_candidate_introduced_path_traversal(tmp_path):
    repository, target = _repository(tmp_path, SAFE_SOURCE)
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")

    payload = review_candidate_patch(repository)

    assert payload["schema_version"] == "belief.candidate_patch_review.v1"
    assert payload["mode"] == "oracle_free_candidate_patch_review"
    assert payload["status"] == "review_required"
    assert payload["counts"]["introduced_actionable"] >= 1
    assert any(
        row["cwe"] == "CWE-22" and row["classification"] == "introduced"
        for row in payload["introduced_findings"]
    )
    assert "missing security guarantee" in payload["feedback"]
    assert payload["comparability"]["benchmark_oracle_used"] is False
    assert payload["comparability"]["security_tests_executed"] is False


def test_review_accepts_candidate_with_path_boundary_guard(tmp_path):
    baseline = """\
def read_asset(root, name):
    raise NotImplementedError
"""
    repository, target = _repository(tmp_path, baseline)
    target.write_text(SAFE_SOURCE, encoding="utf-8")

    payload = review_candidate_patch(repository)

    assert payload["status"] == "passed"
    assert payload["counts"]["candidate_actionable"] == 0
    assert "no actionable security-boundary finding" in payload["feedback"]


def test_review_labels_unchanged_security_risk_as_residual(tmp_path):
    repository, target = _repository(tmp_path, VULNERABLE_SOURCE)
    target.write_text(
        VULNERABLE_SOURCE.replace(
            "path = os.path.join(root, name)",
            "path = os.path.join(str(root), name)",
        ),
        encoding="utf-8",
    )

    payload = review_candidate_patch(repository)

    assert payload["status"] == "review_required"
    assert payload["counts"]["residual_actionable"] >= 1
    assert any(
        row["cwe"] == "CWE-22" and row["classification"] == "residual"
        for row in payload["residual_findings"]
    )


def test_review_excludes_python_tests_by_default(tmp_path):
    repository, _target = _repository(tmp_path, SAFE_SOURCE)
    tests_dir = repository / "tests"
    tests_dir.mkdir()
    test_file = tests_dir / "test_assets.py"
    test_file.write_text("def test_placeholder():\n    assert True\n", encoding="utf-8")
    _git(repository, "add", "tests/test_assets.py")
    _git(repository, "commit", "--quiet", "-m", "add tests")
    test_file.write_text(VULNERABLE_SOURCE, encoding="utf-8")

    payload = review_candidate_patch(repository)

    assert payload["changed_python_files"] == []
    assert payload["excluded_test_files"] == ["tests/test_assets.py"]
    assert payload["status"] == "passed"


def test_worktree_patch_includes_untracked_python_files(tmp_path):
    repository, _target = _repository(tmp_path, SAFE_SOURCE)
    untracked = repository / "preview.py"
    untracked.write_text(VULNERABLE_SOURCE, encoding="utf-8")

    patch = collect_worktree_patch(repository)
    payload = review_candidate_patch(repository, patch)

    assert "preview.py" in patch
    assert payload["changed_python_files"] == ["preview.py"]
    assert payload["counts"]["introduced_actionable"] >= 1


def test_review_digest_excludes_target_and_duration(tmp_path):
    repository, target = _repository(tmp_path, SAFE_SOURCE)
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
    first_clock = iter((10.0, 11.0))
    second_clock = iter((50.0, 58.0))

    first = review_candidate_patch(
        repository,
        clock=lambda: next(first_clock),
    )
    second = review_candidate_patch(
        repository,
        clock=lambda: next(second_clock),
    )

    assert first["duration_seconds"] == 1.0
    assert second["duration_seconds"] == 8.0
    assert first["deterministic_digest"] == second["deterministic_digest"]


def test_review_cli_writes_json_feedback_and_enforces_gate(tmp_path):
    repository, target = _repository(tmp_path, SAFE_SOURCE)
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
    report = tmp_path / "review.json"
    feedback = tmp_path / "feedback.txt"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "review-patch",
            "--target",
            str(repository),
            "--json-output",
            str(report),
            "--feedback-output",
            str(feedback),
            "--fail-on-findings",
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 1, completed.stderr
    summary = json.loads(completed.stdout)
    payload = json.loads(report.read_text(encoding="utf-8"))
    assert summary["status"] == "review_required"
    assert payload["counts"]["candidate_actionable"] >= 1
    assert feedback.read_text(encoding="utf-8").startswith(
        "BELIEF found actionable"
    )


def test_review_requires_repository_root(tmp_path):
    repository, _target = _repository(tmp_path, SAFE_SOURCE)
    subdirectory = repository / "package"
    subdirectory.mkdir()

    with pytest.raises(ValueError, match="repository root"):
        review_candidate_patch(subdirectory)
