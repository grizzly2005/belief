"""Contracts for SusVibes canonical candidate feedback evaluation."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark.susvibes_candidate_review import (
    SUSVIBES_CANDIDATE_REVIEW_MODE,
    SusVibesCandidateReviewThresholds,
    evaluate_susvibes_candidate_review,
)
from belief.benchmark.susvibes_experiment import (
    write_susvibes_experiment_manifest,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]


MASKED_SOURCE = """\
def read_asset(root, name):
    raise NotImplementedError
"""

VULNERABLE_SOURCE = """\
import os

def read_asset(root, name):
    path = os.path.join(root, name)
    return open(path).read()
"""

SECURE_SOURCE = """\
import os

def read_asset(root, name):
    path = os.path.abspath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root:
        raise ValueError("outside root")
    return open(path).read()
"""


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_EMAIL": "candidate@example.invalid",
            "GIT_AUTHOR_NAME": "BELIEF candidate benchmark",
            "GIT_COMMITTER_EMAIL": "candidate@example.invalid",
            "GIT_COMMITTER_NAME": "BELIEF candidate benchmark",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _commit(repository: Path, target: Path, source: str, message: str) -> str:
    target.write_text(source, encoding="utf-8")
    _git(repository, "add", "assets.py")
    _git(repository, "commit", "--quiet", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _candidate_fixture(tmp_path: Path) -> tuple[Path, Path]:
    cache = tmp_path / "repos"
    repository = cache / "example__assets"
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")
    target = repository / "assets.py"
    vulnerable_commit = _commit(
        repository,
        target,
        VULNERABLE_SOURCE,
        "vulnerable implementation",
    )
    fixed_commit = _commit(
        repository,
        target,
        SECURE_SOURCE,
        "secure implementation",
    )
    masked_commit = _commit(
        repository,
        target,
        MASKED_SOURCE,
        "masked task",
    )

    dataset = tmp_path / "susvibes.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "instance_id": "example__assets_fixed",
                "project": "example/assets",
                "base_commit": fixed_commit,
                "security_patch": _git(
                    repository,
                    "diff",
                    vulnerable_commit,
                    fixed_commit,
                ),
                "mask_patch": _git(
                    repository,
                    "diff",
                    vulnerable_commit,
                    masked_commit,
                ),
                "task_patch": _git(
                    repository,
                    "diff",
                    fixed_commit,
                    masked_commit,
                ),
                "golden_patch": _git(
                    repository,
                    "diff",
                    masked_commit,
                    fixed_commit,
                ),
                "test_patch": "",
                "cwe_ids": ["CWE-22"],
                "language": "Python",
                "cve_id": "CVE-2099-0001",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return dataset, cache


def test_candidate_review_discriminates_vulnerable_and_secure_patch(tmp_path):
    dataset, cache = _candidate_fixture(tmp_path)

    payload = evaluate_susvibes_candidate_review(dataset, cache)

    assert payload["schema_version"] == (
        "belief.susvibes_candidate_review.v1"
    )
    assert payload["mode"] == SUSVIBES_CANDIDATE_REVIEW_MODE
    assert payload["status"] == "passed"
    assert payload["metrics"]["evaluable_case_count"] == 1
    assert payload["metrics"]["vulnerable_warning_recall"] == 1.0
    assert (
        payload["metrics"]["secure_warning_false_positive_rate"]
        == 0.0
    )
    assert (
        payload["metrics"]["paired_warning_discrimination_rate"]
        == 1.0
    )
    assert payload["cases"][0]["vulnerable_warned"] is True
    assert payload["cases"][0]["secure_warning_false_positive"] is False
    assert payload["comparability"]["reviewer_received_benchmark_oracle"] is False
    assert payload["comparability"]["susvibes_secpass_equivalent"] is False
    assert payload["reviewer_provenance"]["callable"] == (
        "belief.patch_review.review_candidate_patch"
    )
    assert payload["reviewer_provenance"]["semantic_mode"] == "summaries"
    assert payload["reviewer_provenance"]["belief_python_file_count"] > 0
    assert len(
        payload["reviewer_provenance"]["belief_python_source_sha256"]
    ) == 64
    assert payload["reviewer_provenance"]["source_hash_normalization"] == (
        "relative_path_nul_lf_normalized_bytes"
    )


def test_candidate_reviewer_receives_workspace_only(tmp_path):
    dataset, cache = _candidate_fixture(tmp_path)
    calls: list[Path] = []

    def reviewer(workspace):
        workspace = Path(workspace)
        calls.append(workspace)
        source = (workspace / "assets.py").read_text(encoding="utf-8")
        vulnerable = "os.path.commonpath" not in source
        finding = {
            "actionable": True,
            "classification": "introduced",
            "cwe": "CWE-22",
            "rule_id": "CWE-22",
            "file": "assets.py",
            "line": 4,
            "function": "read_asset",
        }
        return {
            "status": "review_required" if vulnerable else "passed",
            "analysis": {
                "candidate": {"analysis_succeeded": True},
            },
            "introduced_findings": [finding] if vulnerable else [],
            "residual_findings": [],
            "deterministic_digest": "vulnerable" if vulnerable else "secure",
        }

    payload = evaluate_susvibes_candidate_review(
        dataset,
        cache,
        reviewer=reviewer,
    )

    assert len(calls) == 2
    assert payload["metrics"]["paired_warning_discrimination_rate"] == 1.0


def test_candidate_review_records_flow_state_configuration(tmp_path):
    dataset, cache = _candidate_fixture(tmp_path)

    payload = evaluate_susvibes_candidate_review(
        dataset,
        cache,
        reviewer_semantic_mode="flow_states",
    )

    assert (
        payload["reviewer_provenance"]["semantic_mode"]
        == "flow_states"
    )
    assert payload["metrics"]["evaluable_case_count"] == 1


def test_custom_reviewer_rejects_unapplied_semantic_configuration(
    tmp_path,
):
    dataset, cache = _candidate_fixture(tmp_path)

    def reviewer(_workspace):
        raise AssertionError("must not be called")

    with pytest.raises(ValueError, match="built-in"):
        evaluate_susvibes_candidate_review(
            dataset,
            cache,
            reviewer=reviewer,
            reviewer_semantic_mode="flow_states",
        )


def test_candidate_review_digest_excludes_duration(tmp_path):
    dataset, cache = _candidate_fixture(tmp_path)
    first_clock = iter((1.0, 3.0))
    second_clock = iter((50.0, 59.0))

    first = evaluate_susvibes_candidate_review(
        dataset,
        cache,
        clock=lambda: next(first_clock),
    )
    second = evaluate_susvibes_candidate_review(
        dataset,
        cache,
        clock=lambda: next(second_clock),
    )

    assert first["duration_seconds"] == 2.0
    assert second["duration_seconds"] == 9.0
    assert first["deterministic_digest"] == second["deterministic_digest"]


def test_candidate_review_preserves_explicit_selection_and_provenance(
    tmp_path,
):
    dataset, cache = _candidate_fixture(tmp_path)

    payload = evaluate_susvibes_candidate_review(
        dataset,
        cache,
        instance_ids=["example__assets_fixed"],
        selection_provenance={
            "cohort": "canary",
            "manifest_digest": "frozen-manifest",
        },
    )

    assert payload["case_count"] == 1
    assert payload["cases"][0]["id"] == "example__assets_fixed"
    assert payload["selection"]["kind"] == "explicit_instance_ids"
    assert payload["selection"]["case_count"] == 1
    assert len(payload["selection"]["instance_ids_sha256"]) == 64
    assert payload["selection"]["provenance"] == {
        "cohort": "canary",
        "manifest_digest": "frozen-manifest",
    }


@pytest.mark.parametrize(
    ("instance_ids", "only_cwes", "max_cases", "message"),
    [
        (
            ["example__assets_fixed", "example__assets_fixed"],
            (),
            0,
            "instance IDs must be unique",
        ),
        (
            ["unknown__case"],
            (),
            0,
            "instance IDs are absent from the dataset",
        ),
        (
            ["example__assets_fixed"],
            (),
            1,
            "cannot be combined",
        ),
        (
            ["example__assets_fixed"],
            ("CWE-22",),
            0,
            "cannot be combined",
        ),
    ],
)
def test_candidate_review_rejects_invalid_explicit_selection(
    tmp_path,
    instance_ids,
    only_cwes,
    max_cases,
    message,
):
    dataset, cache = _candidate_fixture(tmp_path)

    with pytest.raises(ValueError, match=message):
        evaluate_susvibes_candidate_review(
            dataset,
            cache,
            instance_ids=instance_ids,
            only_cwes=only_cwes,
            max_cases=max_cases,
        )


def test_candidate_review_thresholds_reject_empty_reviewer(tmp_path):
    dataset, cache = _candidate_fixture(tmp_path)

    def empty_reviewer(_workspace):
        return {
            "status": "passed",
            "analysis": {
                "candidate": {"analysis_succeeded": True},
            },
            "introduced_findings": [],
            "residual_findings": [],
            "deterministic_digest": "empty",
        }

    payload = evaluate_susvibes_candidate_review(
        dataset,
        cache,
        reviewer=empty_reviewer,
        thresholds=SusVibesCandidateReviewThresholds(
            minimum_vulnerable_warning_recall=0.5,
            maximum_secure_warning_false_positive_rate=0.0,
            minimum_paired_warning_discrimination_rate=0.5,
        ),
    )

    assert payload["status"] == "failed"
    assert payload["exit_code"] == 1


def test_candidate_review_cli_uses_explicit_local_cache(tmp_path):
    dataset, cache = _candidate_fixture(tmp_path)
    output = tmp_path / "candidate-review.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--mode",
            SUSVIBES_CANDIDATE_REVIEW_MODE,
            "--target",
            str(dataset),
            "--repository-cache",
            str(cache),
            "--only-cwe",
            "CWE-22",
            "--json-output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert summary["status"] == "passed"
    assert summary["deterministic_digest"] == payload["deterministic_digest"]
    assert (
        payload["metrics"]["paired_warning_discrimination_rate"]
        == 1.0
    )


def test_candidate_review_cli_verifies_and_records_manifest_cohort(
    tmp_path,
):
    dataset, cache = _candidate_fixture(tmp_path)
    manifest = tmp_path / "experiment.json"
    output = tmp_path / "candidate-review.json"
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit="a" * 40,
        smoke_size=1,
        canary_size=1,
        batch_size=1,
    )

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--mode",
            SUSVIBES_CANDIDATE_REVIEW_MODE,
            "--target",
            str(dataset),
            "--repository-cache",
            str(cache),
            "--experiment-manifest",
            str(manifest),
            "--cohort",
            "canary",
            "--json-output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["selection"]["case_count"] == 1
    assert payload["selection"]["provenance"]["cohort"] == "canary"
    assert payload["selection"]["provenance"]["susvibes_commit"] == "a" * 40


def test_manifest_selection_is_rejected_outside_candidate_review(tmp_path):
    output = tmp_path / "reportability.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--experiment-manifest",
            str(tmp_path / "experiment.json"),
            "--cohort",
            "canary",
            "--json-output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "supported only with susvibes_candidate_review_v1" in completed.stderr
    assert not output.exists()
