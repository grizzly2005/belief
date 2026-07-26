"""Contracts for the create-only paired SusVibes smoke preregistration."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    write_susvibes_experiment_manifest,
)
from belief.benchmark.susvibes_paired_smoke import (
    build_susvibes_paired_smoke_preregistration,
    write_susvibes_paired_smoke_preregistration,
)


pytestmark = pytest.mark.security


def _git(repository: Path, *arguments: str) -> str:
    environment = dict(os.environ)
    environment.update({
        "GIT_AUTHOR_EMAIL": "paired@example.invalid",
        "GIT_AUTHOR_NAME": "BELIEF paired smoke",
        "GIT_COMMITTER_EMAIL": "paired@example.invalid",
        "GIT_COMMITTER_NAME": "BELIEF paired smoke",
    })
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=environment,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _fixture(tmp_path: Path) -> dict[str, object]:
    susvibes = tmp_path / "susvibes"
    dataset_dir = susvibes / "datasets" / "default"
    dataset_dir.mkdir(parents=True)
    (susvibes / "evaluation_harness" / "claude_code").mkdir(
        parents=True
    )
    dataset = dataset_dir / "susvibes_dataset.jsonl"
    rows = [
        {
            "instance_id": f"owner__project_{index:040x}",
            "project": f"owner/project-{index}",
            "base_commit": f"{index + 1:040x}",
            "language": "python",
            "image_name": f"example/susvibes:{index}",
            "problem_statement": f"Implement safe feature {index}.",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": [f"CWE-{20 + index}"],
        }
        for index in range(4)
    ]
    dataset.write_text(
        "".join(
            json.dumps(row, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    _git(susvibes, "init", "--quiet")
    _git(susvibes, "add", ".")
    _git(susvibes, "commit", "--quiet", "-m", "pinned SusVibes")
    susvibes_commit = _git(susvibes, "rev-parse", "HEAD")

    manifest = tmp_path / "experiment.json"
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit=susvibes_commit,
        smoke_size=3,
        canary_size=3,
        batch_size=2,
    )

    belief = tmp_path / "belief"
    runner = belief / "scripts" / "run_susvibes_belief_claude.py"
    runner.parent.mkdir(parents=True)
    runner.write_text("# pinned paired runner\n", encoding="utf-8")
    _git(belief, "init", "--quiet")
    _git(belief, "add", ".")
    _git(belief, "commit", "--quiet", "-m", "pinned BELIEF")

    return {
        "susvibes_root": susvibes,
        "dataset": dataset,
        "experiment_manifest": manifest,
        "belief_root": belief,
        "runner_path": runner,
        "baseline_results_dir": tmp_path / "runs" / "baseline",
        "belief_results_dir": tmp_path / "runs" / "belief",
        "baseline_preflight_report": (
            tmp_path / "evidence" / "baseline-preflight.json"
        ),
        "belief_preflight_report": (
            tmp_path / "evidence" / "belief-preflight.json"
        ),
        "model": "claude-fable-5",
        "claude_version": "2.1.218",
        "start_index": 0,
        "num_instances": 3,
    }


def test_preregistration_freezes_paired_arms_without_disclosing_tasks(
    tmp_path,
):
    kwargs = _fixture(tmp_path)
    output = tmp_path / "evidence" / "paired-smoke.json"

    payload = write_susvibes_paired_smoke_preregistration(
        output,
        **kwargs,
    )

    assert payload["status"] == "preregistered_not_executed"
    assert payload["experiment"]["num_instances"] == 3
    assert payload["experiment"]["instance_ids_recorded"] is False
    assert [
        (arm["feedback_mode"], arm["max_stop_blocks"])
        for arm in payload["arms"]
    ] == [("none", 0), ("belief", 1)]
    assert payload["protocol"]["pass_at_k"] == 1
    assert payload["protocol"]["arm_union_is_score"] is False
    assert payload["boundaries"]["docker_started"] is False
    assert payload["boundaries"]["model_called"] is False
    serialized = output.read_text(encoding="utf-8")
    assert "Implement safe feature" not in serialized
    assert "owner__project_" not in serialized
    assert len(payload["preregistration_digest"]) == 64

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_susvibes_paired_smoke_preregistration(
            output,
            **kwargs,
        )


def test_preregistration_rejects_dirty_belief_checkout(tmp_path):
    kwargs = _fixture(tmp_path)
    runner = Path(kwargs["runner_path"])
    runner.write_text("# changed after freeze\n", encoding="utf-8")

    with pytest.raises(ValueError, match="BELIEF checkout must be clean"):
        build_susvibes_paired_smoke_preregistration(**kwargs)
