"""Contracts for deterministic public SusVibes experiment cohorts."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    SUSVIBES_EXPERIMENT_ALGORITHM,
    build_susvibes_experiment_manifest,
    load_experiment_cohort,
    write_susvibes_experiment_manifest,
)


pytestmark = pytest.mark.security

PINNED_COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[1]


def _dataset(tmp_path: Path, *, case_count: int = 30) -> Path:
    dataset = tmp_path / "susvibes_dataset.jsonl"
    rows = []
    for index in range(case_count):
        rows.append({
            "instance_id": f"owner{index}__project{index}_{index:040x}",
            "project": f"owner{index}/project{index}",
            "base_commit": f"{index + 1:040x}",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": [f"CWE-{100 + index % 15}"],
            "language": "python",
            "image_name": f"example/image:{index}",
            "problem_statement": f"Implement feature {index}.",
        })
    dataset.write_text(
        "".join(
            json.dumps(row, sort_keys=True) + "\n"
            for row in reversed(rows)
        ),
        encoding="utf-8",
    )
    return dataset


def test_manifest_is_deterministic_and_breadth_first(tmp_path):
    dataset = _dataset(tmp_path)

    first = build_susvibes_experiment_manifest(
        dataset,
        susvibes_commit=PINNED_COMMIT,
        smoke_size=3,
        canary_size=12,
        batch_size=7,
    )
    second = build_susvibes_experiment_manifest(
        dataset,
        susvibes_commit=PINNED_COMMIT,
        smoke_size=3,
        canary_size=12,
        batch_size=7,
    )

    assert first == second
    assert first["selection_algorithm"] == SUSVIBES_EXPERIMENT_ALGORITHM
    assert first["cohorts"]["smoke"]["case_count"] == 3
    assert first["cohorts"]["canary"]["case_count"] == 12
    assert first["cohorts"]["full"]["case_count"] == 30
    assert (
        first["cohorts"]["canary"]["coverage"][
            "primary_cwe_strata_count"
        ]
        == 12
    )
    assert first["cohorts"]["canary"]["coverage"]["project_count"] == 12
    assert len(first["batches"]) == 5
    full_ids = first["cohorts"]["full"]["instance_ids"]
    assert len(full_ids) == len(set(full_ids)) == 30
    assert first["boundaries"]["canary_is_leaderboard_comparable"] is False


def test_loader_returns_ids_only_with_verified_provenance(tmp_path):
    dataset = _dataset(tmp_path)
    manifest_path = tmp_path / "experiment.json"
    payload = write_susvibes_experiment_manifest(
        dataset,
        manifest_path,
        susvibes_commit=PINNED_COMMIT,
        canary_size=12,
    )

    instance_ids, provenance = load_experiment_cohort(
        manifest_path,
        "canary",
        dataset=dataset,
    )

    assert instance_ids == payload["cohorts"]["canary"]["instance_ids"]
    assert set(provenance) == {
        "cohort",
        "dataset_sha256",
        "manifest_digest",
        "manifest_sha256",
        "susvibes_commit",
    }
    assert provenance["cohort"] == "canary"
    assert provenance["susvibes_commit"] == PINNED_COMMIT
    assert "cwe_ids" not in json.dumps(provenance)


def test_loader_rejects_dataset_hash_mismatch(tmp_path):
    dataset = _dataset(tmp_path)
    manifest_path = tmp_path / "experiment.json"
    write_susvibes_experiment_manifest(
        dataset,
        manifest_path,
        susvibes_commit=PINNED_COMMIT,
    )
    dataset.write_text(
        dataset.read_text(encoding="utf-8") + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="dataset SHA-256 mismatch"):
        load_experiment_cohort(
            manifest_path,
            "smoke",
            dataset=dataset,
        )


def test_loader_rejects_manifest_tampering(tmp_path):
    dataset = _dataset(tmp_path)
    manifest_path = tmp_path / "experiment.json"
    write_susvibes_experiment_manifest(
        dataset,
        manifest_path,
        susvibes_commit=PINNED_COMMIT,
    )
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload["cohorts"]["smoke"]["instance_ids"].reverse()
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        load_experiment_cohort(
            manifest_path,
            "smoke",
            dataset=dataset,
        )


def test_writer_refuses_to_overwrite_manifest(tmp_path):
    dataset = _dataset(tmp_path)
    output = tmp_path / "experiment.json"
    output.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_susvibes_experiment_manifest(
            dataset,
            output,
            susvibes_commit=PINNED_COMMIT,
        )

    assert output.read_text(encoding="utf-8") == "preserve\n"


def test_prepare_script_refuses_dirty_checkout(tmp_path):
    root = tmp_path / "susvibes"
    root.mkdir()
    dataset = _dataset(root)
    expected_dataset = (
        root / "datasets" / "default" / "susvibes_dataset.jsonl"
    )
    expected_dataset.parent.mkdir(parents=True)
    dataset.replace(expected_dataset)
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_EMAIL": "experiment@example.invalid",
        "GIT_AUTHOR_NAME": "BELIEF experiment",
        "GIT_COMMITTER_EMAIL": "experiment@example.invalid",
        "GIT_COMMITTER_NAME": "BELIEF experiment",
    })
    for arguments in (
        ("init", "--quiet"),
        ("add", "."),
        ("commit", "--quiet", "-m", "pinned fixture"),
    ):
        completed = subprocess.run(
            ["git", "-C", str(root), *arguments],
            check=False,
            capture_output=True,
            env=env,
            timeout=15,
        )
        assert completed.returncode == 0, completed.stderr
    (root / "dirty.txt").write_text("dirty\n", encoding="utf-8")
    output = tmp_path / "experiment.json"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/prepare_susvibes_experiment.py",
            "--susvibes-root",
            str(root),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "dirty SusVibes checkout" in completed.stderr
    assert not output.exists()


@pytest.mark.parametrize(
    ("smoke", "canary", "batch", "message"),
    [
        (0, 3, 2, "cohort sizes"),
        (4, 3, 2, "cohort sizes"),
        (1, 31, 2, "cohort sizes"),
        (1, 3, 0, "batch_size"),
    ],
)
def test_manifest_rejects_invalid_sizes(
    tmp_path,
    smoke,
    canary,
    batch,
    message,
):
    dataset = _dataset(tmp_path)

    with pytest.raises(ValueError, match=message):
        build_susvibes_experiment_manifest(
            dataset,
            susvibes_commit=PINNED_COMMIT,
            smoke_size=smoke,
            canary_size=canary,
            batch_size=batch,
        )
