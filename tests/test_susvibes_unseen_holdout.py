"""Contracts for artifact-unseen SusVibes holdout derivation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    load_experiment_cohort,
    write_susvibes_experiment_manifest,
)
from scripts.prepare_susvibes_unseen_holdout import (
    DERIVED_COHORT,
    _file_sha256,
    derive_unseen_holdout_manifest,
    write_unseen_holdout_manifest,
)


pytestmark = pytest.mark.security


def _dataset(tmp_path: Path, *, case_count: int = 10) -> Path:
    dataset = tmp_path / "susvibes_dataset.jsonl"
    rows = [
        {
            "instance_id": f"owner__project_{index:040x}",
            "project": f"owner/project-{index}",
            "base_commit": f"{index + 1:040x}",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": [f"CWE-{100 + index}"],
            "language": "python",
            "image_name": f"example/image:{index}",
            "problem_statement": f"Implement feature {index}.",
        }
        for index in range(case_count)
    ]
    dataset.write_text(
        "".join(
            json.dumps(row, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    return dataset


def _parent_manifest(tmp_path: Path, dataset: Path) -> Path:
    path = tmp_path / "experiment.json"
    write_susvibes_experiment_manifest(
        dataset,
        path,
        susvibes_commit="a" * 40,
        smoke_size=1,
        canary_size=3,
        batch_size=4,
    )
    return path


def _prior_results(
    tmp_path: Path,
    parent_manifest: Path,
) -> tuple[Path, list[str]]:
    parent = json.loads(parent_manifest.read_text(encoding="utf-8"))
    canary_id = parent["cohorts"]["canary"]["instance_ids"][0]
    holdout_ids = parent["cohorts"]["holdout"]["instance_ids"]
    results = tmp_path / "results"
    results.mkdir()
    (results / "run-a.json").write_text(
        json.dumps(
            {
                "mode": "susvibes_candidate_review_v1",
                "cases": [
                    {
                        "id": canary_id,
                        "findings": ["must never enter derived manifest"],
                    },
                    {"id": holdout_ids[0]},
                    {"id": holdout_ids[1]},
                ],
            }
        ),
        encoding="utf-8",
    )
    (results / "run-b.json").write_text(
        json.dumps(
            {
                "mode": "susvibes_paired_static_v1",
                "cases": [
                    {"instance_id": holdout_ids[1]},
                    {"id": "not-in-parent"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (results / "unrelated.json").write_text(
        json.dumps({"status": "passed"}),
        encoding="utf-8",
    )
    return results, holdout_ids


def test_derivation_excludes_every_prior_result_case_id(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results, parent_holdout = _prior_results(tmp_path, parent_manifest)

    payload = derive_unseen_holdout_manifest(
        dataset,
        parent_manifest,
        results,
        batch_size=2,
    )

    cohort = payload["cohorts"][DERIVED_COHORT]
    assert cohort["case_count"] == len(parent_holdout) - 2
    assert cohort["instance_ids"] == parent_holdout[2:]
    assert payload["cohorts"]["parent_holdout"]["instance_ids"] == (
        parent_holdout
    )
    audit = payload["novelty_audit"]
    assert audit["prior_artifact_count"] == 2
    assert audit["observed_parent_full_case_count"] == 3
    assert audit["observed_parent_holdout_case_count"] == 2
    assert audit["artifact_unseen_holdout_case_count"] == 5
    assert audit["dataset_case_records_loaded"] is False
    assert audit["prior_result_json_loaded"] is True
    assert audit["prior_result_findings_used"] is False
    assert "must never enter" not in json.dumps(payload)
    assert len(payload["artifact_unseen_holdout_batches"]) == 3
    assert payload["holdout_batches"] == (
        payload["artifact_unseen_holdout_batches"]
    )


def test_derived_manifest_loads_through_verified_cohort_loader(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results, _ = _prior_results(tmp_path, parent_manifest)
    output = tmp_path / "unseen.json"

    payload = write_unseen_holdout_manifest(
        dataset,
        parent_manifest,
        results,
        output,
    )
    instance_ids, provenance = load_experiment_cohort(
        output,
        DERIVED_COHORT,
        dataset=dataset,
    )

    assert instance_ids == payload["cohorts"][DERIVED_COHORT]["instance_ids"]
    assert provenance["cohort"] == DERIVED_COHORT
    assert provenance["manifest_digest"] == payload["deterministic_digest"]


def test_derived_manifest_is_deterministic(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results, _ = _prior_results(tmp_path, parent_manifest)

    first = derive_unseen_holdout_manifest(
        dataset,
        parent_manifest,
        results,
    )
    second = derive_unseen_holdout_manifest(
        dataset,
        parent_manifest,
        results,
    )

    assert first == second


def test_replay_index_ignores_later_results_and_verifies_hashes(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results, parent_holdout = _prior_results(tmp_path, parent_manifest)
    first = derive_unseen_holdout_manifest(
        dataset,
        parent_manifest,
        results,
    )
    replay_index = tmp_path / "replay-index.json"
    replay_index.write_text(
        json.dumps(first, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (results / "later-run.json").write_text(
        json.dumps({"cases": [{"id": parent_holdout[-1]}]}),
        encoding="utf-8",
    )

    replayed = derive_unseen_holdout_manifest(
        dataset,
        parent_manifest,
        results,
        replay_artifact_index=replay_index,
    )

    assert replayed == first
    (results / "run-a.json").write_text("tampered\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash mismatch"):
        derive_unseen_holdout_manifest(
            dataset,
            parent_manifest,
            results,
            replay_artifact_index=replay_index,
        )


def test_writer_refuses_to_overwrite_derived_manifest(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results, _ = _prior_results(tmp_path, parent_manifest)
    output = tmp_path / "unseen.json"
    output.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_unseen_holdout_manifest(
            dataset,
            parent_manifest,
            results,
            output,
        )

    assert output.read_text(encoding="utf-8") == "preserve\n"


def test_derivation_requires_prior_susvibes_case_rows(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results = tmp_path / "results"
    results.mkdir()
    (results / "unrelated.json").write_text(
        json.dumps({"status": "passed"}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="no prior SusVibes result"):
        derive_unseen_holdout_manifest(
            dataset,
            parent_manifest,
            results,
        )


def test_derivation_rejects_an_invalid_prior_json_artifact(tmp_path):
    dataset = _dataset(tmp_path)
    parent_manifest = _parent_manifest(tmp_path, dataset)
    results, _ = _prior_results(tmp_path, parent_manifest)
    (results / "truncated.json").write_text("{", encoding="utf-8")

    with pytest.raises(ValueError, match="invalid result artifact"):
        derive_unseen_holdout_manifest(
            dataset,
            parent_manifest,
            results,
        )


def test_artifact_hash_rejects_a_path_outside_the_allowed_root(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes its allowed root"):
        _file_sha256(outside, allowed_root=allowed)
