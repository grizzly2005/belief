"""Contracts for the nested SusVibes development/test split."""

from __future__ import annotations

import copy
import json
from collections import Counter
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    load_experiment_cohort,
    write_susvibes_experiment_manifest,
)
from scripts.prepare_susvibes_nested_split import (
    DEV_COHORT,
    PARENT_AUDIT_COHORT,
    TEST_COHORT,
    _file_sha256,
    _ids_sha256,
    build_nested_split_manifest,
    write_nested_split_manifest,
)


pytestmark = pytest.mark.security


def _dataset(tmp_path: Path, *, case_count: int = 14) -> Path:
    dataset = tmp_path / "susvibes_dataset.jsonl"
    rows = [
        {
            "instance_id": f"owner__project_{index:040x}",
            "project": f"owner/project-{index // 2}",
            "base_commit": f"{index + 1:040x}",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": [f"CWE-{100 + index % 5}"],
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
        newline="\n",
    )
    return dataset


def _parent_manifest(tmp_path: Path, dataset: Path) -> Path:
    output = tmp_path / "artifact-unseen.json"
    write_susvibes_experiment_manifest(
        dataset,
        output,
        susvibes_commit="a" * 40,
        smoke_size=1,
        canary_size=2,
        batch_size=4,
    )
    return output


def _baseline_result(
    tmp_path: Path,
    parent_manifest: Path,
    *,
    name: str = "baseline.json",
) -> tuple[Path, list[str], set[str]]:
    parent = json.loads(parent_manifest.read_text(encoding="utf-8"))
    parent_ids = parent["cohorts"]["holdout"]["instance_ids"]
    failed_ids = {parent_ids[1], parent_ids[-2]}
    payload = {
        "schema_version": "belief.susvibes_candidate_review.v1",
        "dataset_sha256": parent["dataset"]["sha256"],
        "case_count": len(parent_ids),
        "deterministic_digest": "b" * 64,
        "selection": {
            "instance_ids_sha256": _ids_sha256(parent_ids),
        },
        "reviewer_provenance": {
            "belief_python_source_sha256": "c" * 64,
        },
        "cases": [
            {
                "id": instance_id,
                "analysis_succeeded": instance_id not in failed_ids,
                "vulnerable_warned": index % 2 == 0,
                "secure_warning_false_positive": index % 3 == 0,
                "paired_warning_discriminated": index % 5 == 0,
                "findings": [f"ignored outcome {index}"],
            }
            for index, instance_id in enumerate(parent_ids)
        ],
    }
    output = tmp_path / name
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return output, parent_ids, failed_ids


def test_nested_split_is_exact_disjoint_and_forces_failures_to_dev(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline, parent_ids, failed_ids = _baseline_result(tmp_path, parent)

    payload = build_nested_split_manifest(
        dataset,
        parent,
        baseline,
        dev_size=6,
        batch_size=4,
    )

    dev_ids = payload["cohorts"][DEV_COHORT]["instance_ids"]
    test_ids = payload["cohorts"][TEST_COHORT]["instance_ids"]
    assert len(dev_ids) == len(test_ids) == 6
    assert not set(dev_ids) & set(test_ids)
    assert set(dev_ids) | set(test_ids) == set(parent_ids)
    assert failed_ids <= set(dev_ids)
    assert not failed_ids & set(test_ids)
    assert payload["cohorts"][PARENT_AUDIT_COHORT][
        "instance_ids"
    ] == parent_ids
    assert payload["nested_split_audit"][
        "forced_development_reconstruction_failure_count"
    ] == 2
    assert payload["boundaries"][
        "nested_test_case_details_inspected_before_split"
    ] is False


def test_nested_split_is_deterministic_and_cwe_balanced(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline, _, _ = _baseline_result(tmp_path, parent)

    first = build_nested_split_manifest(
        dataset,
        parent,
        baseline,
        dev_size=6,
    )
    second = build_nested_split_manifest(
        dataset,
        parent,
        baseline,
        dev_size=6,
    )

    assert first == second
    dev_coverage = first["cohorts"][DEV_COHORT]["coverage"]
    test_coverage = first["cohorts"][TEST_COHORT]["coverage"]
    metadata = first["evaluator_metadata"]
    parent_ids = first["cohorts"][PARENT_AUDIT_COHORT]["instance_ids"]
    dev_ids = first["cohorts"][DEV_COHORT]["instance_ids"]
    test_ids = first["cohorts"][TEST_COHORT]["instance_ids"]
    parent_strata = Counter(
        metadata[instance_id]["primary_cwe_stratum"]
        for instance_id in parent_ids
    )
    dev_strata = {
        metadata[instance_id]["primary_cwe_stratum"]
        for instance_id in dev_ids
    }
    test_strata = {
        metadata[instance_id]["primary_cwe_stratum"]
        for instance_id in test_ids
    }
    shareable_strata = {
        stratum
        for stratum, count in parent_strata.items()
        if count >= 2
    }

    # Singleton parent strata cannot occur in both child cohorts.
    assert len(parent_strata) == 5
    assert dev_strata | test_strata == set(parent_strata)
    assert shareable_strata <= dev_strata
    assert shareable_strata <= test_strata
    assert dev_coverage["primary_cwe_strata_count"] == len(dev_strata)
    assert test_coverage["primary_cwe_strata_count"] == len(test_strata)


def test_security_outcome_fields_do_not_influence_allocation(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline_a, _, _ = _baseline_result(
        tmp_path,
        parent,
        name="baseline-a.json",
    )
    payload_b = json.loads(baseline_a.read_text(encoding="utf-8"))
    for row in payload_b["cases"]:
        row["vulnerable_warned"] = not row["vulnerable_warned"]
        row["secure_warning_false_positive"] = not row[
            "secure_warning_false_positive"
        ]
        row["paired_warning_discriminated"] = not row[
            "paired_warning_discriminated"
        ]
        row["findings"] = ["different ignored security outcome"]
    baseline_b = tmp_path / "baseline-b.json"
    baseline_b.write_text(
        json.dumps(payload_b, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    first = build_nested_split_manifest(
        dataset,
        parent,
        baseline_a,
        dev_size=6,
    )
    second = build_nested_split_manifest(
        dataset,
        parent,
        baseline_b,
        dev_size=6,
    )

    assert first["cohorts"][DEV_COHORT] == second["cohorts"][DEV_COHORT]
    assert first["cohorts"][TEST_COHORT] == second["cohorts"][TEST_COHORT]
    assert first["nested_split_audit"][
        "baseline_security_outcomes_used"
    ] is False


def test_written_nested_cohorts_load_through_verified_loader(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline, _, _ = _baseline_result(tmp_path, parent)
    output = tmp_path / "nested.json"

    payload = write_nested_split_manifest(
        dataset,
        parent,
        baseline,
        output,
        dev_size=6,
    )
    dev_ids, dev_provenance = load_experiment_cohort(
        output,
        DEV_COHORT,
        dataset=dataset,
    )
    test_ids, test_provenance = load_experiment_cohort(
        output,
        TEST_COHORT,
        dataset=dataset,
    )

    assert dev_ids == payload["cohorts"][DEV_COHORT]["instance_ids"]
    assert test_ids == payload["cohorts"][TEST_COHORT]["instance_ids"]
    assert dev_provenance["manifest_digest"] == payload[
        "deterministic_digest"
    ]
    assert test_provenance["manifest_digest"] == payload[
        "deterministic_digest"
    ]


def test_nested_split_rejects_baseline_case_set_mismatch(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline, _, _ = _baseline_result(tmp_path, parent)
    payload = json.loads(baseline.read_text(encoding="utf-8"))
    payload["cases"][0]["id"] = "not-in-parent"
    baseline.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="do not match parent cohort"):
        build_nested_split_manifest(
            dataset,
            parent,
            baseline,
            dev_size=6,
        )


def test_writer_refuses_to_overwrite_nested_manifest(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline, _, _ = _baseline_result(tmp_path, parent)
    output = tmp_path / "nested.json"
    output.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_nested_split_manifest(
            dataset,
            parent,
            baseline,
            output,
            dev_size=6,
        )

    assert output.read_text(encoding="utf-8") == "preserve\n"


def test_nested_artifact_hash_rejects_outside_path(tmp_path):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_text("{}\n", encoding="utf-8")

    with pytest.raises(ValueError, match="escapes its allowed root"):
        _file_sha256(outside, allowed_root=allowed)


def test_analysis_status_is_the_only_baseline_case_value_used(tmp_path):
    dataset = _dataset(tmp_path)
    parent = _parent_manifest(tmp_path, dataset)
    baseline, _, _ = _baseline_result(tmp_path, parent)
    original = json.loads(baseline.read_text(encoding="utf-8"))
    changed = copy.deepcopy(original)
    for row in changed["cases"]:
        for key in list(row):
            if key not in {"id", "analysis_succeeded"}:
                row[key] = {"arbitrary": ["ignored", key]}
    alternate = tmp_path / "alternate.json"
    alternate.write_text(
        json.dumps(changed, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    first = build_nested_split_manifest(
        dataset,
        parent,
        baseline,
        dev_size=6,
    )
    second = build_nested_split_manifest(
        dataset,
        parent,
        alternate,
        dev_size=6,
    )

    assert first["cohorts"][DEV_COHORT] == second["cohorts"][DEV_COHORT]
    assert first["cohorts"][TEST_COHORT] == second["cohorts"][TEST_COHORT]
