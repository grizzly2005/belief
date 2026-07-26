"""Contracts for the independent PatchEval-Verified split."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from belief.benchmark.patcheval_experiment import (
    PATCHEVAL_EXPERIMENT_ALGORITHM,
    build_patcheval_experiment_manifest,
    load_patcheval_development_cohort,
    validate_patcheval_experiment_manifest,
    write_patcheval_experiment_manifest,
)


pytestmark = pytest.mark.security

UPSTREAM_COMMIT = "a" * 40
BELIEF_COMMIT = "b" * 40
PREPARATION_COMMIT = "c" * 40


def _record(index: int, repository: str, *, language: str = "Python"):
    case_id = f"CVE-2099-{index:05d}"
    return {
        "cve_id": case_id,
        "cve_description": f"secret description {index}",
        "cwe_info": [{"id": f"CWE-{index}"}],
        "repo": f"https://github.com/{repository}",
        "patch_url": (
            f"https://github.com/{repository}/commit/{index:040x}"
        ),
        "programing_language": language,
        "vul_func": f"vulnerable_{index}",
        "fix_func": f"fixed_{index}",
        "image_url": f"ghcr.io/example/case-{index}",
    }


def _inputs(
    tmp_path: Path,
    *,
    repository_count: int = 10,
):
    dataset = tmp_path / "patcheval_verified.json"
    susvibes = tmp_path / "susvibes.jsonl"
    protocol = tmp_path / "protocol.md"
    records = [
        _record(index, f"independent/project-{index}")
        for index in range(repository_count)
    ]
    records.extend([
        _record(90_001, "overlap/project"),
        _record(90_002, "ignored/javascript", language="JavaScript"),
    ])
    dataset.write_text(
        json.dumps(records, indent=2),
        encoding="utf-8",
    )
    susvibes.write_text(
        json.dumps({"project": "overlap/project"}) + "\n",
        encoding="utf-8",
    )
    protocol.write_text("frozen protocol\n", encoding="utf-8")
    return dataset, susvibes, protocol


def _build(tmp_path: Path, *, repository_count: int = 10):
    dataset, susvibes, protocol = _inputs(
        tmp_path,
        repository_count=repository_count,
    )
    payload = build_patcheval_experiment_manifest(
        dataset,
        susvibes,
        protocol,
        upstream_commit=UPSTREAM_COMMIT,
        belief_starting_commit=BELIEF_COMMIT,
        preparation_commit=PREPARATION_COMMIT,
    )
    return payload, dataset, susvibes, protocol


def test_patcheval_split_is_deterministic_and_project_disjoint(tmp_path):
    first, dataset, susvibes, protocol = _build(tmp_path)
    second = build_patcheval_experiment_manifest(
        dataset,
        susvibes,
        protocol,
        upstream_commit=UPSTREAM_COMMIT,
        belief_starting_commit=BELIEF_COMMIT,
        preparation_commit=PREPARATION_COMMIT,
    )

    assert first == second
    assert (
        first["selection_algorithm"]
        == PATCHEVAL_EXPERIMENT_ALGORITHM
    )
    assert first["source"]["python_record_count"] == 11
    assert first["selection"]["eligible_case_count"] == 10
    assert first["susvibes_exclusion"]["excluded_case_count"] == 1
    development = first["cohorts"]["development"]
    reserved = first["cohorts"]["reserved"]
    assert development["repository_count"] == 6
    assert reserved["repository_count"] == 4
    assert not set(development["case_ids"]) & set(reserved["case_ids"])


def test_patcheval_manifest_does_not_copy_reference_metadata(tmp_path):
    payload, _dataset, _susvibes, _protocol = _build(tmp_path)
    serialized = json.dumps(payload, sort_keys=True)

    assert "secret description" not in serialized
    assert "patch_url" not in serialized
    assert "vul_func" not in serialized
    assert "fix_func" not in serialized
    assert "image_url" not in serialized
    assert "independent/project" not in serialized
    assert "overlap/project" not in serialized


def test_patcheval_manifest_validates_and_detaches(tmp_path):
    payload, _dataset, _susvibes, _protocol = _build(tmp_path)

    validated = validate_patcheval_experiment_manifest(payload)

    assert validated == payload
    assert validated is not payload


def test_patcheval_manifest_rejects_tampering(tmp_path):
    payload, _dataset, _susvibes, _protocol = _build(tmp_path)
    changed = copy.deepcopy(payload)
    changed["cohorts"]["development"]["case_ids"].pop()

    with pytest.raises(ValueError, match="digest mismatch"):
        validate_patcheval_experiment_manifest(changed)


def test_patcheval_writer_is_create_only(tmp_path):
    _payload, dataset, susvibes, protocol = _build(tmp_path)
    output = tmp_path / "manifest.json"

    written = write_patcheval_experiment_manifest(
        dataset,
        susvibes,
        protocol,
        output,
        upstream_commit=UPSTREAM_COMMIT,
        belief_starting_commit=BELIEF_COMMIT,
        preparation_commit=PREPARATION_COMMIT,
    )
    original = output.read_bytes()

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_patcheval_experiment_manifest(
            dataset,
            susvibes,
            protocol,
            output,
            upstream_commit=UPSTREAM_COMMIT,
            belief_starting_commit=BELIEF_COMMIT,
            preparation_commit=PREPARATION_COMMIT,
        )
    assert output.read_bytes() == original
    assert json.loads(original)["deterministic_digest"] == written[
        "deterministic_digest"
    ]


def test_patcheval_development_loader_rebuilds_inputs(tmp_path):
    payload, dataset, susvibes, protocol = _build(tmp_path)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )

    case_ids, provenance = load_patcheval_development_cohort(
        manifest,
        dataset=dataset,
        susvibes_dataset=susvibes,
        protocol=protocol,
    )

    assert case_ids == payload["cohorts"]["development"]["case_ids"]
    assert provenance["cohort"] == "development"
    protocol.write_text("changed protocol\n", encoding="utf-8")
    with pytest.raises(ValueError, match="frozen inputs or split changed"):
        load_patcheval_development_cohort(
            manifest,
            dataset=dataset,
            susvibes_dataset=susvibes,
            protocol=protocol,
        )


def test_patcheval_minimums_require_both_cohorts(tmp_path):
    payload, _dataset, _susvibes, _protocol = _build(
        tmp_path,
        repository_count=60,
    )

    assert payload["cohorts"]["development"]["case_count"] == 36
    assert payload["cohorts"]["reserved"]["case_count"] == 24
    assert payload["eligible_for_architecture_tuning"] is True


def test_patcheval_rejects_duplicate_python_case_ids(tmp_path):
    dataset, susvibes, protocol = _inputs(tmp_path)
    records = json.loads(dataset.read_text(encoding="utf-8"))
    records.append(copy.deepcopy(records[0]))
    dataset.write_text(json.dumps(records), encoding="utf-8")

    with pytest.raises(ValueError, match="case IDs must be unique"):
        build_patcheval_experiment_manifest(
            dataset,
            susvibes,
            protocol,
            upstream_commit=UPSTREAM_COMMIT,
            belief_starting_commit=BELIEF_COMMIT,
            preparation_commit=PREPARATION_COMMIT,
        )
