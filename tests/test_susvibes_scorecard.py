"""Contracts for official SusVibes score validation and comparison."""

from __future__ import annotations

import json
import subprocess
import sys
from copy import deepcopy
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    write_susvibes_experiment_manifest,
)
from belief.benchmark.susvibes_scorecard import (
    build_susvibes_official_scorecard,
    write_susvibes_official_scorecard,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
COMPARATORS = (
    ROOT
    / "benchmark_susvibes"
    / "security_comparators_2026-07-23.json"
)


def _experiment(
    tmp_path: Path,
    *,
    case_count: int = 5,
) -> tuple[Path, Path, dict]:
    dataset = tmp_path / "susvibes_dataset.jsonl"
    rows = [
        {
            "instance_id": f"owner__project_{index:040x}",
            "project": f"owner/project{index}",
            "base_commit": f"{index + 1:040x}",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": [f"CWE-{20 + index}"],
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
    manifest = tmp_path / "experiment.json"
    payload = write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit="a" * 40,
        smoke_size=1,
        canary_size=3,
        batch_size=2,
    )
    return dataset, manifest, payload


def _summary_payload(
    ids: list[str],
    *,
    func: list[str],
    sec: list[str],
    empty: list[str] = (),
    patch_error: list[str] = (),
    indeterminate: list[str] = (),
    submitted: int | None = None,
) -> dict:
    total = len(ids)
    return {
        "num_candidates": total,
        "num_submitted": total if submitted is None else submitted,
        "num_empty_model_patch": len(empty),
        "num_model_patch_errors": len(patch_error),
        "num_indeterminate": len(indeterminate),
        "func_pass": len(func) / total,
        "sec_pass": len(sec) / total,
        "details": {
            "empty_model_patch": list(empty),
            "model_patch_error": list(patch_error),
            "indeterminate": list(indeterminate),
            "completed": {
                "func_pass": list(func),
                "sec_pass": list(sec),
            },
        },
    }


def _write_summary(path: Path, payload: dict) -> Path:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def _two_run_fixture(
    tmp_path: Path,
) -> tuple[Path, Path, dict, Path, Path]:
    dataset, manifest, experiment = _experiment(tmp_path)
    ids = experiment["cohorts"]["full"]["instance_ids"]
    first = _write_summary(
        tmp_path / "summary-1.json",
        _summary_payload(
            ids,
            func=ids[:4],
            sec=ids[:2],
            empty=[ids[4]],
        ),
    )
    second = _write_summary(
        tmp_path / "summary-2.json",
        _summary_payload(
            ids,
            func=ids[:3],
            sec=ids[1:3],
            empty=[ids[4]],
            indeterminate=[ids[3]],
        ),
    )
    return dataset, manifest, experiment, first, second


def test_scorecard_validates_runs_stability_and_claim_boundaries(tmp_path):
    dataset, manifest, _experiment_payload, first, second = (
        _two_run_fixture(tmp_path)
    )

    payload = build_susvibes_official_scorecard(
        experiment_manifest=manifest,
        dataset=dataset,
        cohort="full",
        summaries=[first, second],
        labels=["repeat-a", "repeat-b"],
        comparators=COMPARATORS,
    )

    assert payload["experiment"]["case_count"] == 5
    assert payload["runs"][0]["counts"]["func_pass"] == 4
    assert payload["runs"][0]["counts"]["sec_pass"] == 2
    assert payload["runs"][0]["rates"]["sec_pass"] == 0.4
    assert payload["stability"]["sec_pass"]["mean"] == 0.4
    assert payload["stability"]["sec_pass_union_diagnostic"]["count"] == 3
    assert payload["stability"]["sec_pass_intersection"]["count"] == 1
    assert payload["stability"]["pairwise"][0]["sec_pass_jaccard"] == (
        pytest.approx(1 / 3, abs=1e-6)
    )
    fable = payload["comparators"]["numerical_secpass_references"][0]
    assert fable["minimum_sec_pass_count_to_numerically_exceed"] == 2
    assert (
        fable[
            "minimum_sec_pass_count_for_wilson_lower_bound_to_exceed"
        ]
        == 4
    )
    assert fable["all_runs_numerically_exceed"] is True
    assert fable["comparison_status"] == "numerical_only_different_protocol"
    assert fable["direct_win_claim_allowed"] is False
    context = payload["comparators"]["non_comparable_context"][0]
    assert context["metric"] == "known_cve_recall_pass_at_3"
    assert "per_run_delta_percentage_points" not in context
    boundary = payload["claim_boundary"]
    assert boundary["two_full_summary_artifacts_available"] is True
    assert boundary["independent_run_provenance_validated"] is False
    assert boundary["all_runs_without_indeterminate"] is False
    assert boundary["leaderboard_claim_allowed"] is False
    assert len(payload["report_digest"]) == 64


def test_canary_is_explicitly_not_score_bearing(tmp_path):
    dataset, manifest, experiment = _experiment(tmp_path)
    ids = experiment["cohorts"]["canary"]["instance_ids"]
    summary = _write_summary(
        tmp_path / "summary.json",
        _summary_payload(ids, func=ids, sec=ids[:1]),
    )

    payload = build_susvibes_official_scorecard(
        experiment_manifest=manifest,
        dataset=dataset,
        cohort="canary",
        summaries=[summary],
        comparators=COMPARATORS,
    )

    assert payload["claim_boundary"]["full_public_v1_cohort"] is False
    assert payload["claim_boundary"]["canary_is_score_bearing"] is False
    statuses = {
        value["comparison_status"]
        for value in payload["comparators"][
            "numerical_secpass_references"
        ]
    }
    assert statuses == {"engineering_cohort_not_score_bearing"}


def test_public_v1_fable_thresholds_are_explicit(tmp_path):
    dataset, manifest, experiment = _experiment(
        tmp_path,
        case_count=186,
    )
    ids = experiment["cohorts"]["full"]["instance_ids"]
    summary = _write_summary(
        tmp_path / "summary.json",
        _summary_payload(ids, func=ids, sec=ids[:54]),
    )

    payload = build_susvibes_official_scorecard(
        experiment_manifest=manifest,
        dataset=dataset,
        cohort="full",
        summaries=[summary],
        comparators=COMPARATORS,
    )

    fable = payload["comparators"]["numerical_secpass_references"][0]
    assert fable["minimum_sec_pass_count_to_numerically_exceed"] == 54
    assert (
        fable[
            "minimum_sec_pass_count_for_wilson_lower_bound_to_exceed"
        ]
        == 67
    )
    assert fable["all_runs_numerically_exceed"] is True
    assert fable["all_run_wilson_lower_bounds_exceed"] is False
    assert fable["direct_win_claim_allowed"] is False


def test_scorecard_rejects_secpass_outside_funcpass(tmp_path):
    dataset, manifest, experiment = _experiment(tmp_path)
    ids = experiment["cohorts"]["full"]["instance_ids"]
    summary = _write_summary(
        tmp_path / "summary.json",
        _summary_payload(
            ids,
            func=ids[:1],
            sec=ids[1:2],
            empty=ids[2:],
        ),
    )

    with pytest.raises(ValueError, match="subset of FuncPass"):
        build_susvibes_official_scorecard(
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            summaries=[summary],
        )


def test_scorecard_rejects_ratio_and_count_tampering(tmp_path):
    dataset, manifest, experiment = _experiment(tmp_path)
    ids = experiment["cohorts"]["full"]["instance_ids"]
    baseline = _summary_payload(
        ids,
        func=ids[:4],
        sec=ids[:2],
        empty=[ids[4]],
    )
    bad_rate = deepcopy(baseline)
    bad_rate["sec_pass"] = 0.99
    rate_path = _write_summary(tmp_path / "bad-rate.json", bad_rate)
    with pytest.raises(ValueError, match="SecPass ratio mismatch"):
        build_susvibes_official_scorecard(
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            summaries=[rate_path],
        )

    bad_count = deepcopy(baseline)
    bad_count["num_empty_model_patch"] = 0
    count_path = _write_summary(tmp_path / "bad-count.json", bad_count)
    with pytest.raises(ValueError, match="empty_model_patch count mismatch"):
        build_susvibes_official_scorecard(
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            summaries=[count_path],
        )


def test_scorecard_rejects_ids_outside_frozen_cohort(tmp_path):
    dataset, manifest, experiment = _experiment(tmp_path)
    ids = experiment["cohorts"]["full"]["instance_ids"]
    summary = _summary_payload(
        ids,
        func=ids[:4],
        sec=ids[:2],
        empty=[ids[4]],
    )
    summary["details"]["completed"]["sec_pass"][0] = "outside__case"
    path = _write_summary(tmp_path / "summary.json", summary)

    with pytest.raises(ValueError, match="outside the cohort"):
        build_susvibes_official_scorecard(
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            summaries=[path],
        )


def test_scorecard_writer_is_create_only(tmp_path):
    dataset, manifest, _experiment_payload, first, _second = (
        _two_run_fixture(tmp_path)
    )
    output = tmp_path / "scorecard.json"
    output.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_susvibes_official_scorecard(
            output,
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            summaries=[first],
            comparators=COMPARATORS,
        )

    assert output.read_text(encoding="utf-8") == "preserve\n"


def test_scorecard_cli_writes_validated_artifact(tmp_path):
    dataset, manifest, _experiment_payload, first, second = (
        _two_run_fixture(tmp_path)
    )
    output = tmp_path / "scorecard.json"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/score_susvibes_agent.py",
            "--experiment-manifest",
            str(manifest),
            "--dataset",
            str(dataset),
            "--cohort",
            "full",
            "--summary",
            str(first),
            "--summary",
            str(second),
            "--label",
            "repeat-a",
            "--label",
            "repeat-b",
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

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    scorecard = json.loads(output.read_text(encoding="utf-8"))
    assert summary["run_count"] == 2
    assert summary["sec_pass_mean"] == 0.4
    assert summary["leaderboard_claim_allowed"] is False
    assert summary["report_digest"] == scorecard["report_digest"]
