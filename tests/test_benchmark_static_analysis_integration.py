"""End-to-end contracts for the real benchmark and shared pipeline."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark.static_analysis import evaluate_static_analysis_benchmark
from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = ROOT / "benchmark_static_analysis"


def _pipeline_options() -> StaticAnalysisOptions:
    return StaticAnalysisOptions(
        selected_categories=frozenset({"security", "taint"}),
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        show_dataflow=True,
        include_audit_cases=True,
        audit_mode=True,
        include_routes=True,
        reportability=True,
    )


def _real_pipeline(target: Path):
    return analyze_static_target(target, _pipeline_options())


def test_real_eight_case_corpus_passes_through_common_pipeline_deterministically():
    first = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, _real_pipeline)
    second = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, _real_pipeline)

    assert first["schema_version"] == "belief.static_analysis_benchmark.v1"
    assert first["mode"] == "static_analysis_ground_truth_v1"
    assert first["status"] == "passed"
    assert first["exit_code"] == 0
    assert first["metrics"]["case_count"] == 8
    assert first["metrics"]["matched_verdict_count"] == 6
    assert first["metrics"]["verdict_accuracy"] == 0.75
    assert first["metrics"]["vulnerable_case_detection_rate"] == 1.0
    assert first["metrics"]["protected_case_false_positive_rate"] == 0.0
    assert first["metrics"]["expected_no_case_accuracy"] == 1.0
    assert all(row["analysis_succeeded"] for row in first["cases"])
    assert all(
        row["verdict_matched"]
        or row["field_matches"].get("expected_no_audit_case") is True
        for row in first["cases"]
    )
    observed_cases = [
        row for row in first["cases"]
        if not row["expected"].get("expected_no_audit_case")
    ]
    assert all(row["field_matches"]["vulnerability_type"] for row in observed_cases)
    assert all(row["field_matches"]["file"] for row in observed_cases)
    assert all(row["field_matches"]["source"] for row in observed_cases)
    assert all(row["field_matches"]["sink"] for row in observed_cases)
    assert any(not row["matched"] for row in observed_cases)
    assert first["deterministic_digest"] == second["deterministic_digest"]


def test_cli_real_benchmark_writes_actual_results_and_passes(tmp_path):
    output = tmp_path / "real-benchmark.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--mode",
            "static_analysis_ground_truth_v1",
            "--target",
            str(BENCHMARK_ROOT),
            "--thresholds",
            str(BENCHMARK_ROOT / "thresholds.yml"),
            "--json-output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert summary["status"] == "passed"
    assert summary["deterministic_digest"] == payload["deterministic_digest"]
    assert payload["metrics"]["case_count"] == 8


def test_cli_real_benchmark_exits_nonzero_when_thresholds_fail(tmp_path):
    thresholds = tmp_path / "strict-thresholds.yml"
    thresholds.write_text(
        "\n".join([
            "minimum_verdict_accuracy: 1.0",
            "minimum_vulnerable_detection_rate: 1.0",
            "maximum_protected_false_positive_rate: 0.0",
            "minimum_expected_no_case_accuracy: 1.0",
            "",
        ]),
        encoding="utf-8",
    )
    output = tmp_path / "failed-benchmark.json"
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--mode",
            "static_analysis_ground_truth_v1",
            "--target",
            str(BENCHMARK_ROOT),
            "--thresholds",
            str(thresholds),
            "--json-output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "failed"
    assert payload["thresholds_passed"] is False
    assert payload["threshold_evaluation"]["minimum_verdict_accuracy"]["passed"] is False
