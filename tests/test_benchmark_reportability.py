import json
import subprocess
import sys
from pathlib import Path

from belief.benchmark.metrics import compute_confusion_matrix, summarize_reportability_metrics
from belief.benchmark.reportability import (
    REPORTABILITY_MODE,
    VALID_EXPECTED_VERDICTS,
    evaluate_reportability_benchmark,
    load_benchmark_cases,
)


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = ROOT / "benchmark_reportability"


def test_benchmark_cases_load_and_cover_categories():
    cases = load_benchmark_cases(BENCHMARK_ROOT)

    assert len(cases) >= 7
    assert {case["category"] for case in cases} == {"idor", "mass_assignment", "path_traversal"}
    assert all(case["expected_verdict"] in VALID_EXPECTED_VERDICTS for case in cases)
    assert all((BENCHMARK_ROOT / case["fixture_path"]).exists() for case in cases)


def test_likely_false_positive_trap_is_represented():
    cases = load_benchmark_cases(BENCHMARK_ROOT)

    traps = [case for case in cases if case["expected_verdict"] == "likely_false_positive"]

    assert traps
    assert any(case["category"] == "idor" for case in traps)


def test_metrics_are_deterministic_and_conservative():
    first = evaluate_reportability_benchmark(BENCHMARK_ROOT)
    second = evaluate_reportability_benchmark(BENCHMARK_ROOT)

    assert first == second
    assert first["schema_version"] == "belief.benchmark_reportability.v1"
    assert first["mode"] == REPORTABILITY_MODE
    assert first["case_count"] >= 7
    assert first["metrics"]["matched_cases"] == first["case_count"]
    assert first["metrics"]["false_reportable_candidate_rate"] == 0
    assert first["metrics"]["protected_by_guard_rate"] > 0
    assert first["metrics"]["reportable_candidate_rate"] > 0


def test_protected_and_false_positive_cases_are_not_counted_as_reportable_candidates():
    cases = [
        {"expected_verdict": "protected_by_guard", "observed_verdict": "protected_by_guard"},
        {"expected_verdict": "likely_false_positive", "observed_verdict": "likely_false_positive"},
        {"expected_verdict": "reportable_candidate", "observed_verdict": "reportable_candidate"},
    ]

    metrics = summarize_reportability_metrics(cases)

    assert metrics["reportable_candidate_rate"] == round(1 / 3, 6)
    assert metrics["false_reportable_candidate_rate"] == 0


def test_confusion_matrix_counts_pairs_deterministically():
    matrix = compute_confusion_matrix(
        ["protected_by_guard", "reportable_candidate", "protected_by_guard"],
        ["protected_by_guard", "reportable_candidate", "reportable_candidate"],
    )

    assert matrix == {
        "protected_by_guard": {
            "protected_by_guard": 1,
            "reportable_candidate": 1,
        },
        "reportable_candidate": {
            "reportable_candidate": 1,
        },
    }


def test_cli_writes_json(tmp_path):
    output = tmp_path / "benchmark.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--target",
            str(BENCHMARK_ROOT),
            "--json-output",
            str(output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    summary = json.loads(result.stdout)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert summary["schema_version"] == "belief.benchmark_reportability.v1"
    assert summary["case_count"] == payload["case_count"]
    assert payload["mode"] == REPORTABILITY_MODE


def test_malformed_missing_benchmark_root_exits_with_code_2(tmp_path):
    output = tmp_path / "benchmark.json"
    missing = tmp_path / "missing"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--target",
            str(missing),
            "--json-output",
            str(output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 2
    assert "benchmark root does not exist" in result.stderr


def test_fixture_files_are_not_executed_or_imported(tmp_path):
    category = tmp_path / "idor"
    category.mkdir()
    (category / "fixture_that_must_not_run.py").write_text(
        "raise RuntimeError('fixture was executed')\n",
        encoding="utf-8",
    )
    (category / "cases.yml").write_text(
        "\n".join([
            "- id: safe-metadata-only-case",
            "  file: fixture_that_must_not_run.py",
            "  category: idor",
            "  expected_verdict: weak_signal",
            "  expected_min_score: 10",
            "  expected_evidence:",
            "    - synthetic metadata",
            "  expected_missing_evidence:",
            "    - manual validation",
            "  expected_playbook: idor_bola",
            "  should_not_include:",
            "    - confirmed exploit",
            "  notes: Verifies metadata loading does not execute fixture Python.",
            "",
        ]),
        encoding="utf-8",
    )

    payload = evaluate_reportability_benchmark(tmp_path)

    assert payload["case_count"] == 1
    assert payload["cases"][0]["observed_verdict"] == "weak_signal"
