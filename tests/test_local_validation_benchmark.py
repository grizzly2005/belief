"""Contracts for the separate eight-case local validation benchmark."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from belief.validation.benchmark import (
    load_local_validation_benchmark_corpus,
    run_local_validation_benchmark,
    write_local_validation_benchmark,
)
from belief.validation.execution_models import ValidationContractError


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmark_validation" / "cases.json"


def test_corpus_is_exact_transparent_eight_case_matrix():
    payload, cases = load_local_validation_benchmark_corpus(CORPUS)

    assert payload["schema_version"] == (
        "belief.local_validation_benchmark_corpus.v1"
    )
    assert len(cases) == 8
    assert {
        (case["case_type"], case["variant"])
        for case in cases
    } == {
        (family, variant)
        for family in (
            "path_traversal_possible",
            "idor_bola_possible",
        )
        for variant in (
            "vulnerable",
            "protected",
            "ambiguous",
            "trap",
        )
    }


def test_benchmark_improves_protected_false_positives_after_execution():
    payload = run_local_validation_benchmark(CORPUS)
    static = payload["stages"]["static_only"]
    planned = payload["stages"]["after_validation_plan"]
    validated = payload["stages"]["after_validation_result"]

    assert static["precision"] == 0.5
    assert static["recall"] == 1.0
    assert static["protected_false_positive_count"] == 2
    assert planned["abstention_rate"] == 0.75
    assert planned["protected_false_positive_count"] == 0
    assert validated["precision"] == 1.0
    assert validated["recall"] == 1.0
    assert validated["protected_false_positive_count"] == 0
    assert validated["false_negative_count"] == 0
    assert validated["abstention_rate"] == 0.25
    assert validated["evidence_gap_resolution_rate"] == 0.75
    assert validated["functional_regression_count"] == 0


def test_benchmark_outcomes_match_vulnerable_safe_and_ambiguous_cases():
    payload = run_local_validation_benchmark(CORPUS)
    outcomes = {
        item["benchmark_case_id"]: item["validation_outcome"]
        for item in payload["case_results"]
    }

    assert outcomes == {
        "path_vulnerable": "bypassed",
        "path_protected": "enforced",
        "path_ambiguous": "inconclusive",
        "path_trap": "enforced",
        "idor_vulnerable": "bypassed",
        "idor_protected": "enforced",
        "idor_ambiguous": "inconclusive",
        "idor_trap": "enforced",
    }


def test_benchmark_is_semantically_stable_and_not_secpass():
    payload = run_local_validation_benchmark(CORPUS)

    assert payload["semantic_stability"] == {
        "identical_repeated_execution": True,
        "first_digest": payload["semantic_stability"]["first_digest"],
        "second_digest": payload["semantic_stability"]["first_digest"],
    }
    assert payload["validation_metrics"]["secpass_equivalent"] is False
    assert payload["boundaries"]["secpass_claimed"] is False
    assert payload["boundaries"]["leaderboard_comparison_claimed"] is False
    assert payload["boundaries"]["reserved_holdout_opened"] is False


def test_benchmark_does_not_open_susvibes_or_use_network(
    monkeypatch,
):
    opened: list[Path] = []
    original_read = Path.read_text

    def record_read(path: Path, *args, **kwargs):
        opened.append(path.resolve())
        return original_read(path, *args, **kwargs)

    def reject_network(*_args, **_kwargs):
        raise AssertionError("local benchmark attempted network access")

    monkeypatch.setattr(Path, "read_text", record_read)
    monkeypatch.setattr(socket.socket, "connect", reject_network)

    payload = run_local_validation_benchmark(CORPUS)

    assert payload["boundaries"]["network_used"] is False
    assert opened
    assert not any(
        "benchmark_susvibes" in path.parts for path in opened
    )


def test_benchmark_writer_is_create_only(tmp_path):
    output = tmp_path / "benchmark.json"

    written = write_local_validation_benchmark(
        output,
        corpus_path=CORPUS,
    )
    assert json.loads(output.read_text(encoding="utf-8")) == written
    with pytest.raises(
        ValidationContractError,
        match="refusing to overwrite",
    ):
        write_local_validation_benchmark(
            output,
            corpus_path=CORPUS,
        )


def test_benchmark_script_writes_reproducible_report(tmp_path):
    output = tmp_path / "benchmark.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "benchmark_local_validation.py"),
            "--corpus",
            str(CORPUS),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    report = json.loads(output.read_text(encoding="utf-8"))
    assert summary["case_count"] == 8
    assert summary["semantic_stability"] is True
    assert report["stages"]["after_validation_result"][
        "precision"
    ] == 1.0
