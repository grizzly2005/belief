"""Closed-corpus checks for the exploration-objective research pilot."""

from __future__ import annotations

import copy
import importlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from belief.exploration import (
    ExplorationBenchmarkError,
    load_exploration_pilot_corpus,
    run_exploration_pilot_benchmark,
    write_exploration_pilot_benchmark,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "research" / "duck_path_objective_pilot" / "cases.json"


def test_corpus_is_exact_three_outcome_synthetic_matrix():
    payload, cases = load_exploration_pilot_corpus(CORPUS)

    assert payload["schema_version"] == "belief.exploration_pilot_corpus.v1"
    assert len(cases) == 3
    assert {case.path_artifact.outcome for case in cases} == {
        "plausible_path_artifact",
        "no_plausible_path",
        "inconclusive",
    }
    assert {case.expected_interpretation for case in cases} == {
        "supported",
        "refuted",
        "inconclusive",
    }


def test_benchmark_compares_expected_labels_and_preserves_abstention():
    report = run_exploration_pilot_benchmark(CORPUS)

    assert report["metrics"] == {
        "case_count": 3,
        "correct_count": 3,
        "accuracy": 1.0,
        "supported_count": 1,
        "refuted_count": 1,
        "inconclusive_count": 1,
        "abstention_count": 1,
        "abstention_rate": 0.333333,
    }
    assert all(row["matched"] for row in report["case_results"])
    assert all(not row["confirms_vulnerability"] for row in report["case_results"])
    assert report["semantic_stability"]["identical_repeated_evaluation"] is True


def test_benchmark_boundaries_make_no_external_or_leaderboard_claim():
    boundaries = run_exploration_pilot_benchmark(CORPUS)["boundaries"]

    assert boundaries == {
        "synthetic_corpus": True,
        "artifact_import_only": True,
        "external_tool_executed": False,
        "external_code_executed": False,
        "network_used": False,
        "subprocess_used": False,
        "shell_used": False,
        "compiler_used": False,
        "dynamic_import_used": False,
        "duck_wire_compatibility_verified": False,
        "vulnerability_confirmation_claimed": False,
        "leaderboard_comparison_claimed": False,
    }


def test_expected_labels_are_actually_scored(tmp_path):
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    tampered = copy.deepcopy(payload)
    tampered["cases"][0]["expected_interpretation"] = "refuted"
    tampered["cases"][1]["expected_interpretation"] = "supported"
    corpus = tmp_path / "swapped-labels.json"
    corpus.write_text(json.dumps(tampered), encoding="utf-8")

    report = run_exploration_pilot_benchmark(corpus)

    assert report["metrics"]["correct_count"] == 1
    assert report["metrics"]["accuracy"] == 0.333333


def test_benchmark_attempts_no_network_process_shell_or_dynamic_import(monkeypatch):
    def reject(*_args, **_kwargs):
        raise AssertionError("exploration pilot crossed a forbidden boundary")

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(subprocess, "run", reject)
    monkeypatch.setattr(subprocess, "Popen", reject)
    monkeypatch.setattr(os, "system", reject)
    monkeypatch.setattr(importlib, "import_module", reject)

    report = run_exploration_pilot_benchmark(CORPUS)

    assert report["metrics"]["case_count"] == 3


def test_corpus_loader_rejects_duplicate_json_keys_and_unknown_fields(tmp_path):
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"belief.exploration_pilot_corpus.v1",'
        '"schema_version":"belief.exploration_pilot_corpus.v1","cases":[]}',
        encoding="utf-8",
    )
    with pytest.raises(ExplorationBenchmarkError, match="duplicate"):
        load_exploration_pilot_corpus(duplicate)

    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    payload["unknown"] = True
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ExplorationBenchmarkError, match="fields mismatch"):
        load_exploration_pilot_corpus(unknown)


def test_corpus_loader_is_size_bounded(tmp_path):
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * 257)

    with pytest.raises(ExplorationBenchmarkError, match="exceeds 256 byte limit"):
        load_exploration_pilot_corpus(oversized, max_bytes=256)


def test_benchmark_writer_is_create_only_and_portable(tmp_path):
    output = tmp_path / "report.json"

    written = write_exploration_pilot_benchmark(output, corpus_path=CORPUS)

    assert json.loads(output.read_text(encoding="utf-8")) == written
    assert b"\r\n" not in output.read_bytes()
    with pytest.raises(ExplorationBenchmarkError, match="refusing to overwrite"):
        write_exploration_pilot_benchmark(output, corpus_path=CORPUS)


def test_benchmark_script_writes_reproducible_report(tmp_path):
    output = tmp_path / "report.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "benchmark_exploration_objective.py"),
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
    assert summary["case_count"] == 3
    assert summary["correct_count"] == 3
    assert summary["abstention_count"] == 1
    assert summary["deterministic_digest"] == report["deterministic_digest"]


def test_benchmark_digest_is_stable():
    first = run_exploration_pilot_benchmark(CORPUS)
    second = run_exploration_pilot_benchmark(CORPUS)

    assert first == second
    assert first["corpus"]["sha256"] == (
        "7cb2d7c439938fcf242d95bc4099d75e56327762d79d005b8937cbd1f8be0555"
    )
    assert first["deterministic_digest"] == (
        "d46ec7160f42911ddf743ec26169796d9c9807d32824e9f51660b7db31866679"
    )
    assert first["deterministic_digest"] == second["deterministic_digest"]
