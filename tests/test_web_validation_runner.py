"""Tests for the frozen transparent web-validation static runner."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from belief.audit_case import AuditCase
from belief.benchmark import web_validation_runner as runner
from belief.validation.plan_models import canonical_digest


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmark_web_validation"
MANIFEST_PATH = CORPUS / "development" / "cases.json"
PREREGISTRATION_PATH = CORPUS / "preregistration.json"
RESULT_PATH = (
    ROOT
    / "benchmark_web_validation_results"
    / "development-static.json"
)


def _manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _preregistration() -> dict:
    return json.loads(
        PREREGISTRATION_PATH.read_text(encoding="utf-8")
    )


def test_runner_policy_and_digest_are_frozen():
    policy = runner._runner_policy()

    assert policy["cohort"] == "development"
    assert policy["repetitions"] == 2
    assert policy["classification"] == {
        "conflicting_status_groups": "abstain",
        "ground_truth_not_used_for_prediction": True,
        "no_matching_case": "safe",
        "positive_statuses": ["actionable", "needs_review"],
        "safe_statuses": [
            "false_positive_likely",
            "protected",
        ],
        "unknown_status": "abstain",
    }
    assert policy["plan_scope"]["execution_binding_created"] is False
    assert all(
        value is False
        for value in policy["boundaries"].values()
    )
    assert (
        canonical_digest(policy)
        == runner.WEB_VALIDATION_STATIC_RUNNER_POLICY_DIGEST
    )


@pytest.mark.parametrize(
    ("statuses", "expected"),
    (
        ((), "safe"),
        (("actionable",), "candidate"),
        (("needs_review",), "candidate"),
        (("protected",), "safe"),
        (("false_positive_likely",), "safe"),
        (("needs_review", "protected"), "abstain"),
        (("future_status",), "abstain"),
    ),
)
def test_static_prediction_is_evidence_only(statuses, expected):
    assert runner._static_prediction(statuses) == expected


def test_metric_formulas_penalize_vulnerable_abstention():
    rows = [
        {
            "ground_truth": "vulnerable",
            "observed_static_class": "candidate",
            "matching_audit_case_count": 1,
            "plan_count": 1,
        },
        {
            "ground_truth": "vulnerable",
            "observed_static_class": "abstain",
            "matching_audit_case_count": 1,
            "plan_count": 1,
        },
        {
            "ground_truth": "safe",
            "observed_static_class": "candidate",
            "matching_audit_case_count": 1,
            "plan_count": 1,
        },
        {
            "ground_truth": "safe",
            "observed_static_class": "safe",
            "matching_audit_case_count": 0,
            "plan_count": 0,
        },
        {
            "ground_truth": "ambiguous",
            "observed_static_class": "abstain",
            "matching_audit_case_count": 1,
            "plan_count": 1,
        },
    ]

    metrics = runner._static_metrics(rows)

    assert metrics["confusion"] == {
        "true_positive": 1,
        "false_positive": 1,
        "true_negative": 1,
        "false_negative": 1,
        "binary_abstention": 1,
    }
    assert metrics["static_precision"] == 0.5
    assert metrics["static_recall"] == 0.5
    assert metrics["static_binary_accuracy"] == 0.5
    assert metrics["ambiguous_abstention_rate"] == 1.0
    assert metrics["plan_generation_coverage"] == 1.0
    assert metrics["executable_plan_coverage"] is None
    gates = runner._gate_evaluations(metrics)
    assert gates["maximum_abstention_rate"]["status"] == "fail"
    assert gates["minimum_executable_plan_coverage"][
        "status"
    ] == "not_measured"


def test_matching_audit_case_generates_unbound_plan():
    case = _manifest()["cases"][0]
    audit_case = AuditCase(
        case_id="case_runner_test",
        case_type=str(case["case_type"]),
        status="needs_review",
        review_priority="high",
        confidence=0.8,
        severity="high",
        file=_pure_path_name(case["source_path"]),
        line=17,
        rule_id="RUNNER_TEST",
        cwe=(
            "CWE-22"
            if case["case_type"] == "path_traversal_possible"
            else "CWE-639"
        ),
        source="request.input",
        sink="security.boundary",
        missing_guarantees=("runtime enforcement",),
    )

    result = runner._case_result(
        case,
        records=(),
        audit_cases=(audit_case,),
        diagnostics=(),
    )

    assert result["observed_static_class"] == "candidate"
    assert result["plan_count"] == 1
    assert result["plans"][0]["execution_bound"] is False
    assert result["execution_binding_created"] is False


def test_manifest_guard_rejects_non_development_path():
    manifest = _manifest()
    manifest["cases"][0]["source_path"] = "../reserved/hidden.py"

    with pytest.raises(
        ValueError,
        match="identity or path is invalid",
    ):
        runner._validated_manifest_cases(
            manifest,
            _preregistration(),
        )


def test_evaluator_is_closed_over_bundled_sources_and_uses_no_open_world(
    monkeypatch,
):
    calls = []
    source_root = CORPUS / "development" / "sources"
    files = tuple(
        source_root / _pure_path_name(case["source_path"])
        for case in _manifest()["cases"]
    )

    def fake_scan(target, options):
        calls.append((Path(target).resolve(), options))
        return SimpleNamespace(
            files=files,
            filtered_records=(),
            audit_cases=(),
            diagnostics=(),
            totals={
                name: 0
                for name in (
                    "structural",
                    "security",
                    "taint",
                    "temporal",
                )
            },
        )

    def reject(*_args, **_kwargs):
        raise AssertionError("unexpected open-world runner capability")

    monkeypatch.setattr(runner, "analyze_static_target", fake_scan)
    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(subprocess, "run", reject)
    monkeypatch.setattr(subprocess, "Popen", reject)

    result = runner.evaluate_web_validation_development()

    assert len(calls) == 2
    assert all(target == source_root.resolve() for target, _ in calls)
    assert all(options.import_tool_results == () for _, options in calls)
    assert result["metrics"]["case_count"] == 32
    assert result["metrics"]["static_recall"] == 0.0
    assert result["reproducibility"]["identical"] is True
    assert result["execution_boundaries"]["reserved_source_opened"] is False


def test_writer_is_create_only_and_refuses_corpus_destination(
    monkeypatch,
    tmp_path,
):
    payload = {
        "deterministic_digest": "a" * 64,
        "metrics": {"case_count": 0},
    }
    monkeypatch.setattr(
        runner,
        "evaluate_web_validation_development",
        lambda: payload,
    )
    output = tmp_path / "result.json"

    assert (
        runner.write_web_validation_development_result(output)
        == payload
    )
    with pytest.raises(ValueError, match="refusing to overwrite"):
        runner.write_web_validation_development_result(output)
    with pytest.raises(ValueError, match="outside the corpus"):
        runner.write_web_validation_development_result(
            CORPUS / "result.json"
        )


def test_cli_rejects_existing_output_before_analysis(tmp_path):
    output = tmp_path / "existing.json"
    output.write_text("unchanged\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_web_validation_development.py"),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "refusing to overwrite" in completed.stderr
    assert output.read_text(encoding="utf-8") == "unchanged\n"


def test_committed_negative_baseline_is_digest_bound_and_non_executing():
    payload = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    unsigned = dict(payload)
    expected_digest = unsigned.pop("deterministic_digest")

    assert canonical_digest(unsigned) == expected_digest
    assert (
        payload["runner_policy_digest"]
        == runner.WEB_VALIDATION_STATIC_RUNNER_POLICY_DIGEST
    )
    assert payload["metrics"]["static_precision"] == 0.0
    assert payload["metrics"]["static_recall"] == 0.0
    assert payload["gate_evaluations"]["minimum_static_precision"][
        "status"
    ] == "fail"
    assert payload["gate_evaluations"]["minimum_static_recall"][
        "status"
    ] == "fail"
    assert payload["reproducibility"]["identical"] is True
    assert payload["execution_boundaries"][
        "validation_plans_executed"
    ] is False
    assert payload["execution_boundaries"]["reserved_source_opened"] is False
    assert payload["execution_boundaries"][
        "susvibes_artifacts_opened"
    ] is False


def _pure_path_name(value: str) -> str:
    return str(value).replace("\\", "/").rsplit("/", 1)[-1]
