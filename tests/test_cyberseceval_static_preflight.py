"""Tests for the frozen positive-only CyberSecEval static preflight."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark import cyberseceval_static_preflight as preflight
from belief.validation.plan_models import canonical_digest


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
PREREGISTRATION = (
    ROOT / "benchmark_cyberseceval" / "preregistration.json"
)


def _record(
    source: str,
    line_text: str,
    *,
    cwe: str = "CWE-94",
    prompt_id: int = 7,
) -> dict:
    return {
        "prompt_id": prompt_id,
        "repo": "public/example",
        "file_path": "src/example.py",
        "pattern_id": "public-pattern",
        "cwe_identifier": cwe,
        "line_number": 20,
        "line_text": line_text,
        "origin_code": source,
    }


def test_preregistration_is_digest_bound_and_matches_frozen_policy():
    payload = json.loads(PREREGISTRATION.read_text(encoding="utf-8"))
    unsigned = dict(payload)
    expected_digest = unsigned.pop("deterministic_digest")

    assert canonical_digest(unsigned) == expected_digest
    assert (
        payload
        == preflight.build_cyberseceval_static_preflight_preregistration()
    )
    assert (
        payload["runner_policy_digest"]
        == preflight.CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_POLICY_DIGEST
    )
    assert payload["status"] == "protocol_frozen_before_belief_outcomes"
    assert "precision" in payload["forbidden_claims"]
    assert "secpass" in payload["forbidden_claims"]


def test_runner_policy_is_static_only_and_has_no_open_execution_capability():
    policy = preflight._runner_policy()

    assert policy["adapter"] == "exact_public_json_dataset"
    assert policy["analysis"]["source_field"] == "origin_code"
    assert policy["analysis"]["external_source_executed"] is False
    assert policy["metric_semantics"]["positive_only"] is True
    assert policy["metric_semantics"]["precision_available"] is False
    assert policy["boundaries"]["authorization_required"] is True
    assert all(
        value is False
        for key, value in policy["boundaries"].items()
        if key != "authorization_required"
    )
    assert (
        canonical_digest(policy)
        == preflight.CYBERSECEVAL_STATIC_PREFLIGHT_RUNNER_POLICY_DIGEST
    )


def test_eval_cwe_alias_is_detected_only_when_target_line_is_aligned():
    source = (
        "def calculate(user_input):\n"
        "    return eval(user_input)\n"
    )
    detected = preflight._evaluate_record(
        _record(source, "    return eval(user_input)")
    )
    missed = preflight._evaluate_record(
        _record(source, "def calculate(user_input):")
    )

    assert detected["classification"] == "detected"
    assert detected["expected_cwe"] == "CWE-94"
    assert {
        finding["cwe"]
        for finding in detected["matched_findings"]
    } <= {"CWE-94", "CWE-95"}
    assert missed["classification"] == "missed"
    assert missed["mapped_cwe_finding_count"] >= 1
    assert missed["target_aligned_finding_count"] == 0


def test_target_alignment_normalizes_one_upstream_trailing_carriage_return():
    source = (
        "def calculate(user_input):\n"
        "    return eval(user_input)\n"
    )
    result = preflight._evaluate_record(
        _record(source, "    return eval(user_input)\r")
    )

    assert result["target_line_match_count"] == 1
    assert result["classification"] == "detected"


@pytest.mark.parametrize(
    ("source", "line_text", "reason"),
    (
        ("def broken(:\n", "def broken(:", "python_ast_parse_failed"),
        (
            "def safe(value):\n    return len(value)\n",
            "return missing(value)",
            "target_line_not_located",
        ),
    ),
)
def test_non_evaluable_source_abstains(source, line_text, reason):
    result = preflight._evaluate_record(
        _record(source, line_text)
    )

    assert result["classification"] == "abstain"
    assert result["abstention_reason"] == reason


def test_analysis_exception_abstains_without_retaining_error_or_source(
    monkeypatch,
):
    source = "def safe(value):\n    return len(value)\n"

    class RejectingExtractor:
        def extract(self, *_args, **_kwargs):
            raise RuntimeError(f"must not leak: {source}")

    monkeypatch.setattr(
        preflight,
        "SecurityPatternExtractor",
        RejectingExtractor,
    )
    result = preflight._evaluate_record(
        _record(source, "    return len(value)")
    )

    assert result["classification"] == "abstain"
    assert result["abstention_reason"] == "analysis_exception"
    assert result["analysis_exception"] is True
    rendered = json.dumps(result, sort_keys=True)
    assert source not in rendered
    assert "must not leak" not in rendered


def test_metrics_are_positive_only_and_penalize_abstention():
    rows = [
        {
            "classification": "detected",
            "ast_parseable": True,
            "target_line_match_count": 1,
            "analysis_exception": False,
            "declared_overlap_supported": True,
            "expected_cwe": "CWE-94",
        },
        {
            "classification": "missed",
            "ast_parseable": True,
            "target_line_match_count": 1,
            "analysis_exception": False,
            "declared_overlap_supported": True,
            "expected_cwe": "CWE-94",
        },
        {
            "classification": "abstain",
            "ast_parseable": False,
            "target_line_match_count": 1,
            "analysis_exception": False,
            "declared_overlap_supported": True,
            "expected_cwe": "CWE-94",
        },
        {
            "classification": "missed",
            "ast_parseable": True,
            "target_line_match_count": 1,
            "analysis_exception": False,
            "declared_overlap_supported": False,
            "expected_cwe": "CWE-312",
        },
    ]

    metrics = preflight._metrics(rows)

    assert metrics["target_pattern_sensitivity_lower_bound"] == 0.25
    assert (
        metrics["target_pattern_sensitivity_on_evaluable_cases"]
        == 0.333333
    )
    assert metrics["abstention_rate"] == 0.25
    assert metrics["declared_overlap_case_count"] == 3
    assert "precision" not in metrics
    assert "accuracy" not in metrics


def test_evaluation_payload_retains_digests_but_not_external_source(
    monkeypatch,
):
    source = (
        "def calculate(user_input):\n"
        "    return eval(user_input)\n"
    )

    def reject(*_args, **_kwargs):
        raise AssertionError("unexpected open-world runner capability")

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(subprocess, "run", reject)
    monkeypatch.setattr(subprocess, "Popen", reject)
    payload = preflight._evaluate_once(
        [_record(source, "    return eval(user_input)")],
        preregistration=(
            preflight.build_cyberseceval_static_preflight_preregistration()
        ),
        dataset_verification={
            "exact_binding_verified": True,
        },
        belief_revision="a" * 40,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert source not in rendered
    assert "public/example" not in rendered
    assert payload["case_results"][0]["source_sha256"]
    assert payload["execution_boundaries"]["network_used"] is False
    assert payload["execution_boundaries"]["subprocess_used"] is False
    assert payload["execution_boundaries"]["source_text_retained"] is False
    assert payload["execution_boundaries"]["secpass_equivalent"] is False
    assert "precision" in payload["unavailable_metrics"]


def test_authorization_is_checked_before_external_input_is_opened(
    tmp_path,
):
    missing = tmp_path / preflight.CYBERSECEVAL_DATASET_FILENAME

    with pytest.raises(ValueError, match="acknowledgement is required"):
        preflight.evaluate_cyberseceval_python_static_preflight(
            missing,
            acknowledgement="",
            belief_revision="a" * 40,
        )


def test_dataset_filename_size_and_digest_are_closed(tmp_path):
    wrong_name = tmp_path / "other.json"
    wrong_name.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exact bound dataset filename"):
        preflight._load_bound_python_records(wrong_name)

    wrong_content = tmp_path / preflight.CYBERSECEVAL_DATASET_FILENAME
    wrong_content.write_text("[]\n", encoding="utf-8")
    with pytest.raises(ValueError, match="size mismatch"):
        preflight._load_bound_python_records(wrong_content)


def test_writer_is_create_only(monkeypatch, tmp_path):
    payload = {
        "deterministic_digest": "a" * 64,
        "metrics": {"case_count": 0},
    }
    monkeypatch.setattr(
        preflight,
        "evaluate_cyberseceval_python_static_preflight",
        lambda *_args, **_kwargs: payload,
    )
    output = tmp_path / "result.json"

    assert (
        preflight.write_cyberseceval_python_static_preflight_result(
            tmp_path / preflight.CYBERSECEVAL_DATASET_FILENAME,
            output,
            acknowledgement=(
                preflight.CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT
            ),
            belief_revision="a" * 40,
        )
        == payload
    )
    with pytest.raises(ValueError, match="refusing to overwrite"):
        preflight.write_cyberseceval_python_static_preflight_result(
            tmp_path / preflight.CYBERSECEVAL_DATASET_FILENAME,
            output,
            acknowledgement=(
                preflight.CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT
            ),
            belief_revision="a" * 40,
        )


def test_cli_requires_explicit_external_code_acknowledgement(tmp_path):
    output = tmp_path / "result.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "run_cyberseceval_static_preflight.py"),
            "--dataset",
            str(
                tmp_path
                / preflight.CYBERSECEVAL_DATASET_FILENAME
            ),
            "--output",
            str(output),
            "--belief-revision",
            "a" * 40,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "acknowledgement is required" in completed.stderr
    assert not output.exists()
