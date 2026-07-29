"""Tests for the frozen v2 positive-only CyberSecEval preflight."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark import cyberseceval_static_preflight as v1
from belief.benchmark import cyberseceval_static_preflight_v2 as v2
from belief.validation.plan_models import canonical_digest


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
PREREGISTRATION_V2 = (
    ROOT / "benchmark_cyberseceval" / "preregistration-v2.json"
)
RESULT_V2 = (
    ROOT
    / "benchmark_cyberseceval_results"
    / "python-instruct-v2-static-v2.json"
)


def _record(
    source: str,
    line_text: str,
    *,
    cwe: str = "CWE-94",
    prompt_id: int = 17,
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


def test_v2_preregistration_is_digest_bound_and_matches_runner():
    payload = json.loads(
        PREREGISTRATION_V2.read_text(encoding="utf-8")
    )
    unsigned = dict(payload)
    expected_digest = unsigned.pop("deterministic_digest")

    assert canonical_digest(unsigned) == expected_digest
    assert (
        payload
        == v2.build_cyberseceval_static_preflight_v2_preregistration()
    )
    assert payload["development_context"]["public_corpus_tuning"] is True
    assert payload["development_context"]["unseen_holdout_opened"] is False
    assert (
        payload["runner_policy_digest"]
        == v2.CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_POLICY_DIGEST
    )
    assert "precision" in payload["forbidden_claims"]
    assert "unseen_holdout_generalization" in payload["forbidden_claims"]


def test_v2_policy_freezes_recovery_bounds_and_no_execution_capability():
    policy = v2._runner_policy()

    assert policy["version"] == 2
    assert policy["recovery"]["maximum_window_lines"] == 25
    assert policy["recovery"]["maximum_synthetic_parameters"] == 64
    assert policy["recovery"]["label_or_cwe_used_for_recovery"] is False
    assert policy["recovery"]["source_execution"] is False
    assert policy["metric_semantics"]["public_development_tuned"] is True
    assert policy["metric_semantics"]["unseen_holdout"] is False
    assert policy["boundaries"]["authorization_required"] is True
    assert all(
        value is False
        for key, value in policy["boundaries"].items()
        if key != "authorization_required"
    )
    assert (
        canonical_digest(policy)
        == v2.CYBERSECEVAL_STATIC_PREFLIGHT_V2_RUNNER_POLICY_DIGEST
    )


def test_v2_recovers_partial_eval_and_maps_finding_to_original_target():
    source = (
        "        ignored = 1\n"
        "        return eval(user_input)\n"
    )
    result = v2._evaluate_record(
        _record(source, "        return eval(user_input)")
    )

    assert result["raw_ast_parseable"] is False
    assert result["recovery_available"] is True
    assert result["recovery_methods"] == ["target_window_sync"]
    assert result["classification"] == "detected"
    assert {
        finding["cwe"] for finding in result["matched_findings"]
    } <= {"CWE-94", "CWE-95"}
    assert {
        line
        for finding in result["matched_findings"]
        for line in finding["lines"]
    } == {2}


def test_v2_partial_recovery_does_not_turn_literal_command_into_detection():
    source = '        os.system("printf ok")\n'
    result = v2._evaluate_record(
        _record(
            source,
            'os.system("printf ok")',
            cwe="CWE-78",
        )
    )

    assert result["recovery_available"] is True
    assert result["classification"] == "missed"
    assert result["target_aligned_finding_count"] == 0


def test_v2_unrecoverable_fragment_abstains_without_analysis():
    source = '        value = """unterminated\n'
    result = v2._evaluate_record(
        _record(source, 'value = """unterminated')
    )

    assert result["raw_ast_parseable"] is False
    assert result["recovery_available"] is False
    assert result["classification"] == "abstain"
    assert result["abstention_reason"] == "partial_recovery_failed"
    assert result["security_finding_count"] == 0


def test_v2_metrics_keep_positive_only_semantics():
    rows = [
        {
            "classification": "detected",
            "raw_ast_parseable": False,
            "recovery_available": True,
            "analysis_exception": False,
            "declared_overlap_supported": True,
            "expected_cwe": "CWE-94",
            "recovery_methods": ["target_window_sync"],
            "projection_count": 1,
        },
        {
            "classification": "missed",
            "raw_ast_parseable": True,
            "recovery_available": True,
            "analysis_exception": False,
            "declared_overlap_supported": True,
            "expected_cwe": "CWE-94",
            "recovery_methods": ["raw", "raw_wrapper"],
            "projection_count": 2,
        },
        {
            "classification": "abstain",
            "raw_ast_parseable": False,
            "recovery_available": False,
            "analysis_exception": False,
            "declared_overlap_supported": False,
            "expected_cwe": "CWE-312",
            "recovery_methods": [],
            "projection_count": 0,
        },
    ]

    metrics = v2._metrics(rows)

    assert metrics["raw_ast_parseability_rate"] == 0.333333
    assert metrics["recovery_evaluability_rate"] == 0.666667
    assert metrics["target_pattern_sensitivity_lower_bound"] == 0.333333
    assert (
        metrics["target_pattern_sensitivity_on_evaluable_cases"]
        == 0.5
    )
    assert metrics["abstention_rate"] == 0.333333
    assert "precision" not in metrics
    gates = v2._gate_evaluations(metrics)
    assert gates["minimum_recovery_evaluability_rate"]["status"] == "fail"


def test_v2_payload_uses_no_network_process_or_source_retention(
    monkeypatch,
):
    source = "        return eval(user_input)\n"

    def reject(*_args, **_kwargs):
        raise AssertionError("unexpected open-world runner capability")

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(subprocess, "run", reject)
    monkeypatch.setattr(subprocess, "Popen", reject)
    payload = v2._evaluate_once(
        [_record(source, "return eval(user_input)")],
        preregistration=(
            v2.build_cyberseceval_static_preflight_v2_preregistration()
        ),
        dataset_verification={"exact_binding_verified": True},
        belief_revision="a" * 40,
    )

    rendered = json.dumps(payload, sort_keys=True)
    assert source not in rendered
    assert "public/example" not in rendered
    boundaries = payload["execution_boundaries"]
    assert boundaries["external_source_executed"] is False
    assert boundaries["network_used"] is False
    assert boundaries["subprocess_used"] is False
    assert boundaries["source_text_retained"] is False
    assert boundaries["recovered_source_retained"] is False
    assert boundaries["public_development_tuned"] is True
    assert boundaries["unseen_holdout"] is False
    assert boundaries["secpass_equivalent"] is False
    assert "precision" in payload["unavailable_metrics"]


def test_v2_writer_is_create_only(monkeypatch, tmp_path):
    payload = {
        "deterministic_digest": "a" * 64,
        "metrics": {"case_count": 0},
    }
    monkeypatch.setattr(
        v2,
        "evaluate_cyberseceval_python_static_preflight_v2",
        lambda *_args, **_kwargs: payload,
    )
    output = tmp_path / "result-v2.json"

    assert (
        v2.write_cyberseceval_python_static_preflight_v2_result(
            tmp_path / v1.CYBERSECEVAL_DATASET_FILENAME,
            output,
            acknowledgement=v1.CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT,
            belief_revision="a" * 40,
        )
        == payload
    )
    with pytest.raises(ValueError, match="refusing to overwrite"):
        v2.write_cyberseceval_python_static_preflight_v2_result(
            tmp_path / v1.CYBERSECEVAL_DATASET_FILENAME,
            output,
            acknowledgement=v1.CYBERSECEVAL_EXTERNAL_CODE_ACKNOWLEDGEMENT,
            belief_revision="a" * 40,
        )


def test_v2_cli_requires_explicit_external_code_acknowledgement(tmp_path):
    output = tmp_path / "result-v2.json"
    completed = subprocess.run(
        [
            sys.executable,
            str(
                ROOT
                / "scripts"
                / "run_cyberseceval_static_preflight_v2.py"
            ),
            "--dataset",
            str(tmp_path / v1.CYBERSECEVAL_DATASET_FILENAME),
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


def test_committed_v2_is_digest_bound_and_passes_only_preflight_gates():
    payload = json.loads(RESULT_V2.read_text(encoding="utf-8"))
    unsigned = dict(payload)
    expected_digest = unsigned.pop("deterministic_digest")

    assert canonical_digest(unsigned) == expected_digest
    assert (
        expected_digest
        == "9669a18cec9b1c3df4dde2664cd4487465a21ffd6342e2251eab9172a45d11f2"
    )
    assert (
        payload["declared_belief_revision"]
        == "b658d61618eea74dcca20573d3b872b008f820a4"
    )
    assert payload["metrics"]["classification_counts"] == {
        "abstain": 7,
        "detected": 203,
        "missed": 72,
    }
    assert payload["metrics"]["raw_ast_parseability_rate"] == 0.124113
    assert payload["metrics"]["recovery_evaluability_rate"] == 0.975177
    assert (
        payload["metrics"]["target_pattern_sensitivity_lower_bound"]
        == 0.719858
    )
    assert (
        payload["metrics"][
            "target_pattern_sensitivity_on_evaluable_cases"
        ]
        == 0.738182
    )
    assert payload["metrics"]["analysis_exception_count"] == 0
    assert payload["metrics"]["per_cwe"]["CWE-338"]["detected"] == 0
    assert all(
        gate["status"] == "pass"
        for gate in payload["gate_evaluations"].values()
    )
    assert payload["reproducibility"]["run_digests"] == [
        "837b3ec025a5a6ba4a4199317f3d1862c6e61997855653c90e79a40eac0d6e14",
        "837b3ec025a5a6ba4a4199317f3d1862c6e61997855653c90e79a40eac0d6e14",
    ]
    assert payload["reproducibility"]["identical"] is True
    boundaries = payload["execution_boundaries"]
    assert boundaries["external_source_executed"] is False
    assert boundaries["source_text_retained"] is False
    assert boundaries["recovered_source_retained"] is False
    assert boundaries["public_development_tuned"] is True
    assert boundaries["unseen_holdout"] is False
    assert boundaries["official_cyberseceval_metric"] is False
    assert boundaries["secpass_equivalent"] is False

    allowed_case_keys = {
        "abstention_reason",
        "analysis_exception",
        "case_id",
        "classification",
        "declared_overlap_supported",
        "expected_cwe",
        "file_path_sha256",
        "line_text_sha256",
        "mapped_cwe_finding_count",
        "matched_findings",
        "maximum_synthetic_parameter_count",
        "maximum_window_span",
        "pattern_id_sha256",
        "projection_count",
        "raw_ast_parseable",
        "recovery_available",
        "recovery_methods",
        "repository_sha256",
        "security_finding_count",
        "source_sha256",
        "taint_path_count",
        "target_aligned_finding_count",
        "target_line_match_count",
        "upstream_prompt_id",
    }
    assert all(
        set(case) == allowed_case_keys
        for case in payload["case_results"]
    )
