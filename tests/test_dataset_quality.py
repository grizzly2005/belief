import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest

from belief.datasets.quality import validate_sft_jsonl, validate_sft_row
from belief.datasets.sft import (
    audit_report_to_sft_rows,
    export_sft_dataset_from_audit_report,
)


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"
SFT_V2_SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "belief-sft-v2.schema.json"


def _schema_validator():
    schema = json.loads(SFT_V2_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def _valid_row():
    report = {
        "schema_version": "belief.audit.v1",
        "audit_cases": [
            {
                "case_id": "case-1",
                "case_type": "idor_bola_possible",
                "status": "needs_review",
                "review_priority": "high",
                "confidence": 0.7,
                "severity": "high",
                "file": "app.py",
                "line": 10,
                "rule_id": "AUTH",
                "cwe": "CWE-862",
                "source": "request:id",
                "sink": "Account.query.get",
                "human_next_steps": ["Confirm owner scoping."],
                "reason": "Candidate needs review.",
            }
        ],
    }
    return audit_report_to_sft_rows(report)[0]


def _replace_payload(row, message_index, **changes):
    payload = json.loads(row["messages"][message_index]["content"])
    payload.update(changes)
    row["messages"][message_index]["content"] = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    )


def test_dataset_quality_catches_chain_of_thought_phrase():
    row = _valid_row()
    _replace_payload(row, 2, next_step="chain-of-thought: hidden reasoning")

    issues = validate_sft_row(row, row_index=1)

    assert any(issue.code == "chain_of_thought_leakage" for issue in issues)


def test_dataset_quality_catches_token_cookie_and_api_key_patterns():
    row = _valid_row()
    _replace_payload(
        row,
        1,
        reason=(
            "Authorization: Bearer secretvalue12345 api_key=abcdef123456 Cookie: session=abcdef"
        ),
    )

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "secret_bearer_token" in codes
    assert "secret_api_key" in codes
    assert "secret_cookie" in codes


def test_dataset_quality_catches_real_looking_domain():
    row = _valid_row()
    _replace_payload(row, 1, reason="Review https://internal.company.com/path")

    issues = validate_sft_row(row, row_index=1)

    assert any(issue.code == "real_looking_domain" for issue in issues)


def test_dataset_quality_requires_exact_role_order_and_no_extra_fields():
    row = _valid_row()
    row["messages"][0], row["messages"][1] = row["messages"][1], row["messages"][0]
    row["messages"][2]["unexpected"] = True

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "invalid_role_order" in codes
    assert "unexpected_fields" in codes


def test_dataset_quality_requires_fixed_system_and_matching_case_type():
    row = _valid_row()
    row["messages"][0]["content"] = "Use arbitrary labels."
    user_payload = json.loads(row["messages"][1]["content"])
    user_payload["audit_case"]["case_type"] = "different_case"
    row["messages"][1]["content"] = json.dumps(
        user_payload,
        sort_keys=True,
        separators=(",", ":"),
    )

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "invalid_system_message" in codes
    assert "case_identity_mismatch" in codes


def test_dataset_quality_rejects_legacy_v1_schema():
    row = _valid_row()
    row["metadata"]["schema_version"] = "belief.sft.v1"

    issues = validate_sft_row(row, row_index=1)

    assert any(issue.code == "legacy_schema_version" for issue in issues)


def test_dataset_quality_rejects_reportable_label_without_verified_snapshot():
    row = _valid_row()
    _replace_payload(row, 2, verdict="reportable_candidate", score=100)

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "reportable_label_forbidden" in codes
    assert "recomputed_label_mismatch" in codes


def test_dataset_quality_recomputes_non_reportable_labels_too():
    row = _valid_row()
    _replace_payload(
        row,
        2,
        score=79,
        verdict="needs_manual_validation",
        positive_factors=["forged-authority"],
    )

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "recomputed_label_mismatch" in codes


def test_dataset_quality_recomputes_subject_and_metadata():
    row = _valid_row()
    row["metadata"]["subject_sha256"] = "a" * 64

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "recomputed_metadata_mismatch" in codes


def test_dataset_quality_detects_assistant_metadata_proof_mismatch():
    row = _valid_row()
    _replace_payload(row, 2, proof_state="verified", verified_proof_ids=["vproof_fake"])

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "proof_state_mismatch" in codes
    assert "verified_proof_ids_mismatch" in codes


def test_dataset_quality_reports_non_string_proof_ids_without_crashing():
    row = _valid_row()
    row["metadata"]["verified_proof_ids"] = [{"forged": True}]
    _replace_payload(row, 2, verified_proof_ids=[{"forged": True}])

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "invalid_string_list" in codes
    assert "invalid_verified_proof_id" in codes


def test_dataset_quality_rejects_noncanonical_or_oversized_proof_ids():
    row = _valid_row()
    forged_ids = ["x" * 300]
    row["metadata"]["verified_proof_ids"] = forged_ids
    _replace_payload(row, 2, verified_proof_ids=forged_ids)

    codes = {issue.code for issue in validate_sft_row(row, row_index=1)}

    assert "invalid_verified_proof_id" in codes
    with pytest.raises(jsonschema.ValidationError):
        _schema_validator().validate(row)


def test_dataset_quality_accepts_current_sft_v2_output(tmp_path):
    output = tmp_path / "sft.jsonl"
    export_sft_dataset_from_audit_report(
        FIXTURES / "audit_reportability_sample.json",
        output,
    )

    result = validate_sft_jsonl(output)

    assert result.passed is True
    assert result.score == 100
    assert result.issues == ()


def test_sft_v2_schema_compiles_and_accepts_generated_row():
    _schema_validator().validate(_valid_row())


def test_dataset_quality_strictly_rejects_duplicate_jsonl_key(tmp_path):
    output = tmp_path / "sft.jsonl"
    row = _valid_row()
    encoded = json.dumps(row, sort_keys=True)
    output.write_text(
        encoded.replace('{"messages":', '{"messages":[],"messages":', 1),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="duplicate JSON object key"):
        validate_sft_jsonl(output)


def test_dataset_validate_cli_prints_json(tmp_path):
    output = tmp_path / "sft.jsonl"
    export_sft_dataset_from_audit_report(
        FIXTURES / "audit_reportability_sample.json",
        output,
    )

    result = subprocess.run(
        [sys.executable, "-m", "belief", "dataset", "validate", "--input", str(output)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
    assert payload["score"] == 100
    assert payload["issues"] == []


def test_dataset_export_cli_reports_v2_and_preserves_target_on_error(tmp_path):
    audit = tmp_path / "audit.json"
    output = tmp_path / "sft.jsonl"
    audit.write_text('{"schema_version":"belief.audit.v1","audit_cases":[]}', encoding="utf-8")
    output.write_bytes(b"sentinel")

    failed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "dataset",
            "export",
            "--from-audit",
            str(audit),
            "--format",
            "sft",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert failed.returncode == 2
    assert "audit_cases must be a non-empty list" in failed.stderr
    assert output.read_bytes() == b"sentinel"

    good_audit = FIXTURES / "audit_reportability_sample.json"
    passed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "dataset",
            "export",
            "--from-audit",
            str(good_audit),
            "--format",
            "sft",
            "--output",
            str(output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert passed.returncode == 0, passed.stderr
    assert json.loads(passed.stdout)["schema_version"] == "belief.sft.v2"
