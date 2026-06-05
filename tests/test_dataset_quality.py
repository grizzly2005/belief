import json
import subprocess
import sys
from pathlib import Path

from belief.datasets.quality import validate_sft_jsonl, validate_sft_row
from belief.datasets.sft import export_sft_dataset_from_audit_report


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def _valid_row():
    return {
        "messages": [
            {"role": "system", "content": "Classify candidate evidence safely."},
            {"role": "user", "content": "case_type: idor_bola_possible"},
            {"role": "assistant", "content": "rationale_summary: needs manual validation"},
        ],
        "metadata": {
            "schema_version": "belief.sft.v1",
            "case_id": "case-1",
        },
    }


def test_dataset_quality_catches_chain_of_thought_phrase():
    row = _valid_row()
    row["messages"][2]["content"] = "chain-of-thought: hidden reasoning"

    issues = validate_sft_row(row, row_index=1)

    assert any(issue.code == "chain_of_thought_leakage" for issue in issues)


def test_dataset_quality_catches_token_cookie_and_api_key_patterns():
    row = _valid_row()
    row["messages"][1]["content"] = "Authorization: Bearer secretvalue12345\napi_key=abcdef123456\nCookie: session=abcdef"

    issues = validate_sft_row(row, row_index=1)
    codes = {issue.code for issue in issues}

    assert "secret_bearer_token" in codes
    assert "secret_api_key" in codes
    assert "secret_cookie" in codes


def test_dataset_quality_catches_real_looking_domain():
    row = _valid_row()
    row["messages"][1]["content"] = "Review https://internal.company.com/path"

    issues = validate_sft_row(row, row_index=1)

    assert any(issue.code == "real_looking_domain" for issue in issues)


def test_dataset_quality_catches_missing_roles():
    row = {
        "messages": [{"role": "user", "content": "case"}],
        "metadata": {"schema_version": "belief.sft.v1", "case_id": "case-1"},
    }

    issues = validate_sft_row(row, row_index=1)
    codes = {issue.code for issue in issues}

    assert "missing_system_role" in codes
    assert "missing_assistant_role" in codes


def test_dataset_quality_accepts_current_minimal_sft_output(tmp_path):
    output = tmp_path / "sft.jsonl"
    export_sft_dataset_from_audit_report(FIXTURES / "audit_reportability_sample.json", output)

    result = validate_sft_jsonl(output)

    assert result.passed is True
    assert result.score == 100
    assert result.issues == ()


def test_dataset_validate_cli_prints_json(tmp_path):
    output = tmp_path / "sft.jsonl"
    export_sft_dataset_from_audit_report(FIXTURES / "audit_reportability_sample.json", output)

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
