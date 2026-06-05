import json
from pathlib import Path

from belief.datasets.quality import validate_sft_jsonl
from belief.datasets.sft import export_sft_dataset_from_audit_report


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def test_sft_export_is_minimal_and_deterministic(tmp_path):
    output = tmp_path / "sft.jsonl"
    second_output = tmp_path / "sft-second.jsonl"
    rows = export_sft_dataset_from_audit_report(
        FIXTURES / "audit_reportability_sample.json",
        output,
    )
    export_sft_dataset_from_audit_report(
        FIXTURES / "audit_reportability_sample.json",
        second_output,
    )

    assert len(rows) == 1
    first = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert first["metadata"]["schema_version"] == "belief.sft.v1"
    assert [message["role"] for message in first["messages"]] == ["system", "user", "assistant"]
    assert "chain-of-thought" not in output.read_text(encoding="utf-8").lower()
    assert output.read_text(encoding="utf-8") == second_output.read_text(encoding="utf-8")


def test_sft_export_includes_reasoning_and_feedback_summaries(tmp_path):
    report_path = tmp_path / "audit.json"
    output = tmp_path / "sft.jsonl"
    report = {
        "schema_version": "belief.audit.v1",
        "audit_cases": [
            {
                "case_id": "case-1",
                "case_type": "external_tool_signal",
                "status": "needs_review",
                "review_priority": "medium",
                "confidence": 0.5,
                "severity": "medium",
                "file": "app.py",
                "line": 1,
                "rule_id": "RULE",
                "cwe": "",
                "reason": "Candidate needs review.",
                "metadata": {
                    "reportability": {
                        "verdict": "needs_manual_validation",
                        "score": 55,
                    },
                    "reasoning": {
                        "recommendation": "request_more_evidence",
                        "rationale_summary": "Required evidence is still missing before reporting.",
                    },
                    "feedback_adjustment": {
                        "recommendation": "likely_false_positive",
                        "reportability_effect": "lower",
                    },
                },
            }
        ],
    }
    report_path.write_text(json.dumps(report), encoding="utf-8")

    export_sft_dataset_from_audit_report(report_path, output)
    text = output.read_text(encoding="utf-8")

    assert "reasoning_recommendation: request_more_evidence" in text
    assert "rationale_summary: Required evidence is still missing before reporting." in text
    assert "feedback_adjustment_summary: recommendation=likely_false_positive effect=lower" in text
    assert "chain-of-thought" not in text.lower()
    assert validate_sft_jsonl(output).passed is True
