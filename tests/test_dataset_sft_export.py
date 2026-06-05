import json
from pathlib import Path

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
