import json
import subprocess
import sys
from pathlib import Path


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "belief", *args],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_reason_cli_writes_reasoned_audit_json(tmp_path):
    output = tmp_path / "reasoned.json"

    result = _run(
        "reason",
        "--audit",
        str(FIXTURES / "audit_reportability_sample.json"),
        "--engine",
        "offline",
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "belief.reasoning_report.v1"
    assert payload["engine"] == "offline"
    assert payload["reasoning"][0]["recommendation"] == "request_more_evidence"
    assert "rationale_summary" in payload["reasoning"][0]
    assert "chain_of_thought" not in json.dumps(payload).lower()


def test_reason_cli_malformed_input_exits_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    output = tmp_path / "reasoned.json"

    result = _run("reason", "--audit", str(bad), "--engine", "offline", "--output", str(output))

    assert result.returncode == 2
    assert "ERROR:" in result.stderr
