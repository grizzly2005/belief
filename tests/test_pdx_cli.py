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


def test_pdx_import_cli_writes_normalized_result(tmp_path):
    output = tmp_path / "normalized.json"
    result = _run(
        "pdx",
        "import",
        str(FIXTURES / "pdx_bundle_sample.json"),
        "--normalized-output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "belief.tools.v1"
    assert payload["tool_id"] == "pdx"
    assert payload["findings"][0]["raw"]["pdx"]["validation_results"][0]["outcome"] == "inconclusive"


def test_pdx_export_cli_writes_bundle(tmp_path):
    output = tmp_path / "exported.pdx.json"
    result = _run(
        "pdx",
        "export",
        str(FIXTURES / "audit_reportability_sample.json"),
        "--pdx-output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "belief.pdx.v1"
    assert payload["deltas"]


def test_feedback_cli_uses_store_dir(tmp_path):
    result = _run(
        "feedback",
        "add",
        "--store-dir",
        str(tmp_path),
        "--case-id",
        "case-1",
        "--verdict",
        "false_positive",
        "--reason",
        "owner guard present",
    )

    assert result.returncode == 0, result.stderr
    listed = _run("feedback", "list", "--store-dir", str(tmp_path))
    assert listed.returncode == 0, listed.stderr
    payload = json.loads(listed.stdout)
    assert payload[0]["case_id"] == "case-1"


def test_dataset_export_cli_writes_sft(tmp_path):
    output = tmp_path / "sft.jsonl"
    result = _run(
        "dataset",
        "export",
        "--from-audit",
        str(FIXTURES / "audit_reportability_sample.json"),
        "--format",
        "sft",
        "--output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    first = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
    assert first["metadata"]["schema_version"] == "belief.sft.v1"


def test_pdx_help_mentions_import():
    result = _run("pdx", "--help")
    assert result.returncode == 0
    assert "import" in result.stdout
