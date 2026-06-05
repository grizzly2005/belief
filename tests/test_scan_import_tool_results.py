import json
import subprocess
import sys
from pathlib import Path

from belief.tool_results.io import write_normalized_tool_result
from belief.tools.schemas import AccessObservation, ExternalFinding, NormalizedToolResult


ROOT = Path(__file__).resolve().parents[1]


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "belief", *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )


def test_scan_import_tool_results_audit_json_reportability_and_markdown(tmp_path):
    app = tmp_path / "sample_app"
    app.mkdir()
    (app / "app.py").write_text("def get_user(user_id):\n    return User.query.get(user_id)\n", encoding="utf-8")
    normalized = tmp_path / "tools.json"
    audit_json = tmp_path / "audit.json"
    reportability_json = tmp_path / "audit-reportability.json"
    filtered_json = tmp_path / "audit-filtered.json"
    bug_markdown = tmp_path / "bug-bounty.md"
    write_normalized_tool_result(
        NormalizedToolResult(
            tool_id="fixture",
            findings=[
                ExternalFinding(
                    tool_id="semgrep",
                    rule_id="generic.weak",
                    title="Weak generic signal",
                    severity="info",
                    file="app.py",
                    line=1,
                )
            ],
            access_observations=[
                AccessObservation(
                    source_tool="belief-access-model",
                    actor="current_user",
                    role="member",
                    method="POST",
                    path="/users/{user_id}",
                    object_type="user",
                    object_id_source="user_id",
                    action="update_user",
                    expected_guard="owner_or_tenant_scoped_lookup",
                    missing_guards=["owner_or_tenant_scoped_lookup"],
                    mutation=True,
                    confidence="high",
                )
            ],
        ),
        normalized,
    )

    result = _run(
        "scan",
        str(app),
        "--import-tool-results",
        str(normalized),
        "--audit-mode",
        "--json-output",
        str(audit_json),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(audit_json.read_text(encoding="utf-8"))
    assert payload["audit_cases"]
    assert any(case["case_type"] == "idor_bola_possible" for case in payload["audit_cases"])

    result = _run(
        "scan",
        str(app),
        "--import-tool-results",
        str(normalized),
        "--reportability",
        "--json-output",
        str(reportability_json),
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(reportability_json.read_text(encoding="utf-8"))
    assert any(
        "reportability" in case.get("metadata", {})
        for case in payload["audit_cases"]
    )

    result = _run(
        "scan",
        str(app),
        "--import-tool-results",
        str(normalized),
        "--reportability",
        "--min-reportability-score",
        "50",
        "--json-output",
        str(filtered_json),
    )
    assert result.returncode == 0, result.stderr
    filtered = json.loads(filtered_json.read_text(encoding="utf-8"))
    assert filtered["audit_cases"]
    assert all(
        case["metadata"]["reportability"]["score"] >= 50
        for case in filtered["audit_cases"]
    )

    result = _run(
        "scan",
        str(app),
        "--import-tool-results",
        str(normalized),
        "--reportability",
        "--bug-bounty-markdown",
        str(bug_markdown),
    )
    assert result.returncode == 0, result.stderr
    assert "BELIEF Bug Bounty Candidate Report" in bug_markdown.read_text(encoding="utf-8")


def test_tools_import_normalized_output_cli(tmp_path):
    normalized = tmp_path / "semgrep.belief-tools.json"
    fixture = ROOT / "tests" / "fixtures" / "semgrep_sample.json"

    result = _run(
        "tools",
        "import",
        "semgrep",
        "--file",
        str(fixture),
        "--normalized-output",
        str(normalized),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(normalized.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "belief.tools.v1"
    assert payload["tool_id"] == "semgrep"
    assert payload["findings"][0]["cwe"] == ["CWE-79"]
