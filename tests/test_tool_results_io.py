import json
from pathlib import Path

import pytest

from belief.tool_results.io import (
    normalized_tool_result_from_dict,
    normalized_tool_result_to_dict,
    read_normalized_tool_result,
    write_normalized_tool_result,
)
from belief.tool_results.models import TOOL_RESULT_SCHEMA_VERSION, ToolResultSchemaError
from belief.tools.schemas import ExternalFinding, NormalizedToolResult


def test_write_read_normalized_tool_result_redacts_and_preserves_schema(tmp_path):
    result = NormalizedToolResult(
        tool_id="semgrep",
        findings=[
            ExternalFinding(
                tool_id="semgrep",
                rule_id="python.flask.xss",
                title="XSS candidate",
                file="app.py",
                line=12,
                cwe=["CWE-79"],
                evidence=["Authorization: Bearer abc123"],
                raw={"headers": {"Authorization": "Bearer abc123"}, "path": Path("app.py")},
            )
        ],
        artifacts=[Path("out/semgrep.json")],
        raw={"api_key": "should-not-leak"},
    )
    output = tmp_path / "semgrep.belief-tools.json"

    write_normalized_tool_result(result, output)
    payload = json.loads(output.read_text(encoding="utf-8"))
    restored = read_normalized_tool_result(output)

    assert payload["schema_version"] == TOOL_RESULT_SCHEMA_VERSION
    assert payload["raw"]["api_key"] == "[REDACTED]"
    assert payload["findings"][0]["raw"]["headers"]["Authorization"] == "[REDACTED]"
    assert payload["findings"][0]["evidence"] == ["Authorization: [REDACTED]"]
    assert payload["artifacts"] == ["out/semgrep.json"]
    assert restored.tool_id == "semgrep"
    assert restored.findings[0].raw["headers"]["Authorization"] == "[REDACTED]"


def test_missing_optional_fields_are_tolerated():
    result = normalized_tool_result_from_dict({
        "schema_version": TOOL_RESULT_SCHEMA_VERSION,
        "tool_id": "codeql",
    })

    assert result.tool_id == "codeql"
    assert result.findings == []
    assert result.access_observations == []
    assert result.attack_paths == []


def test_invalid_schema_fails_clearly():
    with pytest.raises(ToolResultSchemaError):
        normalized_tool_result_from_dict({
            "schema_version": "belief.tools.v0",
            "tool_id": "semgrep",
        })


def test_to_dict_is_deterministic_for_paths():
    result = NormalizedToolResult(tool_id="semgrep", artifacts=[Path("b.json"), Path("a.json")])

    first = normalized_tool_result_to_dict(result)
    second = normalized_tool_result_to_dict(result)

    assert first == second
    assert first["artifacts"] == ["b.json", "a.json"]
