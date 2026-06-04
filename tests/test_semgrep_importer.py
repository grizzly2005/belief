import json

from belief.importers.semgrep_json import import_semgrep_json
from belief.tools.bridges.semgrep import SemgrepBridge


def test_semgrep_json_maps_to_external_finding(tmp_path):
    payload = {
        "results": [{
            "check_id": "python.lang.security.audit.eval-use",
            "path": "app.py",
            "start": {"line": 7, "col": 5},
            "end": {"line": 7, "col": 15},
            "extra": {
                "message": "Use of eval",
                "severity": "ERROR",
                "metadata": {"cwe": ["CWE-95"], "confidence": "HIGH"},
            },
        }]
    }
    path = tmp_path / "semgrep.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    findings = import_semgrep_json(path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_id == "semgrep"
    assert finding.rule_id == "python.lang.security.audit.eval-use"
    assert finding.file == "app.py"
    assert finding.line == 7
    assert finding.cwe == ["CWE-95"]


def test_semgrep_bridge_passive_import(tmp_path):
    path = tmp_path / "semgrep.json"
    path.write_text(json.dumps({"results": []}), encoding="utf-8")
    result = SemgrepBridge().import_file(path)
    assert result.tool_id == "semgrep"
    assert result.findings == []
    assert result.artifacts == [path]
