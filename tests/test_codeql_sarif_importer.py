import json

from belief.importers.codeql_sarif import import_codeql_sarif


def test_codeql_sarif_maps_code_flows_to_evidence(tmp_path):
    payload = {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeQL",
                    "rules": [{
                        "id": "py/path-injection",
                        "properties": {"tags": ["external/cwe/cwe-022"], "problem.severity": "error"},
                    }],
                }
            },
            "results": [{
                "ruleId": "py/path-injection",
                "message": {"text": "User-controlled path"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "views.py"},
                        "region": {"startLine": 10, "startColumn": 3},
                    }
                }],
                "codeFlows": [{
                    "threadFlows": [{
                        "locations": [{
                            "location": {
                                "message": {"text": "source"},
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "views.py"},
                                    "region": {"startLine": 5},
                                },
                            }
                        }]
                    }]
                }],
            }],
        }],
    }
    path = tmp_path / "codeql.sarif"
    path.write_text(json.dumps(payload), encoding="utf-8")

    findings = import_codeql_sarif(path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.tool_id == "codeql"
    assert finding.file == "views.py"
    assert finding.line == 10
    assert finding.evidence == ["views.py:5 source"]
    assert "CWE-022" in finding.cwe
