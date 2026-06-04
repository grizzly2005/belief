"""SARIF importer regression tests."""

from __future__ import annotations

import json
from pathlib import Path

from belief.importers.sarif import import_sarif_findings, sarif_result_to_finding


def _sarif_payload() -> dict:
    return {
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Semgrep",
                    "rules": [{
                        "id": "python.lang.security.audit.eval",
                        "properties": {"cwe": "CWE-95"},
                    }],
                }
            },
            "results": [{
                "ruleId": "python.lang.security.audit.eval",
                "level": "error",
                "message": {"text": "Use of eval"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": "app.py"},
                        "region": {"startLine": 7},
                    }
                }],
                "partialFingerprints": {"primaryLocationLineHash": "abc123"},
                "properties": {"cwe": "CWE-95", "confidence": "HIGH"},
            }],
        }],
    }


def test_import_sarif_minimal_result_to_finding(tmp_path: Path):
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(_sarif_payload()), encoding="utf-8")

    findings = import_sarif_findings(path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.source == "sarif:Semgrep"
    assert finding.rule_id == "python.lang.security.audit.eval"
    assert finding.severity == "high"
    assert finding.confidence == 0.7
    assert finding.file == "app.py"
    assert finding.line == 7
    assert finding.cwe == "CWE-95"
    assert finding.metadata["sarif_partial_fingerprints"] == {
        "primaryLocationLineHash": "abc123"
    }


def test_sarif_missing_optional_fields_are_handled():
    finding = sarif_result_to_finding({"message": {"text": "No location"}})

    assert finding.source == "sarif:unknown"
    assert finding.rule_id == ""
    assert finding.file == ""
    assert finding.line is None
    assert finding.severity == "medium"
    assert finding.description == "No location"


def test_sarif_fingerprint_is_deterministic(tmp_path: Path):
    first = tmp_path / "first.sarif"
    second = tmp_path / "second.sarif"
    payload = _sarif_payload()
    first.write_text(json.dumps(payload), encoding="utf-8")
    second.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")

    assert import_sarif_findings(first)[0].fingerprint == import_sarif_findings(second)[0].fingerprint


def test_sarif_import_source_tool_override(tmp_path: Path):
    path = tmp_path / "scan.sarif"
    path.write_text(json.dumps(_sarif_payload()), encoding="utf-8")

    finding = import_sarif_findings(path, source_tool="CodeQL")[0]

    assert finding.source == "sarif:CodeQL"
