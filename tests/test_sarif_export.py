"""SARIF exporter regression tests."""

from __future__ import annotations

import json

from belief.audit_case import AuditCase
from belief.exporters.sarif import (
    audit_case_to_sarif_result,
    export_audit_cases_to_sarif,
)


def _case(case_id: str = "case_a") -> AuditCase:
    return AuditCase(
        case_id=case_id,
        case_type="unsafe_deserialization_possible",
        status="actionable",
        review_priority="critical",
        confidence=0.95,
        severity="critical",
        file="app/cache.py",
        line=12,
        rule_id="B301",
        cwe="CWE-502",
        source="cache_file.read()",
        sink="pickle.loads",
        dataflow_path=("cache_file.read()", "payload", "pickle.loads"),
        missing_guarantees=("deserialization.input_trusted == true",),
        human_next_steps=("Confirm whether cache bytes are attacker-controlled.",),
        related_finding_fingerprint="finding_a",
        reason="pickle.loads consumes untrusted bytes",
    )


def test_audit_case_to_sarif_result_keeps_core_fields():
    result = audit_case_to_sarif_result(_case())

    assert result["ruleId"] == "unsafe_deserialization_possible"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "app/cache.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 12
    assert result["partialFingerprints"]["belief.caseId"] == "case_a"
    assert result["properties"]["cwe"] == "CWE-502"
    assert result["properties"]["missing_guarantees"] == [
        "deserialization.input_trusted == true"
    ]


def test_sarif_export_is_deterministic_and_versioned():
    cases = [_case("case_b"), _case("case_a")]

    first = export_audit_cases_to_sarif(cases, "/tmp/project")
    second = export_audit_cases_to_sarif(list(reversed(cases)), "/tmp/project")

    assert first["version"] == "2.1.0"
    assert first["runs"][0]["tool"]["driver"]["rules"][0]["id"] == (
        "unsafe_deserialization_possible"
    )
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
