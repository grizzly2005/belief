"""Stable Finding and AnalysisReport regression coverage."""

from __future__ import annotations

import json

import pytest

from belief.models import AnalysisReport, Belief, Finding, JustificationCategory, Predicate, Scope

pytestmark = pytest.mark.security


def test_finding_accepts_legacy_bridge_fields_and_roundtrips(tmp_path):
    finding = Finding.from_dict({
        "source": "bandit",
        "test_id": "B307",
        "message": "Use of eval detected",
        "filename": "pkg/app.py",
        "line": "7",
        "cwe": "CWE-95",
        "source_metadata": {"tool": "bandit"},
    })

    assert finding.rule_id == "B307"
    assert finding.file == "pkg/app.py"
    assert finding.line == 7
    assert finding.fingerprint
    assert finding.dedup_key

    report = AnalysisReport(
        project_name="demo",
        findings=[finding],
        bridge_summary={"bandit": {"status": "available", "findings": 1, "errors": []}},
    )
    path = tmp_path / "report.json"
    report.save(str(path))
    raw = json.loads(path.read_text(encoding="utf-8"))

    assert raw["schema_version"] == "belief.report.v2"
    assert raw["summary"]["total_findings"] == 1
    assert raw["findings"][0]["schema_version"] == "belief.finding.v1"
    assert raw["findings"][0]["canonical_key"]
    assert raw["bridge_summary"]["bandit"]["status"] == "available"

    loaded = AnalysisReport.load(str(path))
    assert loaded.findings[0].rule_id == "B307"
    assert loaded.findings[0].metadata["tool"] == "bandit"
    assert loaded.bridge_summary["bandit"]["findings"] == 1


def test_report_output_is_deterministic_for_reordered_beliefs_and_findings():
    b1 = Belief(
        predicate=Predicate(expression="b"),
        scope=Scope(file_path="b.py", line_start=20),
        justification=JustificationCategory.C5_NO_JUSTIFICATION,
    )
    b2 = Belief(
        predicate=Predicate(expression="a"),
        scope=Scope(file_path="a.py", line_start=10),
        justification=JustificationCategory.C5_NO_JUSTIFICATION,
    )
    f1 = Finding(source="security", rule_id="B", file="b.py", line=20, cwe="CWE-95")
    f2 = Finding(source="security", rule_id="A", file="a.py", line=10, cwe="CWE-78")

    left = AnalysisReport(project_name="demo", beliefs=[b1, b2], findings=[f1, f2]).to_dict()
    right = AnalysisReport(project_name="demo", beliefs=[b2, b1], findings=[f2, f1]).to_dict()

    assert left["beliefs"] == right["beliefs"]
    assert left["findings"] == right["findings"]
    assert [item["file"] for item in left["findings"]] == ["a.py", "b.py"]


def test_finding_from_belief_preserves_identity_cwe_and_metadata():
    belief = Belief(
        predicate=Predicate(
            expression="dynamic_code.input.is_trusted == True",
            natural_language="User input reaches eval().",
        ),
        scope=Scope(file_path="app.py", function_name="run", line_start=3),
        justification=JustificationCategory.C5_NO_JUSTIFICATION,
        cwe="CWE-95",
        source_metadata={"source": "security_patterns", "rule_id": "CWE-95"},
        confidence_score=0.95,
    )

    finding = Finding.from_belief(belief)

    assert finding.cwe == "CWE-95"
    assert finding.dedup_key == belief.canonical_key
    assert finding.metadata["belief_id"] == belief.id
    assert finding.metadata["canonical_key"] == belief.canonical_key
