"""Authorization triage must come from security findings, not variable names."""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

from belief.audit_case import build_audit_cases
from belief.hypothesis_engine import (
    attach_hypotheses_to_findings,
    classify_finding_hypothesis,
)
from belief.models import Finding
from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target


pytestmark = pytest.mark.security


@pytest.mark.parametrize("hypotheses", [False, True])
@pytest.mark.parametrize(
    "argument", ["value", "user_id", "owner_id", "source_id", "corridor", "idor", "bola"]
)
def test_pure_string_operation_is_not_an_authorization_case(
    tmp_path: Path, argument: str, hypotheses: bool
) -> None:
    (tmp_path / "module.py").write_text(
        f"def normalize({argument}: str) -> str:\n    return {argument}.strip()\n",
        encoding="utf8",
    )

    result = analyze_static_target(
        tmp_path,
        StaticAnalysisOptions(
            include_hypotheses=hypotheses,
            include_guarantees=True,
            include_dataflow=True,
            include_audit_cases=True,
            reportability=True,
        ),
    )

    assert result.findings  # The structural observation itself is retained.
    assert not result.diagnostics
    assert not result.audit_cases
    assert all(
        (finding.metadata.get("hypothesis") or {}).get("hypothesis_type")
        != "authorization_bypass_possible"
        for finding in result.findings
    )


@pytest.mark.parametrize("argument", ["user_id", "owner_id", "source_id", "corridor"])
def test_untyped_identifier_observation_is_not_authorization(argument: str) -> None:
    finding = Finding(
        source="external-scanner",
        title=f"Attribute access on {argument}",
        description="Check whether the argument can be None.",
        evidence=f"return {argument}.strip()",
    )

    assert classify_finding_hypothesis(finding) is None
    assert build_audit_cases([finding]) == []


def test_security_term_in_raw_code_evidence_does_not_assign_a_category() -> None:
    finding = Finding(
        source="external-scanner",
        rule_id="NULL-CHECK",
        title="Attribute access without a null check",
        evidence="return idor.strip()  # access control example label",
    )

    assert classify_finding_hypothesis(finding) is None
    assert build_audit_cases([finding]) == []


@pytest.mark.parametrize("cwe", ["CWE-639", "CWE-862", "CWE-863"])
def test_typed_authorization_finding_survives_without_identifier_clues(cwe: str) -> None:
    finding = Finding(
        source="external-scanner",
        title="Selected record lacks a permission check",
        cwe=cwe,
        evidence="record = repository.get(selector)",
    )
    _assert_authorization_case_before_and_after_enrichment(finding)


@pytest.mark.parametrize(
    ("field", "label"),
    [
        ("rule_id", "python.IDOR_BOLA"),
        ("title", "Potential IDOR"),
        ("title", "BOLA candidate"),
        ("description", "Missing access control at the resource boundary"),
        ("description", "Potential authorization bypass"),
    ],
)
def test_explicit_scanner_security_label_survives_without_a_cwe(
    field: str, label: str
) -> None:
    fields = {"source": "external-scanner", "title": "Resource permission finding", field: label}
    _assert_authorization_case_before_and_after_enrichment(Finding(**fields))


def _assert_authorization_case_before_and_after_enrichment(finding: Finding) -> None:
    for enriched in (False, True):
        if enriched:
            attach_hypotheses_to_findings([finding], [])
        cases = build_audit_cases([finding])
        assert len(cases) == 1
        assert cases[0].case_type == "idor_bola_possible"
        assert cases[0].status in {"actionable", "needs_review"}
    assert finding.metadata["hypothesis"]["hypothesis_type"] == "authorization_bypass_possible"


def test_identifier_does_not_override_a_sql_findings_explicit_category() -> None:
    finding = Finding(
        source="security",
        title="SQL value interpolated from user_id",
        cwe="CWE-89",
        evidence="cursor.execute(statement)",
    )
    attach_hypotheses_to_findings([finding], [])

    cases = build_audit_cases([finding])
    assert len(cases) == 1
    assert cases[0].case_type == "sql_injection_possible"


@pytest.mark.parametrize("selector", ["document_id", "resource_id"])
def test_real_request_to_resource_flow_remains_an_authorization_case(
    tmp_path: Path, selector: str
) -> None:
    source = dedent(f"""\
        def encode_record(record):
            return {{"id": record.document_id}}

        @router.get("/documents")
        def document_route():
            {selector} = request.args.get("document")
            principal = request.headers.get("X-User")
            workspace = request.headers.get("X-Workspace")
            record = DOCUMENTS.get({selector})
            payload = encode_record(record)
            return payload
    """)
    (tmp_path / "application.py").write_text(source, encoding="utf8")

    result = analyze_static_target(
        tmp_path, StaticAnalysisOptions(audit_mode=True, reportability=True)
    )

    native = [finding for finding in result.findings if finding.cwe == "CWE-639"]
    assert native
    assert all(
        finding.metadata["hypothesis"]["hypothesis_type"] == "authorization_bypass_possible"
        for finding in native
    )
    cases = [case for case in result.audit_cases if case.cwe == "CWE-639"]
    assert cases
    assert all(case.case_type == "idor_bola_possible" for case in cases)
    assert all(case.status in {"actionable", "needs_review"} for case in cases)
    assert any(case.source and case.sink for case in cases)
