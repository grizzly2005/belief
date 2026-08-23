from belief.audit_case import AuditCase
from belief.reportability.scoring import assess_audit_case_reportability
from belief.tool_results.mapper import access_observation_to_audit_case, external_finding_to_audit_case
from belief.tool_results.merger import merge_audit_cases
from belief.tools.schemas import AccessObservation, ExternalFinding


def test_static_only_low_severity_finding_is_weak_or_likely_false_positive():
    case = external_finding_to_audit_case(
        ExternalFinding(
            tool_id="semgrep",
            rule_id="generic.pattern",
            title="Generic static signal",
            severity="info",
            file="tests/app.py",
            line=3,
        )
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.verdict in {"weak_signal", "likely_false_positive"}
    assert assessment.score < 50


def test_access_observation_missing_owner_guard_scores_high():
    case = access_observation_to_audit_case(
        AccessObservation(
            source_tool="belief-access-model",
            actor="current_user",
            role="member",
            method="POST",
            path="/users/{user_id}/promote",
            object_type="user",
            object_id_source="user_id",
            action="promote_user",
            expected_guard="owner_or_tenant_scoped_lookup",
            missing_guards=["owner_or_tenant_scoped_lookup"],
            mutation=True,
            confidence="high",
        )
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.verdict in {"needs_manual_validation", "reportable_candidate"}
    assert assessment.score >= 50
    assert "missing owner/tenant guard" in assessment.positive_factors


def test_strong_guard_becomes_protected_by_guard():
    case = access_observation_to_audit_case(
        AccessObservation(
            source_tool="belief-access-model",
            actor="current_user",
            role="member",
            method="GET",
            path="/users/{user_id}",
            object_type="user",
            object_id_source="user_id",
            action="read_user",
            expected_guard="owner_or_tenant_scoped_lookup",
            detected_guards=["owner_tenant_scope strong"],
            missing_guards=[],
            confidence="high",
        )
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.verdict == "protected_by_guard"


def test_multiple_tools_without_lineage_or_proof_require_validation():
    semgrep = external_finding_to_audit_case(
        ExternalFinding(
            tool_id="semgrep",
            rule_id="python.path.traversal",
            title="Path traversal candidate",
            severity="high",
            file="app.py",
            line=30,
            cwe=["CWE-22"],
            route="/download",
            evidence=["request.args['path'] -> open"],
        )
    )
    codeql = external_finding_to_audit_case(
        ExternalFinding(
            tool_id="codeql",
            rule_id="py/path-injection",
            title="Path injection",
            severity="error",
            file="app.py",
            line=32,
            cwe=["CWE-22"],
            route="/download",
            evidence=["app.py:30 source", "app.py:32 sink"],
        )
    )
    merged = merge_audit_cases([semgrep, codeql])[0]

    assessment = assess_audit_case_reportability(merged)

    assert assessment.verdict == "needs_manual_validation"
    assert assessment.score < 80
    assert assessment.legacy_score >= 80
    assert "external source independence not established" in assessment.negative_factors
    assert "verified validation proof" in assessment.missing_evidence


def test_reportability_can_read_existing_case_metadata():
    case = AuditCase(
        case_id="case_manual",
        case_type="command_injection_possible",
        status="needs_review",
        review_priority="critical",
        confidence=0.9,
        severity="critical",
        file="app.py",
        line=4,
        rule_id="CWE-78",
        cwe="CWE-78",
        route_context={"route": "/run", "methods": ["POST"]},
        human_next_steps=("Review command argument control in authorized scope.",),
        metadata={"source_tools": ["semgrep"], "category": "command_injection"},
    )

    assert assess_audit_case_reportability(case).score >= 50
