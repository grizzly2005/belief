from belief.tool_results.mapper import (
    access_observation_to_audit_case,
    attack_path_to_audit_case,
    external_finding_to_audit_case,
    external_finding_to_finding,
    normalized_result_to_audit_cases,
)
from belief.tools.schemas import (
    AccessObservation,
    AttackPath,
    ExternalFinding,
    NormalizedToolResult,
    RequestStep,
)


def test_external_finding_maps_to_finding_and_audit_case_with_provenance():
    external = ExternalFinding(
        tool_id="semgrep",
        rule_id="python.flask.xss",
        title="XSS candidate",
        message="Unescaped value reaches template",
        severity="warning",
        confidence="medium",
        file="app.py",
        line=7,
        cwe=["CWE-79"],
        route="/profile",
        evidence=["value -> render_template"],
    )

    finding = external_finding_to_finding(external)
    case = external_finding_to_audit_case(external)

    assert finding.source == "tool:semgrep"
    assert finding.metadata["category"] == "xss"
    assert case.case_type == "xss_possible"
    assert case.status == "needs_review"
    assert case.route_context["route"] == "/profile"
    assert case.metadata["provenance"][0]["source_tool"] == "semgrep"
    assert case.metadata["source_tools"] == ["semgrep"]


def test_access_observation_maps_to_candidate_with_safe_validation_steps():
    observation = AccessObservation(
        source_tool="belief-access-model",
        actor="current_user",
        role="member",
        method="GET",
        path="/invoices/{invoice_id}",
        object_type="invoice",
        object_id_source="invoice_id",
        action="read_invoice",
        expected_guard="owner_or_tenant_scoped_lookup",
        detected_guards=["login_required weak"],
        missing_guards=["owner_or_tenant_scoped_lookup"],
        mutation=False,
        response_exposes_object=True,
        confidence="high",
    )

    case = access_observation_to_audit_case(observation)

    assert case.case_type == "idor_bola_possible"
    assert case.status == "needs_review"
    assert "owner_or_tenant_scoped_lookup" in case.missing_guarantees
    assert any("User A" in step for step in case.human_next_steps)
    assert case.metadata["tool_signal_type"] == "access_observation"


def test_attack_path_maps_ordered_request_steps():
    path = AttackPath(
        source_tool="authmatrix",
        title="Cross-user object replay candidate",
        steps=[
            RequestStep(method="POST", path="/objects", actor="User A", produces=["object_id"]),
            RequestStep(method="GET", path="/objects/{id}", actor="User B", consumes=["object_id"]),
        ],
        hypothesis="Produced object id may be reusable across actors.",
        evidence_needed=["Check expected 403/404 behavior."],
        risk="high",
    )

    case = attack_path_to_audit_case(path)

    assert case.case_type == "validation_workflow_candidate"
    assert case.dataflow_path[0].startswith("POST /objects")
    assert case.dataflow_path[1].startswith("GET /objects/{id}")
    assert case.metadata["tool_signal_type"] == "attack_path"


def test_normalized_result_to_audit_cases_combines_signal_types():
    result = NormalizedToolResult(
        tool_id="mixed",
        findings=[ExternalFinding(tool_id="semgrep", rule_id="x", title="xss", cwe=["CWE-79"])],
        access_observations=[
            AccessObservation(
                source_tool="belief-access-model",
                actor="current_user",
                role=None,
                method="GET",
                path="/users/{user_id}",
                object_type="user",
                object_id_source="user_id",
                action="read_user",
                expected_guard="owner_or_tenant_scoped_lookup",
                missing_guards=["owner_or_tenant_scoped_lookup"],
            )
        ],
    )

    cases = normalized_result_to_audit_cases(result)

    assert {case.case_type for case in cases} == {"xss_possible", "idor_bola_possible"}
