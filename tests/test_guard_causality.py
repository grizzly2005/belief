"""Regression coverage for causal guard applicability."""

from __future__ import annotations

from dataclasses import replace
from textwrap import dedent

import pytest

from belief.audit_case import AuditCase
from belief.dataflow import analyze_source_dataflow, attach_dataflow_to_findings
from belief.hypothesis_engine import hypothesis_for_finding
from belief.invariant_miner import InvariantMiner
from belief.models import (
    Belief,
    EpistemicStatus,
    Finding,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from belief.reportability.guards import (
    GUARD_CATEGORIES,
    assess_guard_applicability,
    classify_guard,
)
from belief.reportability.scoring import assess_audit_case_reportability


pytestmark = pytest.mark.security


def _audit_case(**overrides) -> AuditCase:
    values = {
        "case_id": "case_login_only",
        "case_type": "idor_bola_possible",
        "status": "needs_review",
        "review_priority": "high",
        "confidence": 0.9,
        "severity": "high",
        "file": "app/views.py",
        "line": 12,
        "rule_id": "CWE-639",
        "cwe": "CWE-639",
        "source": "object_id",
        "sink": "Object.query.get(object_id)",
        "dataflow_path": ("object_id", "Object.query.get(object_id)"),
        "route_context": {
            "route": "/objects/{object_id}",
            "function": "read_object",
            "auth_guarantees": ["route.requires_login == true"],
        },
        "metadata": {
            "category": "idor",
            "object_type": "object",
            "object_id_source": "object_id",
        },
    }
    values.update(overrides)
    return AuditCase(**values)


def _guarantee(expression: str, *, file: str, line: int) -> Belief:
    return Belief(
        predicate=Predicate(expression=expression, anchor_lines=(line,)),
        scope=Scope(
            file_path=file,
            function_name="protect_path",
            line_start=line,
            line_end=line,
        ),
        justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
        epistemic_status=EpistemicStatus.BELIEF,
        logic_type=LogicType.FOL,
        confidence_score=0.9,
        source_metadata={"source": "invariant_miner", "category": "guarantee"},
    )


def _local_path_hypothesis(source: str, *, sink_line: int) -> dict:
    file_path = "app/files.py"
    finding = Finding(
        source="security_patterns",
        rule_id="CWE-22",
        title="Path traversal candidate",
        description="User-controlled path reaches open().",
        file=file_path,
        line=2,
        end_line=sink_line,
        cwe="CWE-22",
        severity="high",
        confidence=0.9,
        metadata={"function_name": "read_file"},
    )
    summary = analyze_source_dataflow(source, file_path)
    attach_dataflow_to_findings(
        [finding],
        {file_path: summary},
        show_dataflow=True,
    )
    hypothesis = hypothesis_for_finding(
        finding,
        InvariantMiner().extract(source, file_path),
        local_context=source,
        dataflow_summaries={file_path: summary},
        show_dataflow=True,
        show_proofs=True,
    )
    assert hypothesis is not None
    return hypothesis


def test_login_only_is_not_a_strong_authorization_guard() -> None:
    assessment = assess_audit_case_reportability(_audit_case())

    assert assessment.verdict != "protected_by_guard"
    assert "authentication_only" in assessment.blockers
    assert assessment.guard_applicability == [
        {
            "category": "authentication_guard",
            "expression": "route.requires_login == true",
            "applicable": False,
            "reason": "authentication does not bind access to the requested resource",
            "blockers": ["authentication_only"],
            "guard_file": "app/views.py",
            "guard_line": None,
        }
    ]


def test_unstructured_strong_guard_flag_has_no_protective_effect() -> None:
    case = _audit_case(
        route_context={},
        guarantees=(),
        metadata={"strong_guard": True},
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.verdict != "protected_by_guard"
    assert assessment.blockers == ["flow_not_demonstrated"]
    assert assessment.guard_applicability[0]["applicable"] is False


def test_guard_in_safe_file_does_not_counterprove_vulnerable_file() -> None:
    finding = Finding(
        source="security_patterns",
        rule_id="CWE-22",
        title="Path traversal candidate",
        description="User-controlled path reaches open().",
        file="app/vuln.py",
        line=10,
        end_line=10,
        cwe="CWE-22",
        severity="high",
        confidence=0.9,
    )
    safe_file_guard = _guarantee(
        "path.is_within_store == true",
        file="app/safe.py",
        line=3,
    )

    hypothesis = hypothesis_for_finding(finding, [safe_file_guard], show_proofs=True)

    assert hypothesis is not None
    assert hypothesis["status"] != "contradicted"
    assert hypothesis["z3"] == {"checked": False, "status": "not_applicable"}
    assert hypothesis["blockers"] == ["guard_in_unrelated_context"]
    assert hypothesis["guard_applicability"][0]["applicable"] is False
    assert (
        hypothesis["guard_applicability"][0]["reason"]
        == "guard and sink are in unrelated files or call contexts"
    )


def test_homonymous_propagated_helper_does_not_create_a_call_path() -> None:
    finding = Finding(
        source="security_patterns",
        rule_id="CWE-22",
        title="Path traversal candidate",
        description="User-controlled path reaches open().",
        file="app/vuln.py",
        line=10,
        end_line=10,
        cwe="CWE-22",
        severity="high",
        confidence=0.9,
    )
    guard = _guarantee(
        "path.is_within_store == true",
        file="app/safe.py",
        line=3,
    )
    guard.source_metadata.update({
        "propagated": True,
        "propagated_to_finding_id": finding.id,
        "propagated_via": "UnsafePath.path",
        "registered_function": "SafePath.path",
    })

    hypothesis = hypothesis_for_finding(finding, [guard], show_proofs=True)

    assert hypothesis is not None
    assert hypothesis["status"] != "contradicted"
    assert hypothesis["blockers"] == ["guard_in_unrelated_context"]


def test_guard_in_other_function_without_call_path_does_not_counterprove() -> None:
    finding = Finding(
        source="security_patterns",
        rule_id="CWE-22",
        title="Path traversal candidate",
        description="User-controlled path reaches open().",
        file="app/files.py",
        line=20,
        end_line=20,
        cwe="CWE-22",
        severity="high",
        confidence=0.9,
        metadata={"function_name": "read_file"},
    )
    unrelated_guard = _guarantee(
        "path.is_within_store == true",
        file="app/files.py",
        line=4,
    )

    hypothesis = hypothesis_for_finding(finding, [unrelated_guard], show_proofs=True)

    assert hypothesis is not None
    assert hypothesis["status"] != "contradicted"
    assert hypothesis["z3"] == {"checked": False, "status": "not_applicable"}
    assert hypothesis["blockers"] == ["guard_in_unrelated_context"]
    assert hypothesis["guard_applicability"][0]["applicable"] is False


def test_homonymous_methods_in_different_classes_do_not_share_guards() -> None:
    source = dedent(
        """\
        import os
        class Safe:
            def read_file(self, path):
                if os.path.commonpath([ROOT, path]) != ROOT:
                    raise ValueError("outside root")
                return open(path).read()

        class Vulnerable:
            def read_file(self, path):
                return open(path).read()
        """
    )
    finding = Finding(
        source="security_patterns",
        rule_id="CWE-22",
        title="Path traversal candidate",
        description="User-controlled path reaches open().",
        file="app/files.py",
        line=10,
        end_line=10,
        cwe="CWE-22",
        severity="high",
        confidence=0.9,
        metadata={
            "function_name": "read_file",
            "predicate_variables": ["path"],
        },
    )

    hypothesis = hypothesis_for_finding(
        finding,
        InvariantMiner().extract(source, "app/files.py"),
        local_context=source,
        show_proofs=True,
    )

    assert hypothesis is not None
    assert hypothesis["status"] != "contradicted"
    assert "guard_in_unrelated_context" in hypothesis["blockers"]


def test_commonpath_after_sink_cannot_counterprove() -> None:
    hypothesis = _local_path_hypothesis(
        dedent(
            """
            import os
            def read_file(p):
                value = open(p).read()
                if os.path.commonpath([ROOT, p]) != ROOT:
                    raise ValueError("outside root")
                return value
            """
        ),
        sink_line=4,
    )

    assert hypothesis["status"] != "contradicted"
    assert "guard_after_sink" in hypothesis["blockers"]


def test_commonpath_on_other_value_cannot_counterprove() -> None:
    hypothesis = _local_path_hypothesis(
        dedent(
            """
            import os
            def read_file(p, other):
                if os.path.commonpath([ROOT, other]) != ROOT:
                    raise ValueError("outside root")
                return open(p).read()
            """
        ),
        sink_line=6,
    )

    assert hypothesis["status"] != "contradicted"
    assert "guard_on_different_value" in hypothesis["blockers"]


def test_reassignment_after_guard_invalidates_guard() -> None:
    hypothesis = _local_path_hypothesis(
        dedent(
            """
            import os
            from flask import request
            def read_file():
                path = request.args["path"]
                if os.path.commonpath([ROOT, path]) != ROOT:
                    raise ValueError("outside root")
                path = request.args["other"]
                return open(path).read()
            """
        ),
        sink_line=9,
    )

    assert hypothesis["status"] != "contradicted"
    assert "guard_on_different_value" in hypothesis["blockers"]


def test_path_guard_with_unknown_sink_value_cannot_counterprove() -> None:
    result = assess_guard_applicability(
        "path.is_within_store == true",
        guard_file="app/files.py",
        guard_line=4,
        guard_function="read_file",
        guard_value="candidate",
        sink_file="app/files.py",
        sink_line=6,
        sink_function="read_file",
        sink_value="",
        case_type="path_traversal_possible",
        direct_context=True,
    )

    assert result.applicable is False
    assert result.blockers == ("flow_not_demonstrated",)


def test_shared_root_constant_does_not_bind_guard_to_other_path_value() -> None:
    result = assess_guard_applicability(
        "path.is_within_store == true",
        guard_file="app/files.py",
        guard_line=5,
        guard_function="read_file",
        guard_value="ROOT,p",
        sink_file="app/files.py",
        sink_line=8,
        sink_function="read_file",
        sink_value="open(os.path.join(ROOT, other))",
        case_type="path_traversal_possible",
        direct_context=True,
    )

    assert result.applicable is False
    assert result.blockers == ("guard_on_different_value",)


def test_ignored_secure_filename_result_cannot_counterprove() -> None:
    hypothesis = _local_path_hypothesis(
        dedent(
            """
            from werkzeug.utils import secure_filename
            def read_file(p):
                secure_filename(p)
                return open(p).read()
            """
        ),
        sink_line=5,
    )

    assert hypothesis["status"] != "contradicted"
    assert "sanitizer_result_unused" in hypothesis["blockers"]


def test_inverted_commonpath_branch_cannot_counterprove() -> None:
    hypothesis = _local_path_hypothesis(
        dedent(
            """
            import os
            def read_file(p):
                if os.path.commonpath([ROOT, p]) == ROOT:
                    raise ValueError("inverted guard")
                return open(p).read()
            """
        ),
        sink_line=6,
    )

    assert hypothesis["status"] != "contradicted"
    assert "flow_not_demonstrated" in hypothesis["blockers"]


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("route.requires_login == true", "authentication_guard"),
        ("route.requires_admin == true", "role_authorization_guard"),
        ("query.owner_id == current_user.id", "ownership_guard"),
        ("query.tenant_id == current_user.tenant_id", "tenant_guard"),
        ("query.scoped_to_current_user == true", "resource_binding_guard"),
        ("filename.matches_allowed_pattern == true", "input_validation_guard"),
        ("path.is_within_store == true", "path_containment_guard"),
        ("html_output.user_values_escaped == true", "sanitizer_guard"),
    ],
)
def test_guard_categories_are_explicit(expression: str, expected: str) -> None:
    assert expected in GUARD_CATEGORIES
    assert classify_guard(expression) == expected


@pytest.mark.parametrize(
    ("overrides", "blocker"),
    [
        ({"guard_line": 20, "sink_line": 10}, "guard_after_sink"),
        (
            {"guard_value": "safe_id", "sink_value": "object_id"},
            "guard_on_different_value",
        ),
        (
            {"guard_function": "authorize_object", "sink_function": "read_object"},
            "guard_in_unrelated_context",
        ),
        ({"bypass_possible": True}, "guard_not_resource_bound"),
    ],
)
def test_authorization_guard_requires_causal_binding(overrides: dict, blocker: str) -> None:
    arguments = {
        "category": "ownership_guard",
        "guard_file": "app/views.py",
        "guard_line": 5,
        "guard_value": "object_id",
        "sink_file": "app/views.py",
        "sink_line": 10,
        "sink_value": "object_id",
        "case_type": "idor_bola_possible",
        "direct_context": True,
    }
    arguments.update(overrides)

    result = assess_guard_applicability("query.owner_id == current_user.id", **arguments)

    assert result.applicable is False
    assert result.blockers == (blocker,)


def test_ignored_sanitizer_return_is_not_an_effective_guard() -> None:
    result = assess_guard_applicability(
        "sanitize(user_path)",
        category="sanitizer_guard",
        guard_file="app/files.py",
        guard_line=4,
        sink_file="app/files.py",
        sink_line=8,
        case_type="path_traversal_possible",
        direct_context=True,
        result_used=False,
    )

    assert result.applicable is False
    assert result.blockers == ("sanitizer_result_unused",)


def test_resource_bound_owner_guard_before_sink_is_applicable() -> None:
    result = assess_guard_applicability(
        "query.owner_id == current_user.id",
        guard_file="app/views.py",
        guard_line=5,
        guard_value="object_id",
        sink_file="app/views.py",
        sink_line=10,
        sink_value="object_id",
        case_type="idor_bola_possible",
        direct_context=True,
    )

    assert result.applicable is True
    assert result.blockers == ()


def test_filter_by_identifier_without_principal_is_not_resource_authorization() -> None:
    result = assess_guard_applicability(
        "Document.query.filter_by(id=attacker_id)",
        guard_file="app/views.py",
        guard_line=5,
        guard_value="attacker_id",
        sink_file="app/views.py",
        sink_line=5,
        sink_value="attacker_id",
        case_type="idor_bola_possible",
        direct_context=True,
    )

    assert result.category == "resource_binding_guard"
    assert result.applicable is False
    assert result.blockers == ("guard_not_resource_bound",)


@pytest.mark.parametrize(
    "guard_statement",
    [
        "Document.query.filter_by(id=document_id, owner_id=current_user.id)",
        "q = Document.query.filter_by(id=document_id, owner_id=current_user.id)\n    print(q)",
    ],
)
def test_unconsumed_or_unrelated_scoped_query_does_not_protect_get(
    guard_statement: str,
) -> None:
    source = (
        "def read_document(document_id):\n"
        f"    {guard_statement}\n"
        "    return Document.query.get(document_id)\n"
    )
    sink_line = len(source.splitlines())
    finding = Finding(
        source="security_patterns",
        rule_id="CWE-639",
        title="IDOR candidate",
        description="Resource identifier reaches an unscoped lookup.",
        file="app/views.py",
        line=sink_line,
        end_line=sink_line,
        cwe="CWE-639",
        severity="high",
        confidence=0.9,
        metadata={
            "function_name": "read_document",
            "predicate_variables": ["document_id"],
        },
    )

    hypothesis = hypothesis_for_finding(
        finding,
        InvariantMiner().extract(source, "app/views.py"),
        local_context=source,
        show_proofs=True,
    )

    assert hypothesis is not None
    assert hypothesis["status"] != "contradicted"
    assert "guard_not_resource_bound" in hypothesis["blockers"]


def test_ordered_structured_flow_counts_as_source_to_sink_evidence() -> None:
    case = _audit_case(
        case_id="case_structured_flow",
        case_type="path_traversal_possible",
        cwe="CWE-22",
        rule_id="CWE-22",
        source="",
        sink="",
        dataflow_path=(),
        route_context={},
        metadata={},
    )
    evidence = {
        "schema_version": "belief.dataflow_evidence.v1",
        "source": {"symbol": "user_path", "line": 4},
        "sink": {"symbol": "open", "line": 7},
        "ordered_nodes": [
            {"symbol": "user_path", "line": 4},
            {"symbol": "open", "line": 7},
        ],
        "ordered_edges": [
            {"source": "user_path", "target": "open", "kind": "argument"},
        ],
    }

    without_flow = assess_audit_case_reportability(case)
    with_flow = assess_audit_case_reportability(
        replace(case, structured_dataflow=evidence)
    )

    assert with_flow.score >= without_flow.score + 20
    assert "ordered local source-to-sink evidence present" in with_flow.positive_factors
    assert "no route, source-to-sink path, or access observation" not in with_flow.negative_factors
    assert "source-to-sink evidence" not in with_flow.missing_evidence


def test_legacy_guard_string_without_execution_proof_is_not_protective() -> None:
    case = _audit_case(
        case_id="case_contained_path",
        case_type="path_traversal_possible",
        cwe="CWE-22",
        rule_id="CWE-22",
        source="requested_path",
        sink="open(candidate)",
        guarantees=("path.is_within_store == true",),
        missing_guarantees=("filename allow-list or server-generated filename",),
        metadata={"category": "path_traversal"},
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.guard_applicability[0]["category"] == "path_containment_guard"
    assert assessment.guard_applicability[0]["applicable"] is False
    assert assessment.blockers == ["flow_not_demonstrated"]
    assert assessment.verdict != "protected_by_guard"


def test_bare_unsat_status_does_not_make_legacy_guard_causal() -> None:
    case = _audit_case(
        case_id="case_bare_unsat",
        case_type="path_traversal_possible",
        cwe="CWE-22",
        rule_id="CWE-22",
        source="requested_path",
        sink="open(candidate)",
        guarantees=("path.is_within_store == true",),
        z3_status="unsat",
        route_context={},
        metadata={"category": "path_traversal"},
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.guard_applicability[0]["applicable"] is False
    assert "flow_not_demonstrated" in assessment.blockers
    assert assessment.verdict != "protected_by_guard"


def test_causal_path_containment_is_sufficient_when_allowlist_is_only_missing_alternative() -> None:
    case = _audit_case(
        case_id="case_structurally_contained_path",
        case_type="path_traversal_possible",
        cwe="CWE-22",
        rule_id="CWE-22",
        source="requested_path",
        sink="open(candidate)",
        guarantees=("path.is_within_store == true",),
        missing_guarantees=("filename allow-list or server-generated filename",),
        structured_dataflow={
            "source": {"file": "app/views.py", "line": 4, "symbol": "requested_path"},
            "sink": {"file": "app/views.py", "line": 8, "symbol": "open(candidate)"},
            "ordered_nodes": [
                {
                    "kind": "source",
                    "expression": "requested_path",
                    "line": 4,
                    "function_name": "read_object",
                    "file": "app/views.py",
                },
                {
                    "kind": "guarantee",
                    "expression": "path.is_within_store == true",
                    "line": 6,
                    "function_name": "read_object",
                    "file": "app/views.py",
                },
                {
                    "kind": "sink",
                    "expression": "open(candidate)",
                    "line": 8,
                    "function_name": "read_object",
                    "file": "app/views.py",
                },
            ],
            "ordered_edges": [
                {"source_id": "source", "target_id": "guard", "kind": "flows_to"},
                {"source_id": "guard", "target_id": "sink", "kind": "flows_to"},
            ],
            "function_context": "read_object",
            "guard_applicability": {
                "guard_applicable": True,
                "reason": "guard_on_dataflow_path_before_sink",
            },
        },
        metadata={"category": "path_traversal"},
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.guard_applicability[0]["applicable"] is True
    assert assessment.verdict == "protected_by_guard"


def test_unvalidated_local_idor_flow_is_capped_at_manual_validation() -> None:
    case = _audit_case(
        case_id="case_static_idor",
        missing_guarantees=("owner or tenant resource binding",),
        human_next_steps=("Validate cross-user access with two disposable test accounts.",),
        structured_dataflow={
            "schema_version": "belief.dataflow_evidence.v1",
            "source": {"symbol": "object_id", "line": 5},
            "sink": {"symbol": "Object.query.get", "line": 6},
            "ordered_nodes": [
                {"symbol": "object_id", "line": 5},
                {"symbol": "Object.query.get", "line": 6},
            ],
            "ordered_edges": [
                {
                    "source": "object_id",
                    "target": "Object.query.get",
                    "kind": "argument",
                },
            ],
        },
    )

    assessment = assess_audit_case_reportability(case)

    assert assessment.score == 79
    assert assessment.verdict == "needs_manual_validation"
    assert (
        "static access-control flow requires manual authorization validation"
        in assessment.negative_factors
    )
