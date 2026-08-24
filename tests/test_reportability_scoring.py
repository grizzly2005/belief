from types import SimpleNamespace

import pytest

import belief.reportability.scoring as scoring_module
from belief.audit_case import AuditCase
from belief.reportability.scoring import (
    assess_audit_case_reportability,
    assess_many,
    attach_reportability_to_cases,
)
from belief.tool_results.mapper import (
    access_observation_to_audit_case,
    external_finding_to_audit_case,
)
from belief.tool_results.merger import merge_audit_cases
from belief.tools.schemas import AccessObservation, ExternalFinding
from belief.validation.ledger import ValidationProofLedger, VerifiedProofSnapshot
from belief.validation.proof import ProofAuthorityContext, VerifiedProofIndex


def _proof_snapshot(tmp_path) -> VerifiedProofSnapshot:
    context = ProofAuthorityContext(
        engagement_id="engagement-snapshot",
        target_id="target-snapshot",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256="b" * 64)
    return store.load_scope(context, expected_authority_sha256="b" * 64)


def _snapshot_case(case_id, *, metadata=None) -> AuditCase:
    return AuditCase(
        case_id=case_id,
        case_type="external_tool_signal",
        status="needs_review",
        review_priority="medium",
        confidence=0.5,
        severity="medium",
        file="app.py",
        line=4,
        rule_id="EXTERNAL",
        cwe="",
        metadata=metadata or {},
    )


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


def test_proof_snapshot_derives_index_and_context_as_one_input(monkeypatch, tmp_path):
    snapshot = _proof_snapshot(tmp_path)
    case = _snapshot_case(
        "case_snapshot",
        metadata={
            "engagement_id": snapshot.context.engagement_id,
            "target_id": snapshot.context.target_id,
            "validation_results": [{}],
        },
    )
    calls = []

    def _capture_proof_inputs(_result, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(state="signal_only", reasons=(), proof_id="")

    monkeypatch.setattr(
        scoring_module,
        "assess_validation_result_proof",
        _capture_proof_inputs,
    )

    assess_audit_case_reportability(case, proof_snapshot=snapshot)

    assert len(calls) == 1
    assert calls[0]["proof_index"] is snapshot.proof_index
    assert calls[0]["engagement_id"] == snapshot.context.engagement_id
    assert calls[0]["target_id"] == snapshot.context.target_id


def test_proof_snapshot_is_required_instead_of_legacy_pair(tmp_path):
    snapshot = _proof_snapshot(tmp_path)
    case = _snapshot_case(
        "case_snapshot_compat",
        metadata={"target_id": "different-target"},
    )

    atomic = assess_audit_case_reportability(case, proof_snapshot=snapshot)

    assert "validation_proof_target_id_context_mismatch" in atomic.negative_factors
    with pytest.raises(TypeError, match="legacy proof_index/proof_context"):
        assess_audit_case_reportability(
            case,
            proof_index=snapshot.proof_index,
            proof_context=snapshot.context,
        )


def test_snapshot_cannot_be_mixed_with_legacy_inputs_even_for_empty_batches(tmp_path):
    snapshot = _proof_snapshot(tmp_path)
    case = _snapshot_case("case_snapshot_mixed")

    with pytest.raises(TypeError, match="legacy proof_index/proof_context"):
        assess_audit_case_reportability(
            case,
            proof_snapshot=snapshot,
            proof_index=snapshot.proof_index,
        )
    with pytest.raises(TypeError, match="legacy proof_index/proof_context"):
        assess_many(
            (),
            proof_snapshot=snapshot,
            proof_context=snapshot.context,
        )
    with pytest.raises(TypeError, match="legacy proof_index/proof_context"):
        attach_reportability_to_cases(
            (),
            proof_snapshot=snapshot,
            proof_index=snapshot.proof_index,
        )


@pytest.mark.parametrize(
    "call",
    (
        lambda value: assess_many((), proof_snapshot=value),
        lambda value: attach_reportability_to_cases((), proof_snapshot=value),
    ),
)
def test_empty_batch_rejects_invalid_snapshot_type(call):
    with pytest.raises(TypeError, match="VerifiedProofSnapshot"):
        call(object())


def test_reportability_rejects_snapshot_subclass_authority_override():
    class ForgedSnapshot(VerifiedProofSnapshot):
        def __init__(self):
            pass

        def _authority_inputs(self):
            raise AssertionError("subclass authority method must not be called")

    with pytest.raises(TypeError, match="VerifiedProofSnapshot"):
        assess_audit_case_reportability(
            _snapshot_case("case-subclass-forged"),
            proof_snapshot=ForgedSnapshot(),
        )


def test_verified_snapshot_public_constructor_is_closed():
    with pytest.raises(TypeError, match="ValidationProofLedger.load_scope"):
        VerifiedProofSnapshot(
            context=ProofAuthorityContext(
                engagement_id="engagement-forged",
                target_id="target-forged",
            ),
            proof_index=VerifiedProofIndex(),
            sealed_results=(),
            ledger_snapshot_id="vledger_snapshot_" + "a" * 24,
            authority_sha256="b" * 64,
        )


def test_reportability_rejects_snapshot_without_ledger_origin():
    forged = object.__new__(VerifiedProofSnapshot)
    object.__setattr__(
        forged,
        "context",
        ProofAuthorityContext(
            engagement_id="engagement-forged",
            target_id="target-forged",
        ),
    )
    object.__setattr__(forged, "proof_index", VerifiedProofIndex())

    with pytest.raises(TypeError, match="not a ledger-origin snapshot"):
        assess_audit_case_reportability(
            _snapshot_case("case-forged"),
            proof_snapshot=forged,
        )
