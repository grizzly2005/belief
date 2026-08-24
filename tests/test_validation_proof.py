import copy
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import belief.reportability.scoring as scoring_module
from belief.audit_case import AuditCase
from belief.reportability.scoring import assess_audit_case_reportability
from belief.validation.models import ValidationResult
from belief.validation.proof import (
    ProofAuthorityContext,
    ValidationEvidenceRef,
    ValidationProof,
    ValidationProofError,
    VerifiedProofIndex,
    VerifiedProofMaterial,
    assess_validation_result_proof,
    proof_subject_digest,
    validation_result_proof_digest,
)


_EVIDENCE_DIGEST = "a" * 64
_PLAN_DIGEST = "b" * 64


def _authority_context() -> ProofAuthorityContext:
    return ProofAuthorityContext(
        engagement_id="engagement-1",
        target_id="target-1",
    )


def _proof_and_result(
    *,
    outcome: str = "bypassed",
    attempt_id: str = "attempt-1",
) -> tuple[ValidationProof, dict]:
    result = ValidationResult(
        subject_id="case-1",
        subject_kind="audit_case",
        source="belief.local_validation_executor.v1",
        outcome=outcome,
        confidence=0.95,
        tested=True,
        method="local_fixture/path_traversal/test-adapter",
        reason="A local oracle produced a terminal result.",
    )
    proof = ValidationProof(
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id=result.subject_id,
        subject_kind=result.subject_kind,
        plan_id="plan-1",
        attempt_id=attempt_id,
        result_id=result.result_id,
        outcome=result.outcome,
        oracle_id="path_boundary_invariant",
        oracle_version="1",
        evidence_refs=(
            ValidationEvidenceRef(
                evidence_id="evidence-1",
                kind="oracle",
                sha256=_EVIDENCE_DIGEST,
                media_type="application/json",
            ),
        ),
    )
    payload = result.to_dict()
    payload["metadata"] = {
        "validation_plan_id": proof.plan_id,
        "validation_plan_digest": _PLAN_DIGEST,
        "validation_proof": proof.to_dict(),
    }
    return proof, payload


def _material(proof: ValidationProof, result: dict) -> VerifiedProofMaterial:
    return VerifiedProofMaterial(
        proof=proof,
        engagement_id=proof.engagement_id,
        target_id=proof.target_id,
        subject_id=proof.subject_id,
        subject_kind=proof.subject_kind,
        plan_id=proof.plan_id,
        attempt_id=proof.attempt_id,
        result_id=proof.result_id,
        outcome=proof.outcome,
        oracle_id=proof.oracle_id,
        oracle_version=proof.oracle_version,
        subject_sha256=proof_subject_digest(_high_signal_case({})),
        plan_sha256=_PLAN_DIGEST,
        result_sha256=validation_result_proof_digest(result),
        evidence_bindings={reference.evidence_id: reference for reference in proof.evidence_refs},
        evidence_sha256={"evidence-1": _EVIDENCE_DIGEST},
        evidence_sizes={"evidence-1": 1},
    )


def _high_signal_case(validation_result: dict) -> AuditCase:
    return AuditCase(
        case_id="case-1",
        case_type="path_traversal_possible",
        status="needs_review",
        review_priority="high",
        confidence=0.9,
        severity="high",
        file="app.py",
        line=30,
        rule_id="CWE-22",
        cwe="CWE-22",
        route_context={"route": "/download", "methods": ["GET"]},
        dataflow_path=("request.args['path']", "open(path)"),
        human_next_steps=("Run the authorized path-boundary oracle.",),
        metadata={
            "engagement_id": "engagement-1",
            "target_id": "target-1",
            "tool_signal_type": "external_finding",
            "source_tools": ["semgrep", "codeql"],
            "independent_source_lineages": ["semgrep-static", "codeql-dataflow"],
            "category": "path_traversal",
            "has_codeflow": True,
            "validation_results": [validation_result],
        },
    )


def test_validation_proof_round_trip_and_order_are_canonical():
    proof, _ = _proof_and_result()

    assert ValidationProof.from_dict(proof.to_dict()).to_dict() == proof.to_dict()
    assert proof.proof_id.startswith("vproof_")


def test_validation_proof_rejects_changed_content_with_old_id():
    proof, _ = _proof_and_result()
    changed = copy.deepcopy(proof.to_dict())
    changed["target_id"] = "target-2"

    with pytest.raises(
        ValidationProofError,
        match="id does not match",
    ):
        ValidationProof.from_dict(changed)


def test_verified_index_rejects_missing_or_orphaned_evidence():
    proof, result = _proof_and_result()
    material = _material(proof, result)
    missing = VerifiedProofMaterial(
        **{
            **material.__dict__,
            "evidence_sha256": {},
        }
    )

    with pytest.raises(ValidationProofError, match="evidence set mismatch"):
        VerifiedProofIndex([missing])


def test_cross_target_proof_is_quarantined():
    proof, result = _proof_and_result()
    index = VerifiedProofIndex([_material(proof, result)])

    assessment = assess_validation_result_proof(
        result,
        proof_index=index,
        engagement_id="engagement-1",
        target_id="target-2",
        subject_id="case-1",
        subject_kind="audit_case",
        plan_id="plan-1",
        subject_sha256=proof_subject_digest(_high_signal_case({})),
    )

    assert assessment.state == "quarantined"
    assert assessment.reasons == ("validation_proof_target_id_mismatch",)


def test_forged_legacy_booleans_cannot_make_case_reportable():
    _, result = _proof_and_result()
    result.pop("metadata")
    result["tested"] = True
    result["human_validated"] = True

    assessment = assess_audit_case_reportability(_high_signal_case(result))

    assert assessment.proof_state == "signal_only"
    assert assessment.verdict == "needs_manual_validation"
    assert assessment.score == 79
    assert assessment.legacy_score == 100
    assert "unverified validation claims ignored" in assessment.negative_factors


def test_self_asserted_proof_is_not_trusted_without_verified_index():
    _, result = _proof_and_result()

    assessment = assess_audit_case_reportability(_high_signal_case(result))

    assert assessment.proof_state == "unresolved"
    assert assessment.verdict == "needs_manual_validation"
    assert assessment.score == 79
    assert assessment.verified_proof_ids == []
    assert "validation_proof_unresolved" in assessment.negative_factors


def test_non_finite_validation_result_is_quarantined_without_scoring_crash():
    _, result = _proof_and_result()
    result["metadata"]["validation_proof"]["attempt_id"] = float("nan")

    assessment = assess_audit_case_reportability(_high_signal_case(result))

    assert assessment.proof_state == "quarantined"
    assert "validation_result_not_finite_json" in assessment.negative_factors
    assert assessment.score == 79


def test_identical_validation_results_are_deduplicated_across_carriers(monkeypatch):
    _, result = _proof_and_result()
    case = _high_signal_case(result)
    case.metadata["external_raw"] = {
        "validation_results": [copy.deepcopy(result)],
        "pdx": {"validation_results": [copy.deepcopy(result)]},
    }
    calls = []

    def _capture(_result, **_kwargs):
        calls.append(_result)
        return SimpleNamespace(state="signal_only", reasons=(), proof_id="")

    monkeypatch.setattr(scoring_module, "assess_validation_result_proof", _capture)

    assess_audit_case_reportability(case)

    assert calls == [result]


def test_proof_state_precedence_is_fail_closed():
    state = lambda value: SimpleNamespace(state=value)

    assert scoring_module._proof_state([state("verified"), state("signal_only")]) == ("verified")
    assert scoring_module._proof_state([state("unresolved"), state("verified")]) == ("unresolved")
    assert scoring_module._proof_state([state("quarantined"), state("unresolved")]) == (
        "quarantined"
    )


def test_synthetic_legacy_authority_pair_cannot_cross_reportability_gate():
    proof, result = _proof_and_result()
    index = VerifiedProofIndex([_material(proof, result)])

    with pytest.raises(TypeError, match="legacy proof_index/proof_context"):
        assess_audit_case_reportability(
            _high_signal_case(result),
            proof_index=index,
            proof_context=_authority_context(),
        )


def test_case_metadata_cannot_supply_the_authority_context():
    proof, result = _proof_and_result()
    index = VerifiedProofIndex([_material(proof, result)])

    assessment = assess_validation_result_proof(
        result,
        proof_index=index,
        engagement_id="",
        target_id="",
        subject_id="case-1",
        subject_kind="audit_case",
        plan_id="plan-1",
        subject_sha256=proof_subject_digest(_high_signal_case({})),
    )

    assert assessment.state == "quarantined"
    assert assessment.reasons == ("validation_proof_binding_context_missing",)


def test_case_metadata_conflicting_with_authority_context_is_quarantined():
    proof, result = _proof_and_result()
    index = VerifiedProofIndex([_material(proof, result)])
    case = _high_signal_case(result)
    case.metadata["target_id"] = "target-2"

    assessment = assess_validation_result_proof(
        result,
        proof_index=index,
        engagement_id="engagement-1",
        target_id="target-2",
        subject_id=case.case_id,
        subject_kind="audit_case",
        plan_id="plan-1",
        subject_sha256=proof_subject_digest(case),
    )

    assert assessment.state == "quarantined"
    assert "validation_proof_target_id_mismatch" in assessment.reasons


def test_validation_proof_matches_strict_json_schema():
    proof, _ = _proof_and_result()
    schema_path = (
        Path(__file__).resolve().parents[1] / "schemas" / "belief-validation-proof-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    payload = proof.to_dict()
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(payload)
    assert schema["properties"]["schema_version"]["const"] == (payload["schema_version"])
    assert payload["outcome"] in schema["properties"]["outcome"]["enum"]
    ref_schema = schema["properties"]["evidence_refs"]["items"]
    assert ref_schema["additionalProperties"] is False
    assert set(ref_schema["required"]) == set(payload["evidence_refs"][0])


def test_same_case_id_with_changed_subject_content_is_quarantined():
    proof, result = _proof_and_result()
    index = VerifiedProofIndex([_material(proof, result)])
    changed = replace(
        _high_signal_case(result),
        file="different.py",
        line=999,
    )

    assessment = assess_validation_result_proof(
        result,
        proof_index=index,
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id=changed.case_id,
        subject_kind="audit_case",
        plan_id="plan-1",
        subject_sha256=proof_subject_digest(changed),
    )

    assert assessment.state == "quarantined"
    assert "validation_proof_subject_sha256_mismatch" in assessment.reasons


def test_subject_digest_ignores_nested_derived_proof_carriers():
    baseline = _high_signal_case({})
    metadata = copy.deepcopy(baseline.metadata)
    metadata["external_raw"] = {
        "proofs": [{"proof_id": "forged"}],
        "validation_results": [{"outcome": "bypassed"}],
        "pdx": {
            "proofs": [{"proof_id": "forged-pdx"}],
            "validation_results": [{"outcome": "bypassed"}],
        },
    }
    carried = replace(baseline, metadata=metadata)

    assert proof_subject_digest(carried) == proof_subject_digest(baseline)


def test_subject_digest_still_binds_non_derived_external_raw_fields():
    baseline = _high_signal_case({})
    changed = replace(
        baseline,
        metadata={
            **baseline.metadata,
            "external_raw": {"pdx": {"source_revision": "revision-2"}},
        },
    )

    assert proof_subject_digest(changed) != proof_subject_digest(baseline)


def test_verified_proof_index_internal_mappings_are_read_only():
    proof, result = _proof_and_result()
    index = VerifiedProofIndex([_material(proof, result)])

    with pytest.raises(TypeError):
        index._proofs[proof.proof_id] = _material(proof, result)
    with pytest.raises(TypeError):
        index._quarantined_proofs[proof.proof_id] = "forged"
    with pytest.raises(AttributeError, match="immutable"):
        index._proofs = {proof.proof_id: _material(proof, result)}
    with pytest.raises(AttributeError, match="immutable"):
        index._quarantined_proofs = {proof.proof_id: "forged"}
    with pytest.raises(AttributeError, match="immutable"):
        del index._sealed
    with pytest.raises(AttributeError, match="immutable"):
        del index._proofs
    with pytest.raises(AttributeError, match="immutable"):
        del index._quarantined_proofs


def test_index_allows_identical_result_id_and_digest_across_distinct_attempts():
    first_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    second_proof = ValidationProof(
        **{
            **first_proof.__dict__,
            "attempt_id": "attempt-2",
            "proof_id": "",
        }
    )
    second_result = copy.deepcopy(first_result)
    second_result["metadata"]["validation_proof"] = second_proof.to_dict()

    index = VerifiedProofIndex(
        [
            _material(first_proof, first_result),
            _material(second_proof, second_result),
        ]
    )

    resolved, reasons = index.resolve(
        second_proof,
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id="case-1",
        subject_kind="audit_case",
        plan_id="plan-1",
        result_id=second_proof.result_id,
        outcome=second_proof.outcome,
        subject_sha256=proof_subject_digest(_high_signal_case({})),
        plan_sha256=_PLAN_DIGEST,
        result_sha256=validation_result_proof_digest(second_result),
    )

    assert resolved is True
    assert reasons == ()


def _proof_for_attempt(
    proof: ValidationProof,
    result: dict,
    *,
    attempt_id: str,
    evidence_refs: tuple[ValidationEvidenceRef, ...] | None = None,
) -> tuple[ValidationProof, dict]:
    changed_proof = ValidationProof(
        **{
            **proof.__dict__,
            "attempt_id": attempt_id,
            "evidence_refs": evidence_refs or proof.evidence_refs,
            "proof_id": "",
        }
    )
    changed_result = copy.deepcopy(result)
    changed_result["metadata"]["validation_proof"] = changed_proof.to_dict()
    return changed_proof, changed_result


def _regenerate_result_id(result: dict, **changes: object) -> dict:
    changed_result = copy.deepcopy(result)
    changed_result.update(changes)
    changed_result["result_id"] = ""
    return ValidationResult.from_dict(changed_result).to_dict()


def _resolve_material(
    index: VerifiedProofIndex,
    proof: ValidationProof,
    result: dict,
) -> tuple[bool, tuple[str, ...]]:
    return index.resolve(
        proof,
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id="case-1",
        subject_kind="audit_case",
        plan_id=proof.plan_id,
        result_id=proof.result_id,
        outcome=proof.outcome,
        subject_sha256=proof_subject_digest(_high_signal_case({})),
        plan_sha256=_PLAN_DIGEST,
        result_sha256=validation_result_proof_digest(result),
    )


def test_index_quarantines_confidence_only_result_id_collision():
    first_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    second_result = _regenerate_result_id(first_result, confidence=0.75)
    second_proof, second_result = _proof_for_attempt(
        first_proof,
        second_result,
        attempt_id="attempt-2",
    )

    assert first_result["result_id"] == second_result["result_id"]
    assert validation_result_proof_digest(first_result) != (
        validation_result_proof_digest(second_result)
    )
    index = VerifiedProofIndex(
        [
            _material(first_proof, first_result),
            _material(second_proof, second_result),
        ]
    )

    expected = (False, ("validation_proof_result_id_collision",))
    assert _resolve_material(index, first_proof, first_result) == expected
    assert _resolve_material(index, second_proof, second_result) == expected


def test_index_quarantines_metadata_only_result_id_collision():
    first_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    changed_metadata = copy.deepcopy(first_result["metadata"])
    changed_metadata["trusted_worker_generation"] = 2
    second_result = _regenerate_result_id(
        first_result,
        metadata=changed_metadata,
    )
    second_proof, second_result = _proof_for_attempt(
        first_proof,
        second_result,
        attempt_id="attempt-2",
    )

    assert first_result["result_id"] == second_result["result_id"]
    assert validation_result_proof_digest(first_result) != (
        validation_result_proof_digest(second_result)
    )
    index = VerifiedProofIndex(
        [
            _material(first_proof, first_result),
            _material(second_proof, second_result),
        ]
    )

    expected = (False, ("validation_proof_result_id_collision",))
    assert _resolve_material(index, first_proof, first_result) == expected
    assert _resolve_material(index, second_proof, second_result) == expected


def test_result_id_collision_quarantine_is_input_order_independent():
    first_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    second_result = _regenerate_result_id(first_result, confidence=0.75)
    second_proof, second_result = _proof_for_attempt(
        first_proof,
        second_result,
        attempt_id="attempt-2",
    )
    first = _material(first_proof, first_result)
    second = _material(second_proof, second_result)

    expected = (False, ("validation_proof_result_id_collision",))
    for materials in ([first, second], [second, first]):
        index = VerifiedProofIndex(materials)
        assert _resolve_material(index, first_proof, first_result) == expected
        assert _resolve_material(index, second_proof, second_result) == expected


def test_result_id_collision_does_not_quarantine_unrelated_proof():
    first_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    second_result = _regenerate_result_id(first_result, confidence=0.75)
    second_proof, second_result = _proof_for_attempt(
        first_proof,
        second_result,
        attempt_id="attempt-2",
    )
    third_proof, third_result = _proof_and_result(
        outcome="enforced",
        attempt_id="attempt-3",
    )

    index = VerifiedProofIndex(
        [
            _material(first_proof, first_result),
            _material(second_proof, second_result),
            _material(third_proof, third_result),
        ]
    )

    assert _resolve_material(index, third_proof, third_result) == (True, ())


def test_result_id_collision_does_not_mask_other_evidence_identity_conflicts():
    first_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    second_result = _regenerate_result_id(first_result, confidence=0.75)
    changed_ref = ValidationEvidenceRef(
        evidence_id="evidence-1",
        kind="response",
        sha256="d" * 64,
        media_type="application/json",
    )
    second_proof, second_result = _proof_for_attempt(
        first_proof,
        second_result,
        attempt_id="attempt-2",
        evidence_refs=(changed_ref,),
    )
    second_base = _material(second_proof, second_result)
    second = VerifiedProofMaterial(
        **{
            **second_base.__dict__,
            "evidence_sha256": {"evidence-1": "d" * 64},
            "evidence_sizes": {"evidence-1": 2},
        }
    )
    third_proof, third_result = _proof_and_result(
        outcome="enforced",
        attempt_id="attempt-3",
    )

    with pytest.raises(
        ValidationProofError,
        match="evidence_id has conflicting global identity: evidence-1",
    ):
        VerifiedProofIndex(
            [
                _material(first_proof, first_result),
                second,
                _material(third_proof, third_result),
            ]
        )


def test_result_id_collision_quarantines_its_derived_result_evidence_binding():
    first_base_proof, first_result = _proof_and_result(attempt_id="attempt-1")
    result_evidence_id = f"validation-result:{first_result['result_id']}"
    first_result_digest = validation_result_proof_digest(first_result)
    first_ref = ValidationEvidenceRef(
        evidence_id=result_evidence_id,
        kind="artifact",
        sha256=first_result_digest,
        media_type="application/vnd.belief.validation-result.v1+json",
    )
    first_proof, first_result = _proof_for_attempt(
        first_base_proof,
        first_result,
        attempt_id="attempt-1",
        evidence_refs=(first_ref,),
    )
    second_result = _regenerate_result_id(first_result, confidence=0.75)
    second_ref = replace(
        first_ref,
        sha256=validation_result_proof_digest(second_result),
    )
    second_proof, second_result = _proof_for_attempt(
        first_proof,
        second_result,
        attempt_id="attempt-2",
        evidence_refs=(second_ref,),
    )

    first_base = _material(first_proof, first_result)
    first = VerifiedProofMaterial(
        **{
            **first_base.__dict__,
            "evidence_bindings": {result_evidence_id: first_ref},
            "evidence_sha256": {result_evidence_id: first_ref.sha256},
            "evidence_sizes": {result_evidence_id: 10},
        }
    )
    second_base = _material(second_proof, second_result)
    second = VerifiedProofMaterial(
        **{
            **second_base.__dict__,
            "evidence_bindings": {result_evidence_id: second_ref},
            "evidence_sha256": {result_evidence_id: second_ref.sha256},
            "evidence_sizes": {result_evidence_id: 11},
        }
    )

    index = VerifiedProofIndex([first, second])
    expected = (False, ("validation_proof_result_id_collision",))
    assert _resolve_material(index, first_proof, first_result) == expected
    assert _resolve_material(index, second_proof, second_result) == expected


def test_index_rejects_one_plan_id_with_conflicting_full_digests():
    first_proof, first_result = _proof_and_result(
        outcome="bypassed",
        attempt_id="attempt-1",
    )
    second_proof, second_result = _proof_and_result(
        outcome="enforced",
        attempt_id="attempt-2",
    )
    first = _material(first_proof, first_result)
    second = VerifiedProofMaterial(
        **{
            **_material(second_proof, second_result).__dict__,
            "plan_sha256": "c" * 64,
        }
    )

    with pytest.raises(
        ValidationProofError,
        match="plan_id has conflicting canonical digests",
    ):
        VerifiedProofIndex([first, second])


def test_index_rejects_evidence_id_relabelled_to_another_blob():
    first_proof, first_result = _proof_and_result(
        outcome="bypassed",
        attempt_id="attempt-1",
    )
    second_result = ValidationResult(
        subject_id="case-1",
        subject_kind="audit_case",
        source="belief.local_validation_executor.v1",
        outcome="enforced",
        tested=True,
        method="local_fixture/path_traversal/test-adapter",
        reason="A second terminal outcome.",
    ).to_dict()
    changed_ref = ValidationEvidenceRef(
        evidence_id="evidence-1",
        kind="response",
        sha256="d" * 64,
        media_type="application/json",
    )
    second_proof = ValidationProof(
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id="case-1",
        subject_kind="audit_case",
        plan_id="plan-2",
        attempt_id="attempt-2",
        result_id=second_result["result_id"],
        outcome="enforced",
        oracle_id="path_boundary_invariant",
        oracle_version="1",
        evidence_refs=(changed_ref,),
    )
    second_result["metadata"] = {
        "validation_plan_id": "plan-2",
        "validation_plan_digest": "c" * 64,
        "validation_proof": second_proof.to_dict(),
    }
    second = VerifiedProofMaterial(
        proof=second_proof,
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id="case-1",
        subject_kind="audit_case",
        plan_id="plan-2",
        attempt_id="attempt-2",
        result_id=second_proof.result_id,
        outcome="enforced",
        oracle_id="path_boundary_invariant",
        oracle_version="1",
        subject_sha256=proof_subject_digest(_high_signal_case({})),
        plan_sha256="c" * 64,
        result_sha256=validation_result_proof_digest(second_result),
        evidence_bindings={"evidence-1": changed_ref},
        evidence_sha256={"evidence-1": "d" * 64},
        evidence_sizes={"evidence-1": 2},
    )

    with pytest.raises(
        ValidationProofError,
        match="evidence_id has conflicting global identity",
    ):
        VerifiedProofIndex([_material(first_proof, first_result), second])
