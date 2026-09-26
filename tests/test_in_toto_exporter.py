"""Contract tests for the unsigned in-toto validation exporter."""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from belief.exporters.in_toto import (
    BELIEF_VALIDATION_EXTENSION,
    BELIEF_VALIDATION_EXTENSION_SCHEMA,
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    SIMPLE_VERIFICATION_RESULT_TYPE,
    InTotoExportError,
    PolicyReference,
    build_validation_svr_statement,
    prepare_dsse_payload,
    serialize_in_toto_statement,
)
from belief.validation.models import ValidationResult
from belief.validation.proof import ValidationEvidenceRef, ValidationProof


def _result() -> ValidationResult:
    return ValidationResult(
        subject_id="case-1",
        subject_kind="audit_case",
        source="belief.local_validation_executor.v1",
        outcome="bypassed",
        confidence=0.95,
        tested=True,
        method="registered_fixture/path_traversal",
        reason="The bounded oracle observed a path boundary bypass.",
    )


def _proof(result: ValidationResult) -> ValidationProof:
    return ValidationProof(
        engagement_id="engagement-1",
        target_id="target-1",
        subject_id=result.subject_id,
        subject_kind=result.subject_kind,
        plan_id="plan-1",
        attempt_id="attempt-1",
        result_id=result.result_id,
        outcome=result.outcome,
        oracle_id="path_boundary_invariant",
        oracle_version="1",
        evidence_refs=(
            ValidationEvidenceRef(
                evidence_id="response-1",
                kind="response",
                sha256="b" * 64,
                media_type="application/json",
            ),
            ValidationEvidenceRef(
                evidence_id="oracle-1",
                kind="oracle",
                sha256="a" * 64,
                media_type="application/json",
            ),
        ),
    )


def _statement(**overrides):
    result = overrides.pop("result", _result())
    proof = overrides.pop("proof", _proof(result))
    values = {
        "proof_state": "verified",
        "subject_name": "pkg:github/example/service@0123456",
        "subject_sha256": "c" * 64,
        "verifier_id": "https://belief.example/verifiers/local-validation/v1",
        "tool_id": "https://belief.example/tools/belief-sec/v0.2.0",
        "policies": (
            PolicyReference(
                uri="https://belief.example/policies/scope/v1",
                sha256="e" * 64,
                name="scope-policy",
            ),
            PolicyReference(
                uri="https://belief.example/policies/path-boundary/v1",
                sha256="d" * 64,
                name="path-boundary-policy",
            ),
        ),
        "time_created": datetime(
            2026,
            9,
            4,
            12,
            30,
            45,
            120000,
            tzinfo=timezone(timedelta(hours=2)),
        ),
    }
    values.update(overrides)
    return build_validation_svr_statement(result, proof=proof, **values)


def test_builds_v1_statement_with_vetted_svr_and_bound_belief_evidence():
    result = _result()
    proof = _proof(result)

    statement = _statement(result=result, proof=proof)

    assert statement["_type"] == IN_TOTO_STATEMENT_TYPE
    assert statement["predicateType"] == SIMPLE_VERIFICATION_RESULT_TYPE
    assert statement["subject"] == [{
        "name": "pkg:github/example/service@0123456",
        "digest": {"sha256": "c" * 64},
    }]
    predicate = statement["predicate"]
    assert predicate["timeCreated"] == "2026-09-04T10:30:45.12Z"
    assert predicate["properties"] == [
        "BELIEF_PROOF_STATE_VERIFIED",
        "BELIEF_VALIDATION_OUTCOME_BYPASSED",
    ]
    assert predicate["verifier"] == {
        "id": "https://belief.example/verifiers/local-validation/v1",
        "policies": [
            {
                "uri": "https://belief.example/policies/path-boundary/v1",
                "digest": {"sha256": "d" * 64},
                "name": "path-boundary-policy",
            },
            {
                "uri": "https://belief.example/policies/scope/v1",
                "digest": {"sha256": "e" * 64},
                "name": "scope-policy",
            },
        ],
    }
    extension = predicate[BELIEF_VALIDATION_EXTENSION]
    assert extension["schemaVersion"] == BELIEF_VALIDATION_EXTENSION_SCHEMA
    assert extension["tool"] == {
        "uri": "https://belief.example/tools/belief-sec/v0.2.0",
        "name": result.source,
    }
    assert extension["result"] == {
        "resultId": result.result_id,
        "subjectId": result.subject_id,
        "subjectKind": result.subject_kind,
        "source": result.source,
        "outcome": result.outcome,
        "method": result.method,
    }
    assert extension["proof"]["proofId"] == proof.proof_id
    assert extension["proof"]["evidence"] == [
        {
            "name": "oracle-1",
            "digest": {"sha256": "a" * 64},
            "mediaType": "application/json",
            "annotations": {"beliefEvidenceKind": "oracle"},
        },
        {
            "name": "response-1",
            "digest": {"sha256": "b" * 64},
            "mediaType": "application/json",
            "annotations": {"beliefEvidenceKind": "response"},
        },
    ]


def test_statement_serialization_and_dsse_inputs_are_deterministic_not_an_envelope():
    statement = _statement()

    first = serialize_in_toto_statement(statement)
    second = serialize_in_toto_statement(dict(reversed(list(statement.items()))))
    prepared = prepare_dsse_payload(statement)

    assert first == second == prepared.payload
    assert prepared.payload_type == DSSE_PAYLOAD_TYPE
    assert json.loads(first) == statement
    assert b'"signatures"' not in first
    assert b'"payload"' not in first


def test_signal_only_statement_is_explicit_and_cannot_smuggle_a_proof():
    statement = _statement(proof=None, proof_state="signal_only")

    assert statement["predicate"]["properties"] == []
    proof_binding = statement["predicate"][BELIEF_VALIDATION_EXTENSION]["proof"]
    assert proof_binding == {"state": "signal_only", "evidence": []}

    with pytest.raises(InTotoExportError, match="cannot carry"):
        _statement(proof_state="signal_only")


@pytest.mark.parametrize("state", ["unresolved", "quarantined"])
def test_unverified_outcomes_do_not_become_standard_svr_verified_properties(state):
    statement = _statement(proof_state=state)

    assert statement["predicate"]["properties"] == []
    extension = statement["predicate"][BELIEF_VALIDATION_EXTENSION]
    assert extension["proof"]["state"] == state
    assert extension["result"]["outcome"] == "bypassed"


@pytest.mark.parametrize("state", ["verified", "unresolved", "quarantined"])
def test_non_signal_proof_states_require_a_structural_proof(state):
    with pytest.raises(InTotoExportError, match="requires a validation proof"):
        _statement(proof=None, proof_state=state)


def test_rejects_unknown_proof_state_and_result_proof_mismatch():
    with pytest.raises(InTotoExportError, match="unsupported proof state"):
        _statement(proof_state="trusted")

    result = _result()
    mismatched = replace(result, subject_id="case-2", result_id="")
    with pytest.raises(InTotoExportError, match="binding mismatch"):
        _statement(result=mismatched, proof=_proof(result))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("subject_sha256", "A" * 64, "lowercase SHA-256"),
        ("subject_sha256", "a" * 63, "lowercase SHA-256"),
        ("verifier_id", "belief-verifier", "absolute"),
        ("tool_id", "https://BELIEF.example/tool/v1", "case-normalized"),
        ("tool_id", "HTTPS://belief.example/tool/v1", "case-normalized"),
        ("tool_id", "https://belief.example/tool/%zz", "absolute"),
        ("tool_id", "https://belief.example/tool/a|b", "absolute"),
        ("tool_id", "https://:443/tool/v1", "absolute"),
        ("subject_name", "bad\nname", "invalid"),
        ("subject_name", " padded", "invalid"),
    ],
)
def test_rejects_invalid_subject_digests_and_identifiers(field, value, message):
    with pytest.raises(InTotoExportError, match=message):
        _statement(**{field: value})


def test_rejects_invalid_or_ambiguous_policy_identity():
    with pytest.raises(InTotoExportError, match="policy sha256"):
        PolicyReference(uri="https://belief.example/policy/v1", sha256="bad")
    with pytest.raises(InTotoExportError, match="policy uri"):
        PolicyReference(uri="relative/policy", sha256="a" * 64)
    with pytest.raises(InTotoExportError, match="policy name"):
        PolicyReference(uri="urn:belief:policy:v1", sha256="a" * 64, name=1)  # type: ignore[arg-type]
    duplicate_uri = (
        PolicyReference(uri="urn:belief:policy:v1", sha256="a" * 64),
        PolicyReference(uri="urn:belief:policy:v1", sha256="b" * 64),
    )
    with pytest.raises(InTotoExportError, match="duplicate URIs"):
        _statement(policies=duplicate_uri)


def test_missing_policy_references_are_represented_by_the_required_empty_array():
    statement = _statement(policies=())

    assert statement["predicate"]["verifier"]["policies"] == []


def test_timestamp_must_be_aware_and_is_normalized_to_utc():
    with pytest.raises(InTotoExportError, match="timezone-aware"):
        _statement(time_created=datetime(2026, 9, 4, 10, 30, 45))

    statement = _statement(
        time_created=datetime(2026, 9, 4, 10, 30, 45, tzinfo=timezone.utc)
    )
    assert statement["predicate"]["timeCreated"] == "2026-09-04T10:30:45Z"


def test_timestamp_keeps_four_digit_years_and_rejects_utc_overflow():
    statement = _statement(time_created=datetime(1, 1, 1, tzinfo=timezone.utc))
    assert statement["predicate"]["timeCreated"] == "0001-01-01T00:00:00Z"

    with pytest.raises(InTotoExportError, match="supported UTC range"):
        _statement(
            time_created=datetime(1, 1, 1, tzinfo=timezone(timedelta(hours=1)))
        )


def test_policy_and_evidence_order_do_not_change_serialized_signing_inputs():
    result = _result()
    proof = _proof(result)
    policies = (
        PolicyReference("urn:belief:policy:b", "b" * 64),
        PolicyReference("urn:belief:policy:a", "a" * 64),
    )
    first = _statement(result=result, proof=proof, policies=policies)
    second = _statement(
        result=result,
        proof=replace(proof, evidence_refs=tuple(reversed(proof.evidence_refs))),
        policies=tuple(reversed(policies)),
    )

    assert prepare_dsse_payload(first) == prepare_dsse_payload(second)
