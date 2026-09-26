"""Offline integration of a synthetic static signal, trusted proof, and unsigned export."""

from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import json

import pytest

from belief.exporters.in_toto import (
    BELIEF_VALIDATION_EXTENSION,
    PolicyReference,
    build_validation_svr_statement,
    prepare_dsse_payload,
)
from belief.reportability.scoring import assess_audit_case_reportability
from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target
from belief.validation.audit_case_executor import (
    AuditCaseEvidence,
    AuditCaseExecutorOutput,
    AuditCaseProofGrant,
    AuditCaseProofPolicy,
    BoundedAuditCaseExecutor,
    run_audit_case_validation_with_ledger,
)
from belief.validation.ledger import ValidationProofLedger, ValidationProofLedgerError
from belief.validation.plans import build_validation_plan
from belief.validation.proof import ProofAuthorityContext, ValidationProof, proof_subject_digest


pytestmark = [pytest.mark.security, pytest.mark.integration]


def test_static_signal_requires_replayed_ledger_proof_before_verified_export(tmp_path):
    # The callback below is an explicitly trusted synthetic test executor. This
    # test checks integration contracts; it does not execute analyzed source.
    source = b"import os\n\ndef download(root, name):\n    return open(os.path.join(root, name)).read()\n"
    target = tmp_path / "download.py"
    target.write_bytes(source)
    analysis = analyze_static_target(
        target,
        StaticAnalysisOptions(
            selected_categories=frozenset({"security"}),
            include_audit_cases=True,
            audit_mode=True,
        ),
    )
    case = next(case for case in analysis.audit_cases if case.case_type == "path_traversal_possible")
    case = replace(
        case,
        route_context={"path": "/download"},
        human_next_steps=("Validate the synthetic fixture's path boundary.",),
    )
    assert assess_audit_case_reportability(case).verdict != "reportable_candidate"
    plan = build_validation_plan(case)
    target_digest = sha256(source).hexdigest()
    executor_digest = sha256(b"synthetic-test-executor-v1").hexdigest()
    oracle_digest = sha256(b"synthetic-test-oracle-v1").hexdigest()
    policy = AuditCaseProofPolicy(
        authority_id="integration-test",
        authority_version="1",
        engagement_id="synthetic-engagement",
        target_id="synthetic-download",
        target_revision="1" * 40,
        target_sha256=target_digest,
        executor_id="synthetic-executor",
        executor_version="1",
        executor_sha256=executor_digest,
        oracle_id="synthetic-oracle",
        oracle_version="1",
        oracle_sha256=oracle_digest,
        grants=(AuditCaseProofGrant.for_case(case, plan),),
        allowed_outcomes=("bypassed",),
        max_evidence_refs=2,
        max_total_evidence_bytes=4096,
    )
    context = ProofAuthorityContext(policy.engagement_id, policy.target_id)
    ledger_root = tmp_path / "ledger"
    ledger = ValidationProofLedger(ledger_root)
    ledger.register_scope(context, authority_sha256=policy.policy_sha256)

    def execute(request):
        return AuditCaseExecutorOutput(
            outcome="bypassed",
            oracle_passed=True,
            observed_target_revision=request.policy.target_revision,
            observed_target_sha256=sha256(target.read_bytes()).hexdigest(),
            observed_subject_sha256=proof_subject_digest(request.audit_case),
            method="synthetic/integration",
            reason="Synthetic oracle result for an integration contract test.",
            evidence=(
                AuditCaseEvidence("synthetic-oracle", "oracle", b'{"passed":true}'),
                AuditCaseEvidence("synthetic-observation", "observation", b"synthetic fixture"),
            ),
        )

    executor = BoundedAuditCaseExecutor(
        executor_id=policy.executor_id,
        executor_version=policy.executor_version,
        executor_sha256=executor_digest,
        oracle_id=policy.oracle_id,
        oracle_version=policy.oracle_version,
        oracle_sha256=oracle_digest,
        callback=execute,
    )
    result = run_audit_case_validation_with_ledger(
        ledger,
        context,
        case,
        plan,
        policy=policy,
        expected_authority_sha256=policy.policy_sha256,
        executor=executor,
    )
    snapshot = ValidationProofLedger(ledger_root).load_scope(
        context, expected_authority_sha256=policy.policy_sha256,
    )
    enriched = replace(case, metadata={**case.metadata, "validation_results": [result.to_dict()]})
    assert proof_subject_digest(enriched) == proof_subject_digest(case)
    untrusted = assess_audit_case_reportability(enriched)
    assert untrusted.proof_state == "unresolved"
    assert untrusted.verdict != "reportable_candidate"
    verified = assess_audit_case_reportability(enriched, proof_snapshot=snapshot)
    assert verified.proof_state == "verified"
    assert verified.verdict == "reportable_candidate"
    assert "verified bypass proof present" in verified.positive_factors
    proof = ValidationProof.from_dict(result.metadata["validation_proof"])
    common = {
        "proof": proof,
        "subject_name": "synthetic/download.py",
        "subject_sha256": target_digest,
        "verifier_id": "urn:belief:integration-verifier",
        "tool_id": "urn:belief:integration-tool",
        "policies": (PolicyReference("urn:belief:integration-policy", policy.policy_sha256),),
        "time_created": datetime(2026, 9, 14, tzinfo=timezone.utc),
    }
    unresolved_statement = build_validation_svr_statement(result, proof_state=untrusted.proof_state, **common)
    assert unresolved_statement["predicate"]["properties"] == []
    statement = build_validation_svr_statement(result, proof_state=verified.proof_state, **common)
    payload = prepare_dsse_payload(statement)
    assert payload == prepare_dsse_payload(statement)
    decoded = json.loads(payload.payload)
    assert "BELIEF_PROOF_STATE_VERIFIED" in decoded["predicate"]["properties"]
    assert decoded["subject"][0]["digest"]["sha256"] == target_digest
    assert decoded["predicate"][BELIEF_VALIDATION_EXTENSION]["proof"]["proofId"] == proof.proof_id
    assert "signatures" not in decoded
    oracle_ref = next(ref for ref in proof.evidence_refs if ref.kind == "oracle")
    next(ledger_root.rglob(oracle_ref.sha256)).write_bytes(b"tampered")
    with pytest.raises(ValidationProofLedgerError, match="digest"):
        ValidationProofLedger(ledger_root).load_scope(
            context, expected_authority_sha256=policy.policy_sha256,
        )
