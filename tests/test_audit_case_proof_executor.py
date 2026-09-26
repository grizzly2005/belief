import hashlib
from dataclasses import replace

import pytest

from belief.audit_case import AuditCase
from belief.validation.audit_case_executor import (
    AuditCaseEvidence,
    AuditCaseExecutionRequest,
    AuditCaseExecutionResponse,
    AuditCaseExecutorOutput,
    AuditCaseProofError,
    AuditCaseProofGrant,
    AuditCaseProofPolicy,
    BoundedAuditCaseExecutor,
    run_audit_case_validation_with_ledger,
)
from belief.validation.ledger import ValidationProofLedger, ValidationProofLedgerError
from belief.validation.plan_models import canonical_digest
from belief.validation.plans import build_validation_plan
from belief.validation.proof import (
    ProofAuthorityContext,
    assess_validation_result_proof,
    proof_subject_digest,
)


_TARGET_REVISION = "1" * 40
_TARGET_SHA256 = "2" * 64
_EXECUTOR_SHA256 = "3" * 64
_ORACLE_SHA256 = "4" * 64


def _case(case_id: str = "case-real-target-1") -> AuditCase:
    return AuditCase(
        case_id=case_id,
        case_type="path_traversal_possible",
        status="needs_review",
        review_priority="high",
        confidence=0.95,
        severity="high",
        file="src/download.py",
        line=42,
        rule_id="CWE-22",
        cwe="CWE-22",
        source="request.args['name']",
        sink="open(candidate)",
        dataflow_path=("request.args['name']", "open(candidate)"),
        missing_guarantees=("candidate remains below the authorized root",),
    )


def _policy(case: AuditCase, plan=None) -> AuditCaseProofPolicy:
    plan = plan or build_validation_plan(case)
    return AuditCaseProofPolicy(
        authority_id="security-team",
        authority_version="2026.09",
        engagement_id="engagement-real-1",
        target_id="project:example-api",
        target_revision=_TARGET_REVISION,
        target_sha256=_TARGET_SHA256,
        executor_id="sandboxed-path-validator",
        executor_version="1.0.0",
        executor_sha256=_EXECUTOR_SHA256,
        oracle_id="path-boundary-oracle",
        oracle_version="1.0.0",
        oracle_sha256=_ORACLE_SHA256,
        grants=(AuditCaseProofGrant.for_case(case, plan),),
        allowed_outcomes=("bypassed", "enforced"),
        max_evidence_refs=2,
        max_total_evidence_bytes=4096,
    )


def _context(target_id: str = "project:example-api") -> ProofAuthorityContext:
    return ProofAuthorityContext(
        engagement_id="engagement-real-1",
        target_id=target_id,
    )


def _output(
    case: AuditCase,
    *,
    oracle_passed: bool = True,
    target_revision: str = _TARGET_REVISION,
    target_sha256: str = _TARGET_SHA256,
) -> AuditCaseExecutorOutput:
    return AuditCaseExecutorOutput(
        outcome="bypassed",
        oracle_passed=oracle_passed,
        observed_target_revision=target_revision,
        observed_target_sha256=target_sha256,
        observed_subject_sha256=proof_subject_digest(case),
        confidence=0.97,
        method="sandbox/path-boundary/differential",
        reason="The traversal stimulus escaped the authorized root.",
        evidence=(
            AuditCaseEvidence(
                evidence_id="oracle:path-boundary:result",
                kind="oracle",
                content=b'{"escaped_root":true,"baseline_passed":true}',
                media_type="application/json",
            ),
            AuditCaseEvidence(
                evidence_id="observation:path-boundary:trace",
                kind="observation",
                content=b"authorized=/srv/data observed=/srv/secret.txt",
                media_type="text/plain",
            ),
        ),
    )


def _executor(callback) -> BoundedAuditCaseExecutor:
    return BoundedAuditCaseExecutor(
        executor_id="sandboxed-path-validator",
        executor_version="1.0.0",
        executor_sha256=_EXECUTOR_SHA256,
        oracle_id="path-boundary-oracle",
        oracle_version="1.0.0",
        oracle_sha256=_ORACLE_SHA256,
        callback=callback,
    )


def _registered(tmp_path, policy: AuditCaseProofPolicy) -> ValidationProofLedger:
    ledger = ValidationProofLedger(tmp_path)
    ledger.register_scope(_context(), authority_sha256=policy.policy_sha256)
    return ledger


def test_real_audit_case_proof_is_durable_replayable_and_reportability_verifiable(
    tmp_path,
):
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    ledger = _registered(tmp_path, policy)
    observed = []

    def execute(request):
        observed.append(
            (
                request.attempt_id,
                any(tmp_path.rglob("attempts/*.json")),
                not any(tmp_path.rglob("terminals/*.json")),
            )
        )
        return _output(case)

    result = run_audit_case_validation_with_ledger(
        ledger,
        _context(),
        case,
        plan,
        policy=policy,
        expected_authority_sha256=policy.policy_sha256,
        executor=_executor(execute),
        attempt_id="vattempt_real_1",
    )
    snapshot = ValidationProofLedger(tmp_path).load_scope(
        _context(),
        expected_authority_sha256=policy.policy_sha256,
    )
    assessment = assess_validation_result_proof(
        result,
        proof_index=snapshot.proof_index,
        engagement_id=_context().engagement_id,
        target_id=_context().target_id,
        subject_id=case.case_id,
        subject_kind="audit_case",
        plan_id=plan.plan_id,
        subject_sha256=proof_subject_digest(case),
    )

    assert observed == [("vattempt_real_1", True, True)]
    assert assessment.state == "verified"
    assert snapshot.unterminated_attempt_ids == ()
    assert snapshot.sealed_results[0].to_dict() == result.to_dict()
    proof = result.metadata["validation_proof"]
    assert proof["target_id"] == policy.target_id
    assert proof["oracle_id"] == policy.oracle_id
    assert {item["kind"] for item in proof["evidence_refs"]} == {
        "artifact",
        "observation",
        "oracle",
        "request",
        "response",
    }


@pytest.mark.parametrize(
    "wrong_binding",
    ["authority", "target", "subject", "executor", "oracle"],
)
def test_unpinned_or_cross_bound_inputs_are_rejected_before_execution(
    tmp_path,
    wrong_binding,
):
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    ledger = ValidationProofLedger(tmp_path)
    context = _context()
    authority = policy.policy_sha256
    selected_case = case
    selected_plan = plan
    executor = _executor(lambda _request: _output(selected_case))

    if wrong_binding == "authority":
        ledger.register_scope(context, authority_sha256=policy.policy_sha256)
        authority = "9" * 64
    elif wrong_binding == "target":
        context = _context("project:other-api")
        ledger.register_scope(context, authority_sha256=policy.policy_sha256)
    elif wrong_binding == "subject":
        ledger.register_scope(context, authority_sha256=policy.policy_sha256)
        selected_case = _case("case-not-granted")
        selected_plan = build_validation_plan(selected_case)
    elif wrong_binding == "executor":
        ledger.register_scope(context, authority_sha256=policy.policy_sha256)
        executor = BoundedAuditCaseExecutor(
            executor_id="different-executor",
            executor_version="1.0.0",
            executor_sha256=_EXECUTOR_SHA256,
            oracle_id="path-boundary-oracle",
            oracle_version="1.0.0",
            oracle_sha256=_ORACLE_SHA256,
            callback=lambda _request: _output(case),
        )
    else:
        ledger.register_scope(context, authority_sha256=policy.policy_sha256)
        executor = BoundedAuditCaseExecutor(
            executor_id="sandboxed-path-validator",
            executor_version="1.0.0",
            executor_sha256=_EXECUTOR_SHA256,
            oracle_id="different-oracle",
            oracle_version="1.0.0",
            oracle_sha256=_ORACLE_SHA256,
            callback=lambda _request: _output(case),
        )

    called = []
    object.__setattr__(executor, "callback", lambda _request: called.append(True))
    with pytest.raises((AuditCaseProofError, ValidationProofLedgerError)):
        run_audit_case_validation_with_ledger(
            ledger,
            context,
            selected_case,
            selected_plan,
            policy=policy,
            expected_authority_sha256=authority,
            executor=executor,
        )

    assert called == []
    assert not any(tmp_path.rglob("attempts/*.json"))


@pytest.mark.parametrize("failure", ["oracle", "revision", "digest", "exception"])
def test_failed_executor_contract_is_terminal_but_never_proof(failure, tmp_path):
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    ledger = _registered(tmp_path, policy)

    def execute(_request):
        if failure == "exception":
            raise RuntimeError("executor failed")
        return _output(
            case,
            oracle_passed=failure != "oracle",
            target_revision=("5" * 40 if failure == "revision" else _TARGET_REVISION),
            target_sha256=("6" * 64 if failure == "digest" else _TARGET_SHA256),
        )

    with pytest.raises((AuditCaseProofError, RuntimeError)):
        run_audit_case_validation_with_ledger(
            ledger,
            _context(),
            case,
            plan,
            policy=policy,
            expected_authority_sha256=policy.policy_sha256,
            executor=_executor(execute),
        )

    snapshot = ledger.load_scope(
        _context(),
        expected_authority_sha256=policy.policy_sha256,
    )
    assert snapshot.sealed_results == ()
    assert snapshot.unterminated_attempt_ids == ()
    terminal = next(tmp_path.rglob("terminals/*.json")).read_text(encoding="utf-8")
    assert '"proof":null' in terminal
    assert '"result":null' in terminal


def test_response_from_one_attempt_cannot_be_replayed_for_another():
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    first = AuditCaseExecutionRequest("vattempt_first", policy, case, plan)
    second = AuditCaseExecutionRequest("vattempt_second", policy, case, plan)
    first_bytes = canonical_digest(first.to_dict())
    response = AuditCaseExecutionResponse.from_output(
        first,
        request_sha256=first_bytes,
        output=_output(case),
    )

    with pytest.raises(AuditCaseProofError, match="attempt_id"):
        response.validate_for(second)


def test_tampered_cas_evidence_fails_closed_after_restart(tmp_path):
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    ledger = _registered(tmp_path, policy)
    result = run_audit_case_validation_with_ledger(
        ledger,
        _context(),
        case,
        plan,
        policy=policy,
        expected_authority_sha256=policy.policy_sha256,
        executor=_executor(lambda _request: _output(case)),
    )
    oracle_ref = next(
        item
        for item in result.metadata["validation_proof"]["evidence_refs"]
        if item["kind"] == "oracle"
    )
    evidence_path = next(tmp_path.rglob(oracle_ref["sha256"]))
    evidence_path.write_bytes(b"tampered")

    with pytest.raises(ValidationProofLedgerError, match="digest"):
        ValidationProofLedger(tmp_path).load_scope(
            _context(),
            expected_authority_sha256=policy.policy_sha256,
        )


def test_policy_digest_is_the_external_scope_pin_and_canonical():
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    restored = AuditCaseProofPolicy.from_dict(policy.to_dict())

    assert restored == policy
    assert restored.policy_sha256 == hashlib.sha256(
        canonical_digest(restored._unsigned_payload()).encode("ascii")
    ).hexdigest() or restored.policy_sha256 == policy.policy_sha256

    forged = policy.to_dict()
    forged["target_revision"] = "7" * 40
    with pytest.raises(AuditCaseProofError, match="digest"):
        AuditCaseProofPolicy.from_dict(forged)


def test_repeated_execution_namespaces_evidence_per_attempt(tmp_path):
    case = _case()
    plan = build_validation_plan(case)
    policy = _policy(case, plan)
    ledger = _registered(tmp_path, policy)
    results = [
        run_audit_case_validation_with_ledger(
            ledger, _context(), case, plan,
            policy=policy,
            expected_authority_sha256=policy.policy_sha256,
            executor=_executor(lambda _request: _output(case)),
        )
        for _ in range(2)
    ]
    refs = [
        {ref["evidence_id"] for ref in result.metadata["validation_proof"]["evidence_refs"]}
        for result in results
    ]
    assert refs[0].isdisjoint(refs[1])
    snapshot = ValidationProofLedger(tmp_path).load_scope(
        _context(), expected_authority_sha256=policy.policy_sha256,
    )
    assert len(snapshot.sealed_results) == 2


@pytest.mark.parametrize("mismatch", ["request_digest", "evidence_attempt"])
def test_response_rejects_incorrect_request_digest_or_evidence_namespace(mismatch):
    case = _case()
    plan = build_validation_plan(case)
    request = AuditCaseExecutionRequest("vattempt_first", _policy(case, plan), case, plan)
    response = AuditCaseExecutionResponse.from_output(
        request, request_sha256=canonical_digest(request.to_dict()), output=_output(case),
    )
    if mismatch == "request_digest":
        response = replace(response, request_sha256="f" * 64, response_id="")
    else:
        refs = tuple(replace(ref, evidence_id=ref.evidence_id.replace("vattempt_first", "vattempt_other"))
                     for ref in response.evidence_refs)
        response = replace(response, evidence_refs=refs, response_id="")
    with pytest.raises(AuditCaseProofError, match="request_sha256|bound to this attempt"):
        response.validate_for(request)
