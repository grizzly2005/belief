import copy
import hashlib
import json
import multiprocessing
import shutil
from dataclasses import replace

import pytest

from belief.audit_case import AuditCase
from belief.reportability.scoring import assess_audit_case_reportability
from belief.mcp.validation import prepare_registered_fixture
from belief.validation.ledger import (
    EvidenceArtifact,
    ValidationProofLedger,
    ValidationProofLedgerError,
    run_registered_fixture_validation_with_ledger,
)
from belief.validation.plan_models import canonical_digest
from belief.validation.models import ValidationResult
from belief.validation.plans import (
    build_validation_plan,
    validation_result_from_plan,
)
from belief.validation.proof import (
    ProofAuthorityContext,
    assess_validation_result_proof,
    proof_subject_digest,
)


_AUTHORITY_DIGEST = "c" * 64


def _canonical_bytes(value) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _rewrite_integrity(record: dict) -> None:
    record["integrity"]["record_sha256"] = None
    record["integrity"]["record_sha256"] = hashlib.sha256(
        _canonical_bytes(record)
    ).hexdigest()


def _finish_in_spawned_process(
    root,
    terminal_status,
    result_payload,
    start_event,
    output_queue,
):
    store = ValidationProofLedger(root)
    context = _context()
    attempt = store.resume_attempt(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        attempt_id="vattempt_race",
    )
    start_event.wait(10)
    try:
        receipt = store.finish_attempt(
            attempt,
            terminal_status=terminal_status,
            result=ValidationResult.from_dict(result_payload),
            response_bytes=terminal_status.encode("ascii"),
        )
        output_queue.put(("ok", receipt.terminal_status))
    except Exception as exc:
        output_queue.put((type(exc).__name__, str(exc)))


def _case() -> AuditCase:
    return AuditCase(
        case_id="case-ledger-1",
        case_type="path_traversal_possible",
        status="needs_review",
        review_priority="high",
        confidence=0.95,
        severity="high",
        file="app.py",
        line=30,
        rule_id="CWE-22",
        cwe="CWE-22",
        source="request.args['path']",
        sink="open(path)",
        dataflow_path=("request.args['path']", "open(path)"),
        missing_guarantees=("path stays within the authorized root",),
        human_next_steps=("Run the registered path-boundary oracle.",),
        route_context={"route": "/download", "methods": ["GET"]},
        metadata={
            "tool_signal_type": "external_finding",
            "source_tools": ["semgrep", "codeql"],
            "independent_source_lineages": [
                "semgrep-static",
                "codeql-dataflow",
            ],
            "category": "path_traversal",
            "has_codeflow": True,
        },
    )


def _context(target_id: str = "target-1") -> ProofAuthorityContext:
    return ProofAuthorityContext(
        engagement_id="engagement-1",
        target_id=target_id,
    )


def _plan_and_result(case: AuditCase, *, outcome: str = "bypassed"):
    plan = build_validation_plan(case)
    result = validation_result_from_plan(
        plan,
        source="belief.local_validation_executor.v1",
        outcome=outcome,
        confidence=0.95,
        tested=True,
        method="local_fixture/path_traversal/isolated-worker",
        reason="The registered oracle reached a terminal outcome.",
        evidence=("oracle:path_boundary_invariant",),
        metadata={"validation_plan_digest": canonical_digest(plan.to_dict())},
    )
    return plan, result


def _begin(store: ValidationProofLedger, case: AuditCase, *, attempt_id: str = ""):
    plan, result = _plan_and_result(case)
    attempt = store.begin_attempt(
        _context(),
        plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        subject_sha256=proof_subject_digest(case),
        request_bytes=b'{"request":"bounded"}',
        oracle_id="path_boundary_invariant",
        oracle_version="1",
        attempt_id=attempt_id,
        started_at="2026-08-24T10:00:00Z",
    )
    return attempt, result


def _registered_store(tmp_path) -> ValidationProofLedger:
    store = ValidationProofLedger(tmp_path)
    store.register_scope(
        _context(),
        authority_sha256=_AUTHORITY_DIGEST,
        registered_at="2026-08-24T09:59:00Z",
    )
    return store


def test_attempt_and_request_are_durable_before_execution_and_pending_is_not_proof(
    tmp_path,
):
    store = _registered_store(tmp_path)
    attempt, _ = _begin(store, _case())

    restarted = ValidationProofLedger(tmp_path)
    snapshot = restarted.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )

    assert next(tmp_path.rglob(f"{attempt.attempt_id}.json")).is_file()
    assert next(tmp_path.rglob(attempt.request_ref.sha256)).read_bytes() == (
        b'{"request":"bounded"}'
    )
    assert snapshot.sealed_results == ()


@pytest.mark.parametrize("attempt_id", ["attempt:ads", "CON", "NUL.txt"])
def test_attempt_id_must_be_a_portable_filename(tmp_path, attempt_id):
    store = _registered_store(tmp_path)

    with pytest.raises(
        ValidationProofLedgerError,
        match="portable filename",
    ):
        _begin(store, _case(), attempt_id=attempt_id)

    assert not any(tmp_path.rglob("attempts/*.json"))


def test_scope_attempt_count_is_bounded_on_write_and_restart(tmp_path):
    bounded = ValidationProofLedger(tmp_path, max_scope_attempts=1)
    bounded.register_scope(
        _context(),
        authority_sha256=_AUTHORITY_DIGEST,
        registered_at="2026-08-24T09:59:00Z",
    )
    _begin(bounded, _case(), attempt_id="vattempt_first")

    with pytest.raises(
        ValidationProofLedgerError,
        match="scope exceeds configured attempt limit",
    ):
        _begin(bounded, _case(), attempt_id="vattempt_second")

    unbounded_for_setup = ValidationProofLedger(tmp_path)
    _begin(unbounded_for_setup, _case(), attempt_id="vattempt_second")
    with pytest.raises(
        ValidationProofLedgerError,
        match="scope exceeds configured attempt limit",
    ):
        ValidationProofLedger(tmp_path, max_scope_attempts=1).load_scope(
            _context(),
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )


def test_restart_rolls_forward_auto_id_after_interrupted_attempt_inventory(
    tmp_path,
    monkeypatch,
):
    store = _registered_store(tmp_path)
    original_append = store._append_scope_inventory_entry

    def _interrupt_inventory(_context, *, field_name, record):
        if field_name == "attempts":
            raise RuntimeError("injected interruption before inventory update")
        return original_append(
            _context,
            field_name=field_name,
            record=record,
        )

    monkeypatch.setattr(
        store,
        "_append_scope_inventory_entry",
        _interrupt_inventory,
    )
    with pytest.raises(RuntimeError, match="injected interruption"):
        _begin(store, _case())
    pending = tuple(tmp_path.rglob("pending/attempts/*.json"))
    assert len(pending) == 1
    generated_attempt_id = pending[0].stem

    restarted = ValidationProofLedger(tmp_path)
    snapshot = restarted.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    recovered = restarted.resume_attempt(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
        attempt_id=generated_attempt_id,
    )

    assert recovered.attempt_id == generated_attempt_id
    assert not any(tmp_path.rglob("pending/attempts/*.json"))
    assert snapshot.sealed_results == ()


def test_restart_rolls_forward_attempt_when_only_pending_record_exists(
    tmp_path,
    monkeypatch,
):
    store = _registered_store(tmp_path)
    original_write = store._atomic_write

    def _interrupt_final_attempt_write(destination, data):
        if destination.parent.name == "attempts" and "pending" not in destination.parts:
            raise RuntimeError("injected interruption before attempt publication")
        return original_write(destination, data)

    monkeypatch.setattr(store, "_atomic_write", _interrupt_final_attempt_write)
    with pytest.raises(RuntimeError, match="injected interruption"):
        _begin(store, _case())

    pending = tuple(tmp_path.rglob("pending/attempts/*.json"))
    assert len(pending) == 1
    assert not any(
        path
        for path in tmp_path.rglob("attempts/*.json")
        if "pending" not in path.parts
    )

    restarted = ValidationProofLedger(tmp_path)
    snapshot = restarted.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )

    assert not any(tmp_path.rglob("pending/attempts/*.json"))
    assert next(
        path
        for path in tmp_path.rglob(f"attempts/{pending[0].name}")
        if "pending" not in path.parts
    ).is_file()
    assert snapshot.sealed_results == ()


def test_plain_attempt_orphan_without_pending_intent_still_fails_closed(
    tmp_path,
    monkeypatch,
):
    store = _registered_store(tmp_path)

    def _interrupt_inventory(_context, *, field_name, record):
        raise RuntimeError("injected interruption before inventory update")

    monkeypatch.setattr(
        store,
        "_append_scope_inventory_entry",
        _interrupt_inventory,
    )
    with pytest.raises(RuntimeError, match="injected interruption"):
        _begin(store, _case(), attempt_id="vattempt_plain_orphan")
    pending = next(tmp_path.rglob("pending/attempts/*.json"))
    pending.unlink()

    with pytest.raises(
        ValidationProofLedgerError,
        match="attempt record does not match scope inventory",
    ):
        ValidationProofLedger(tmp_path).load_scope(
            _context(),
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )


def test_snapshot_pinned_load_refuses_pending_recovery_without_mutation(
    tmp_path,
    monkeypatch,
):
    store = _registered_store(tmp_path)
    _begin(store, _case(), attempt_id="vattempt_committed")
    committed = store.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    original_append = store._append_scope_inventory_entry

    def _interrupt_inventory(_context, *, field_name, record):
        if field_name == "attempts":
            raise RuntimeError("injected interruption before inventory update")
        return original_append(
            _context,
            field_name=field_name,
            record=record,
        )

    monkeypatch.setattr(
        store,
        "_append_scope_inventory_entry",
        _interrupt_inventory,
    )
    with pytest.raises(RuntimeError, match="injected interruption"):
        _begin(store, _case())

    inventory_path = next(tmp_path.rglob("inventory.json"))
    pending_path = next(tmp_path.rglob("pending/attempts/*.json"))
    final_path = next(
        path
        for path in tmp_path.rglob(f"attempts/{pending_path.name}")
        if "pending" not in path.parts
    )
    before = (
        inventory_path.read_bytes(),
        pending_path.read_bytes(),
        final_path.read_bytes(),
    )

    restarted = ValidationProofLedger(tmp_path)
    with pytest.raises(
        ValidationProofLedgerError,
        match="pending ledger transaction requires unpinned recovery",
    ):
        restarted.load_scope(
            _context(),
            expected_authority_sha256=_AUTHORITY_DIGEST,
            expected_ledger_snapshot_id=committed.ledger_snapshot_id,
        )

    assert (
        inventory_path.read_bytes(),
        pending_path.read_bytes(),
        final_path.read_bytes(),
    ) == before
    recovered = restarted.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    assert recovered.ledger_snapshot_id != committed.ledger_snapshot_id
    assert not pending_path.exists()


@pytest.mark.parametrize("kind", ["request", "response"])
def test_additional_evidence_rejects_ledger_reserved_kinds(tmp_path, kind):
    store = _registered_store(tmp_path)
    attempt, result = _begin(store, _case())

    with pytest.raises(
        ValidationProofLedgerError,
        match="additional evidence kind is reserved",
    ):
        store.finish_attempt(
            attempt,
            terminal_status="completed",
            result=result,
            response_bytes=b'{"worker_status":"completed"}',
            evidence=(
                EvidenceArtifact(
                    kind=kind,
                    content=b'{"spoofed":true}',
                    media_type="application/json",
                ),
            ),
        )

    assert not any(tmp_path.rglob("terminals/*.json"))


def test_restart_rolls_forward_terminal_after_interrupted_inventory_publication(
    tmp_path,
    monkeypatch,
):
    store = _registered_store(tmp_path)
    attempt, result = _begin(
        store,
        _case(),
        attempt_id="vattempt_recover_terminal",
    )
    original_append = store._append_scope_inventory_entry

    def _interrupt_inventory(_context, *, field_name, record):
        if field_name == "terminals":
            raise RuntimeError("injected interruption before inventory update")
        return original_append(
            _context,
            field_name=field_name,
            record=record,
        )

    monkeypatch.setattr(
        store,
        "_append_scope_inventory_entry",
        _interrupt_inventory,
    )
    with pytest.raises(RuntimeError, match="injected interruption"):
        store.finish_attempt(
            attempt,
            terminal_status="completed",
            result=result,
            response_bytes=b'{"worker_status":"completed"}',
            finished_at="2026-08-24T10:00:01Z",
        )
    assert len(tuple(tmp_path.rglob("pending/terminals/*.json"))) == 1

    restarted = ValidationProofLedger(tmp_path)
    snapshot = restarted.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    recovered = restarted.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b'{"worker_status":"completed"}',
        finished_at="2026-08-24T10:00:01Z",
    )

    assert recovered.replayed is True
    assert not any(tmp_path.rglob("pending/terminals/*.json"))
    assert snapshot.sealed_results == ()


def test_generic_completed_terminal_is_durable_but_cannot_cross_reportability(
    tmp_path,
):
    case = _case()
    store = _registered_store(tmp_path)
    attempt, result = _begin(store, case)

    receipt = store.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b'{"worker_status":"completed"}',
        evidence=(
            EvidenceArtifact(
                kind="oracle",
                content=b'{"path_boundary":"bypassed"}',
                media_type="application/json",
            ),
        ),
        finished_at="2026-08-24T10:00:01Z",
    )
    snapshot = ValidationProofLedger(tmp_path).load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    assessed_case = replace(
        case,
        metadata={
            **case.metadata,
            "validation_results": [receipt.result.to_dict()],
        },
    )

    assessment = assess_audit_case_reportability(
        assessed_case,
        proof_index=snapshot.proof_index,
        proof_context=snapshot.context,
    )

    assert receipt.proof is None
    assert receipt.result is not None
    assert snapshot.sealed_results == ()
    assert assessment.proof_state == "signal_only"
    assert assessment.verdict != "reportable_candidate"
    assert snapshot.ledger_snapshot_id.startswith("vledger_snapshot_")


def test_identical_terminal_replay_is_idempotent_but_conflict_is_rejected(tmp_path):
    store = _registered_store(tmp_path)
    attempt, result = _begin(store, _case(), attempt_id="vattempt_fixed")
    first = store.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b"response",
        finished_at="2026-08-24T10:00:01Z",
    )
    replay = store.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b"response",
        finished_at="2026-08-24T10:05:00Z",
    )

    assert first.replayed is False
    assert replay.replayed is True
    assert replay.proof == first.proof

    _, conflicting = _plan_and_result(_case(), outcome="inconclusive")
    with pytest.raises(
        ValidationProofLedgerError,
        match="different terminal result",
    ):
        store.finish_attempt(
            attempt,
            terminal_status="timed_out",
            result=conflicting,
            response_bytes=b"timeout",
        )


def test_cross_process_terminal_race_has_exactly_one_winner(tmp_path):
    store = _registered_store(tmp_path)
    _begin(store, _case(), attempt_id="vattempt_race")
    _, completed = _plan_and_result(_case(), outcome="bypassed")
    _, timed_out = _plan_and_result(_case(), outcome="inconclusive")
    process_context = multiprocessing.get_context("spawn")
    start_event = process_context.Event()
    output_queue = process_context.Queue()
    processes = [
        process_context.Process(
            target=_finish_in_spawned_process,
            args=(
                str(tmp_path),
                status,
                result.to_dict(),
                start_event,
                output_queue,
            ),
        )
        for status, result in (
            ("completed", completed),
            ("timed_out", timed_out),
        )
    ]
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(30)
        assert process.exitcode == 0
    outcomes = sorted(output_queue.get(timeout=5) for _ in processes)

    assert sum(item[0] == "ok" for item in outcomes) == 1
    assert sum(item[0] == "ValidationProofLedgerError" for item in outcomes) == 1
    assert len(list(tmp_path.rglob("terminals/*.json"))) == 1
    snapshot = store.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    assert snapshot.sealed_results == ()


def test_tampered_cas_fails_scope_reconstruction_closed(tmp_path):
    store = _registered_store(tmp_path)
    attempt, result = _begin(store, _case())
    store.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b"response",
    )
    terminal = json.loads(
        next(tmp_path.rglob("terminals/*.json")).read_text(encoding="utf-8")
    )
    result_ref = next(
        item
        for item in terminal["evidence_refs"]
        if item["evidence_id"].startswith("validation-result:")
    )
    cas_path = next(tmp_path.rglob(result_ref["sha256"]))
    cas_path.write_bytes(b"tampered")

    with pytest.raises(ValidationProofLedgerError, match="CAS object digest mismatch"):
        ValidationProofLedger(tmp_path).load_scope(
            _context(),
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )


def test_tampered_attempt_record_and_wrong_authority_pin_fail_closed(tmp_path):
    store = _registered_store(tmp_path)
    attempt, _ = _begin(store, _case())
    attempt_path = next(tmp_path.rglob(f"{attempt.attempt_id}.json"))
    attempt_path.write_text(
        attempt_path.read_text(encoding="utf-8").replace(
            '"target_id":"target-1"',
            '"target_id":"target-9"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValidationProofLedgerError, match="attempt scope binding"):
        store.load_scope(
            _context(),
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )
    with pytest.raises(ValidationProofLedgerError, match="scope authority binding"):
        store.load_scope(
            _context(),
            expected_authority_sha256="d" * 64,
        )


def test_rehashed_terminal_cannot_relabel_the_captured_worker_response(tmp_path):
    store = _registered_store(tmp_path)
    attempt, result = _begin(store, _case())
    store.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b"response",
    )
    terminal_path = next(tmp_path.rglob("terminals/*.json"))
    terminal = json.loads(terminal_path.read_text(encoding="utf-8"))
    response_ref = next(
        item for item in terminal["evidence_refs"] if item["kind"] == "response"
    )
    response_ref["evidence_id"] = "relabeled-worker-response"
    terminal["evidence_refs"].sort(
        key=lambda item: (item["evidence_id"], item["kind"], item["sha256"])
    )
    _rewrite_integrity(terminal)
    terminal_path.write_bytes(_canonical_bytes(terminal) + b"\n")

    with pytest.raises(
        ValidationProofLedgerError,
        match="response artifact binding",
    ):
        ValidationProofLedger(tmp_path).load_scope(
            _context(),
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )


def test_scope_copy_cannot_rebind_attempt_and_terminal_to_another_target(tmp_path):
    store = _registered_store(tmp_path)
    attempt, result = _begin(store, _case())
    store.finish_attempt(
        attempt,
        terminal_status="completed",
        result=result,
        response_bytes=b"response",
    )
    second_context = _context("target-2")
    store.register_scope(
        second_context,
        authority_sha256=_AUTHORITY_DIGEST,
    )
    first_scope = next(
        path.parent
        for path in tmp_path.rglob("authority.json")
        if b'"target_id":"target-1"' in path.read_bytes()
    )
    second_scope = next(
        path.parent
        for path in tmp_path.rglob("authority.json")
        if b'"target_id":"target-2"' in path.read_bytes()
    )
    shutil.copytree(first_scope / "attempts", second_scope / "attempts")
    shutil.copytree(first_scope / "terminals", second_scope / "terminals")

    with pytest.raises(ValidationProofLedgerError, match="attempt scope binding"):
        store.load_scope(
            second_context,
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )


def test_result_payload_change_with_same_id_and_proof_is_quarantined(tmp_path):
    prepared = prepare_registered_fixture("fx_01d7c2_v1")
    context = ProofAuthorityContext(
        engagement_id="fixture-lab-1",
        target_id=f"registered-fixture:{prepared.fixture_id}",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256=_AUTHORITY_DIGEST)
    result = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
    )
    snapshot = store.load_scope(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    forged = copy.deepcopy(result.to_dict())
    forged["reason"] = "changed after the terminal was sealed"

    assessment = assess_validation_result_proof(
        forged,
        proof_index=snapshot.proof_index,
        engagement_id=context.engagement_id,
        target_id=context.target_id,
        subject_id=prepared.plan.subject_id,
        subject_kind="validation_contract_seed",
        plan_id=prepared.plan.plan_id,
        subject_sha256=prepared.plan.metadata["proof_subject_sha256"],
    )

    assert assessment.state == "quarantined"
    assert assessment.reasons == ("validation_proof_result_sha256_mismatch",)


def test_timeout_terminal_is_durable_but_never_enters_bypass_path(tmp_path):
    store = _registered_store(tmp_path)
    attempt, _ = _begin(store, _case())
    _, inconclusive = _plan_and_result(_case(), outcome="inconclusive")

    receipt = store.finish_attempt(
        attempt,
        terminal_status="timed_out",
        result=inconclusive,
        response_bytes=b'{"worker_status":"timed_out"}',
    )
    snapshot = store.load_scope(
        _context(),
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )

    assert receipt.terminal_status == "timed_out"
    assert receipt.proof is None
    assert receipt.result.outcome == "inconclusive"
    assert snapshot.sealed_results == ()


def test_registered_fixture_wrapper_persists_attempt_before_spawn_and_response(
    tmp_path,
):
    prepared = prepare_registered_fixture("fx_01d7c2_v1")
    context = ProofAuthorityContext(
        engagement_id="fixture-lab-1",
        target_id=f"registered-fixture:{prepared.fixture_id}",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256=_AUTHORITY_DIGEST)
    attempt_existed_before_spawn = []

    def _observe_pre_spawn(_handle):
        attempt_existed_before_spawn.append(
            any(tmp_path.rglob("attempts/*.json"))
        )

    result = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
        on_handle=_observe_pre_spawn,
    )
    snapshot = ValidationProofLedger(tmp_path).load_scope(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )

    assert snapshot.sealed_results[0].result_id == result.result_id
    assert result.metadata["validation_proof"]["target_id"] == context.target_id
    assert attempt_existed_before_spawn == [True]
    assert any(tmp_path.rglob("attempts/*.json"))
    assert any(tmp_path.rglob("terminals/*.json"))
    assessment = assess_validation_result_proof(
        result,
        proof_index=snapshot.proof_index,
        engagement_id=context.engagement_id,
        target_id=context.target_id,
        subject_id=prepared.plan.subject_id,
        subject_kind="validation_contract_seed",
        plan_id=prepared.plan.plan_id,
        subject_sha256=prepared.plan.metadata["proof_subject_sha256"],
    )
    assert assessment.state == "verified"


def test_registered_fixture_rerun_reconstructs_two_proofs_for_one_stable_result(
    tmp_path,
):
    prepared = prepare_registered_fixture("fx_01d7c2_v1")
    context = ProofAuthorityContext(
        engagement_id="fixture-lab-1",
        target_id=f"registered-fixture:{prepared.fixture_id}",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256=_AUTHORITY_DIGEST)

    first = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
    )
    second = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
    )
    snapshot = ValidationProofLedger(tmp_path).load_scope(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )

    assert first.result_id == second.result_id
    assert (
        first.metadata["validation_proof"]["attempt_id"]
        != second.metadata["validation_proof"]["attempt_id"]
    )
    assert len(snapshot.sealed_results) == 2
    assert {item.result_id for item in snapshot.sealed_results} == {
        first.result_id
    }
    for result in snapshot.sealed_results:
        assessment = assess_validation_result_proof(
            result,
            proof_index=snapshot.proof_index,
            engagement_id=context.engagement_id,
            target_id=context.target_id,
            subject_id=prepared.plan.subject_id,
            subject_kind="validation_contract_seed",
            plan_id=prepared.plan.plan_id,
            subject_sha256=prepared.plan.metadata["proof_subject_sha256"],
        )
        assert assessment.state == "verified"


@pytest.mark.parametrize("remove_attempt", [False, True])
def test_scope_inventory_rejects_missing_durable_records(
    tmp_path,
    remove_attempt,
):
    prepared = prepare_registered_fixture("fx_01d7c2_v1")
    context = ProofAuthorityContext(
        engagement_id="fixture-lab-1",
        target_id=f"registered-fixture:{prepared.fixture_id}",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256=_AUTHORITY_DIGEST)
    result = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
    )
    attempt_id = result.metadata["validation_proof"]["attempt_id"]
    next(tmp_path.rglob(f"terminals/{attempt_id}.json")).unlink()
    if remove_attempt:
        next(tmp_path.rglob(f"attempts/{attempt_id}.json")).unlink()

    with pytest.raises(
        ValidationProofLedgerError,
        match="scope inventory (attempt|terminal) set is incomplete",
    ):
        ValidationProofLedger(tmp_path).load_scope(
            context,
            expected_authority_sha256=_AUTHORITY_DIGEST,
        )


def test_external_snapshot_pin_rejects_inventory_and_record_rollback(tmp_path):
    prepared = prepare_registered_fixture("fx_01d7c2_v1")
    context = ProofAuthorityContext(
        engagement_id="fixture-lab-1",
        target_id=f"registered-fixture:{prepared.fixture_id}",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256=_AUTHORITY_DIGEST)
    first = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
    )
    first_snapshot = store.load_scope(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    inventory_path = next(tmp_path.rglob("inventory.json"))
    first_inventory = inventory_path.read_bytes()

    second = run_registered_fixture_validation_with_ledger(
        store,
        context,
        prepared.plan,
        expected_authority_sha256=_AUTHORITY_DIGEST,
        fixture_id=prepared.fixture_id,
        source_revision=prepared.source_revision,
    )
    second_snapshot = store.load_scope(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    assert second_snapshot.ledger_snapshot_id != first_snapshot.ledger_snapshot_id
    assert (
        store.load_scope(
            context,
            expected_authority_sha256=_AUTHORITY_DIGEST,
            expected_ledger_snapshot_id=second_snapshot.ledger_snapshot_id,
        ).ledger_snapshot_id
        == second_snapshot.ledger_snapshot_id
    )

    second_attempt_id = second.metadata["validation_proof"]["attempt_id"]
    assert second_attempt_id != first.metadata["validation_proof"]["attempt_id"]
    next(tmp_path.rglob(f"terminals/{second_attempt_id}.json")).unlink()
    next(tmp_path.rglob(f"attempts/{second_attempt_id}.json")).unlink()
    inventory_path.write_bytes(first_inventory)

    rolled_back = ValidationProofLedger(tmp_path).load_scope(
        context,
        expected_authority_sha256=_AUTHORITY_DIGEST,
    )
    assert rolled_back.ledger_snapshot_id == first_snapshot.ledger_snapshot_id
    with pytest.raises(
        ValidationProofLedgerError,
        match="ledger snapshot does not match the external pin",
    ):
        ValidationProofLedger(tmp_path).load_scope(
            context,
            expected_authority_sha256=_AUTHORITY_DIGEST,
            expected_ledger_snapshot_id=second_snapshot.ledger_snapshot_id,
        )


def test_registered_fixture_wrapper_refuses_arbitrary_project_target(tmp_path):
    prepared = prepare_registered_fixture("fx_01d7c2_v1")
    context = ProofAuthorityContext(
        engagement_id="project-engagement",
        target_id="real-project:production",
    )
    store = ValidationProofLedger(tmp_path)
    store.register_scope(context, authority_sha256=_AUTHORITY_DIGEST)

    with pytest.raises(
        ValidationProofLedgerError,
        match="cannot authorize a project target",
    ):
        run_registered_fixture_validation_with_ledger(
            store,
            context,
            prepared.plan,
            expected_authority_sha256=_AUTHORITY_DIGEST,
            fixture_id=prepared.fixture_id,
            source_revision=prepared.source_revision,
        )

    assert not any(tmp_path.rglob("attempts/*.json"))
