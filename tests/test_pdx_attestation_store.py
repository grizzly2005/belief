from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.json_contracts import strict_json_dumps
from belief.pdx.attestation import (
    attestation_sha256,
    canonical_attestation_bytes,
    parse_attestation,
    parse_engagement,
)
from belief.pdx.attestation_store import PDXEvidenceStore, PDXEvidenceStoreError


CAPTURE_ID = "12345678-1234-4234-8234-123456789abc"
TARGET_ID = "pdx:target:sha256:" + ("a" * 64)
OTHER_TARGET_ID = "pdx:target:sha256:" + ("b" * 64)
ENDPOINT_ID = "pdx:endpoint:sha256:" + ("c" * 64)
CONTEXT_ID = "pdx:context:sha256:" + ("d" * 64)


def _engagement(**overrides):
    value = {
        "schema_version": "belief.pdx_engagement.v1",
        "engagement_id": "engagement-alpha",
        "engagement_version": 3,
        "status": "active",
        "owner_ref": "owner:alpha",
        "scope_ref": "scope:alpha:v3",
        "scope_sha256": "e" * 64,
        "authorization_ref": "authorization:alpha:v3",
        "policy_ref": "policy:alpha:v3",
        "budget_ref": "budget:alpha:v3",
        "valid_from": "2026-08-01T00:00:00Z",
        "valid_until": "2026-09-01T00:00:00Z",
        "target_ids": [TARGET_ID],
    }
    value.update(overrides)
    return value


def _attestation(*, partial=False, **overrides):
    identity = {
        "identity_state": "complete",
        "engagement_id": "engagement-alpha",
        "target_id": TARGET_ID,
        "endpoint_id": ENDPOINT_ID,
        "correlation_state": "joinable",
        "correlation_key": CONTEXT_ID,
        "missing": [],
    }
    if partial:
        identity.update(
            {
                "identity_state": "partial",
                "correlation_state": "non_joinable",
                "correlation_key": None,
                "missing": ["session", "actor", "role", "tenant", "workflow", "workflow_step"],
            }
        )
    observation = {
        "capture_id": CAPTURE_ID,
        "observed_at": "2026-08-23T10:00:00Z",
        "observation_hash": "f" * 64,
        "request_sha256": "1" * 64,
        "response_sha256": "2" * 64,
        "contract_state": "accepted",
        "truncated_any": False,
        "payload_integrity": {
            "request_raw": "verified",
            "request_body": "verified",
            "response_raw": "verified",
            "response_body": "verified",
        },
        "identity": identity,
    }
    document = {
        "schema_version": "pdx.observation_attestation.v1",
        "attestation_id": "pdx:observation-attestation:sha256:" + ("0" * 64),
        "created_at": "2026-08-23T10:01:00Z",
        "engagement": {
            "engagement_id": "engagement-alpha",
            "engagement_version": 3,
            "scope_ref": "scope:alpha:v3",
            "scope_sha256": "e" * 64,
            "authorization_ref": "authorization:alpha:v3",
        },
        "producer": {
            "tool_id": "pdx",
            "exporter_version": "1.0.0",
            "observation_contract": "pdx.http_observation.v2",
            "observation_canonicalization": "pdx-json-digest-v1",
        },
        "observations": [observation],
        "loss_manifest": {
            "projection": "metadata-and-digests-only",
            "omitted": ["request_bytes", "response_bytes", "headers", "timing", "pdx_cas_references"],
            "cas_exposed": False,
            "source_truncated_capture_ids": [],
            "projected_fields_lossless": True,
        },
        "integrity": {
            "canonicalization": "pdx-observation-attestation-json-v1",
            "attestation_sha256": "0" * 64,
        },
    }
    for path, value in overrides.items():
        if path.startswith("observation__"):
            observation[path.removeprefix("observation__")] = value
        elif path.startswith("identity__"):
            identity[path.removeprefix("identity__")] = value
        elif path.startswith("engagement__"):
            document["engagement"][path.removeprefix("engagement__")] = value
        else:
            document[path] = value
    if observation["truncated_any"]:
        document["loss_manifest"]["source_truncated_capture_ids"] = [observation["capture_id"]]
    digest = attestation_sha256(document)
    document["integrity"]["attestation_sha256"] = digest
    document["attestation_id"] = f"pdx:observation-attestation:sha256:{digest}"
    return document


def _raw(document) -> bytes:
    return strict_json_dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def test_strict_models_accept_exact_documents_and_reject_extra_fields():
    assert parse_engagement(_engagement())["status"] == "active"
    document = _attestation()
    assert parse_attestation(document)["attestation_id"] == document["attestation_id"]
    hostile = copy.deepcopy(document)
    hostile["observations"][0]["request"] = {"raw": "secret"}
    with pytest.raises(ValueError, match="keys are not exact"):
        parse_attestation(hostile)


def test_attestation_canonicalization_uses_literal_utf8_like_pdx():
    document = _attestation()
    document["producer"]["exporter_version"] = "version-é"
    digest = attestation_sha256(document)
    document["integrity"]["attestation_sha256"] = digest
    document["attestation_id"] = f"pdx:observation-attestation:sha256:{digest}"

    canonical = canonical_attestation_bytes(document)
    assert "version-é".encode() in canonical
    assert b"\\u00e9" not in canonical
    assert parse_attestation(document)["attestation_id"] == document["attestation_id"]


def test_deeply_nested_json_is_rejected_with_a_durable_receipt(tmp_path):
    raw = (b"[" * 2_000) + b"0" + (b"]" * 2_000)

    result = PDXEvidenceStore(tmp_path).import_attestation_bytes(
        raw,
        received_at="2026-08-23T10:02:00Z",
    )

    assert result.receipt["status"] == "REJECT"
    assert result.receipt["reason_codes"] == ["invalid_attestation"]
    assert result.receipt["attestation_id"] is None


def test_register_accept_and_exact_replay_survive_restart(tmp_path):
    first = PDXEvidenceStore(tmp_path)
    registration = first.register_engagement(_engagement())
    raw = _raw(_attestation())

    imported = first.import_attestation_bytes(raw, received_at="2026-08-23T10:02:00Z")
    restarted = PDXEvidenceStore(tmp_path)
    replay = restarted.import_attestation_bytes(raw, received_at="2026-08-23T11:00:00Z")

    assert registration["status"] == "registered"
    assert imported.receipt["status"] == "ACCEPT"
    assert imported.receipt["observation_refs"][0]["proof_state"] == (
        "signal_only_no_belief_attempt_result_evidence"
    )
    assert replay.replayed is True
    assert replay.receipt == imported.receipt
    assert len(list((tmp_path / "receipts").rglob("*.json"))) == 1


@pytest.mark.parametrize(
    ("engagement", "attestation", "reason"),
    [
        (None, _attestation(), "engagement_not_registered"),
        (_engagement(), _attestation(engagement__scope_sha256="9" * 64), "scope_sha256_mismatch"),
        (_engagement(status="suspended"), _attestation(), "engagement_not_active"),
        (_engagement(target_ids=[OTHER_TARGET_ID]), _attestation(), "target_not_authorized"),
        (
            _engagement(valid_until="2026-08-10T00:00:00Z"),
            _attestation(),
            "observation_outside_engagement_validity",
        ),
    ],
)
def test_authority_binding_failures_are_quarantined_without_observation_claims(
    tmp_path, engagement, attestation, reason
):
    store = PDXEvidenceStore(tmp_path)
    if engagement is not None:
        store.register_engagement(engagement)

    result = store.import_attestation_bytes(_raw(attestation), received_at="2026-08-23T10:02:00Z")

    assert result.receipt["status"] == "QUARANTINE"
    assert reason in result.receipt["reason_codes"]
    assert result.receipt["observation_refs"] == []


def test_invalid_hash_is_rejected_without_trusting_claimed_identity(tmp_path):
    store = PDXEvidenceStore(tmp_path)
    document = _attestation()
    document["integrity"]["attestation_sha256"] = "0" * 64

    result = store.import_attestation_bytes(_raw(document), received_at="2026-08-23T10:02:00Z")

    assert result.receipt["status"] == "REJECT"
    assert result.receipt["reason_codes"] == ["invalid_attestation"]
    assert result.receipt["attestation_id"] is None
    assert result.receipt["engagement_id"] is None
    assert result.receipt["observation_refs"] == []


def test_same_capture_hash_is_deduplicated_but_conflicting_hash_is_quarantined(tmp_path):
    store = PDXEvidenceStore(tmp_path)
    store.register_engagement(_engagement())
    first = store.import_attestation_bytes(_raw(_attestation()), received_at="2026-08-23T10:02:00Z")
    same = store.import_attestation_bytes(
        _raw(_attestation(created_at="2026-08-23T10:03:00Z")),
        received_at="2026-08-23T10:04:00Z",
    )
    conflict = store.import_attestation_bytes(
        _raw(_attestation(created_at="2026-08-23T10:05:00Z", observation__observation_hash="3" * 64)),
        received_at="2026-08-23T10:06:00Z",
    )

    assert first.receipt["status"] == "ACCEPT"
    assert same.receipt["status"] == "ACCEPT"
    assert "observation_already_imported" in same.receipt["caveats"]
    assert conflict.receipt["status"] == "QUARANTINE"
    assert conflict.receipt["reason_codes"] == ["capture_id_hash_conflict"]
    assert conflict.receipt["observation_refs"] == []


def test_non_joinable_and_truncated_observation_is_accepted_only_as_caveated_signal(tmp_path):
    store = PDXEvidenceStore(tmp_path)
    store.register_engagement(_engagement())
    document = _attestation(
        partial=True,
        observation__truncated_any=True,
        observation__payload_integrity={
            "request_raw": "producer_declared",
            "request_body": "verified",
            "response_raw": "verified",
            "response_body": "verified",
        },
    )

    result = store.import_attestation_bytes(_raw(document), received_at="2026-08-23T10:02:00Z")

    assert result.receipt["status"] == "ACCEPT"
    assert "identity_non_joinable_signal_only" in result.receipt["caveats"]
    assert "source_observation_truncated" in result.receipt["caveats"]
    assert "one_or_more_full_payload_hashes_are_producer_declared" in result.receipt["caveats"]


def test_persistent_store_contains_metadata_only_and_detects_registration_tampering(tmp_path):
    store = PDXEvidenceStore(tmp_path)
    store.register_engagement(_engagement())
    store.import_attestation_bytes(_raw(_attestation()), received_at="2026-08-23T10:02:00Z")

    stored = b"\n".join(path.read_bytes() for path in tmp_path.rglob("*.json"))
    assert b"request_bytes" not in stored
    assert b"response_bytes" not in stored
    assert b"pdx_cas_references" not in stored
    assert b"request_sha256" not in stored
    assert b"response_sha256" not in stored

    registration = next((tmp_path / "engagements").rglob("*.json"))
    registration.write_text(registration.read_text(encoding="utf-8").replace("owner:alpha", "owner:other"), encoding="utf-8")
    with pytest.raises(PDXEvidenceStoreError, match="content hash"):
        PDXEvidenceStore(tmp_path).register_engagement(_engagement(owner_ref="owner:other"))


def test_store_initialization_cleans_owned_temporary_files_under_the_store_lock(tmp_path):
    temporary = tmp_path / "receipts" / "sha256" / "aa" / ".receipt.json.tmp-interrupted"
    ordinary = temporary.parent / "keep.txt"
    temporary.parent.mkdir(parents=True)
    temporary.write_bytes(b"partial")
    ordinary.write_bytes(b"keep")

    PDXEvidenceStore(tmp_path)

    assert not temporary.exists()
    assert ordinary.read_bytes() == b"keep"


def test_cross_process_import_serialization_prevents_conflicting_accepts(tmp_path):
    journal = tmp_path / "journal"
    PDXEvidenceStore(journal).register_engagement(_engagement())
    first_path = tmp_path / "first.json"
    second_path = tmp_path / "second.json"
    first_path.write_bytes(_raw(_attestation()))
    second_path.write_bytes(
        _raw(
            _attestation(
                created_at="2026-08-23T10:05:00Z",
                observation__observation_hash="3" * 64,
            )
        )
    )
    commands = [
        [
            sys.executable,
            "-m",
            "belief",
            "pdx",
            "import-attestation",
            str(source),
            "--store-dir",
            str(journal),
        ]
        for source in (first_path, second_path)
    ]
    processes = [
        subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for command in commands
    ]
    completed = []
    for process in processes:
        stdout, stderr = process.communicate(timeout=30)
        completed.append((process.returncode, json.loads(stdout), stderr))

    assert sorted(item[0] for item in completed) == [0, 3]
    assert sorted(item[1]["receipt"]["status"] for item in completed) == ["ACCEPT", "QUARANTINE"]
    quarantined = next(item[1]["receipt"] for item in completed if item[1]["receipt"]["status"] == "QUARANTINE")
    assert quarantined["reason_codes"] == ["capture_id_hash_conflict"]
    assert quarantined["observation_refs"] == []


def test_repository_schema_is_present_and_structurally_strict():
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / "pdx-observation-attestation-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["additionalProperties"] is False
    assert schema["properties"]["loss_manifest"]["properties"]["cas_exposed"] == {"const": False}
    schema_bytes = schema_path.read_bytes().replace(b"\r\n", b"\n")
    assert hashlib.sha256(schema_bytes).hexdigest() == (
        "66f00c7c70f30caeb31adf7c8209110386eb59478f52d733846e26b8d44c7850"
    )


def test_cli_registers_and_imports_with_structured_replay_output(tmp_path):
    engagement_path = tmp_path / "engagement.json"
    attestation_path = tmp_path / "attestation.json"
    store_path = tmp_path / "journal"
    engagement_path.write_text(strict_json_dumps(_engagement()), encoding="utf-8")
    attestation_path.write_bytes(_raw(_attestation()))

    registered = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "pdx",
            "register-engagement",
            str(engagement_path),
            "--store-dir",
            str(store_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    imported = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "pdx",
            "import-attestation",
            str(attestation_path),
            "--store-dir",
            str(store_path),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    replayed = subprocess.run(imported.args, check=False, capture_output=True, text=True)

    assert registered.returncode == 0, registered.stderr
    assert json.loads(registered.stdout)["status"] == "registered"
    assert imported.returncode == 0, imported.stderr
    assert json.loads(imported.stdout)["receipt"]["status"] == "ACCEPT"
    assert replayed.returncode == 0, replayed.stderr
    assert json.loads(replayed.stdout)["replayed"] is True


def _store_snapshot(root):
    """Content and modification times, including directories and the lock."""
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): (
            path.stat().st_mtime_ns,
            hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None,
        )
        for path in [root, *root.rglob("*")]
    }


def _accepted_store(root):
    store = PDXEvidenceStore(root)
    store.register_engagement(_engagement())
    receipt = store.import_attestation_bytes(
        _raw(_attestation()), received_at="2026-08-23T10:02:00Z",
    ).receipt
    return store, receipt


def _rewrite_receipt(root, receipt):
    """Rehash test corruption so structural checks, not just hashes, are exercised."""
    receipt = copy.deepcopy(receipt)
    receipt["receipt_id"] = None
    receipt["integrity"]["receipt_sha256"] = None
    digest = hashlib.sha256(_raw(receipt).removesuffix(b"\n")).hexdigest()
    receipt["receipt_id"] = f"belief:pdx-receipt:sha256:{digest}"
    receipt["integrity"]["receipt_sha256"] = digest
    raw_hash = receipt["raw_sha256"]
    path = root / "receipts" / "sha256" / raw_hash[:2] / f"{raw_hash}.json"
    path.write_bytes(_raw(receipt))


def test_accepted_reader_is_read_only_deterministic_and_preserves_receipt_lineage(tmp_path):
    store, first = _accepted_store(tmp_path)
    second = store.import_attestation_bytes(_raw(_attestation(
        created_at="2026-08-23T10:03:00Z", partial=True,
        observation__truncated_any=True,
    )), received_at="2026-08-23T10:04:00Z").receipt
    rejected = store.import_attestation_bytes(b"not JSON").receipt
    quarantined = store.import_attestation_bytes(_raw(_attestation(
        engagement__scope_sha256="9" * 64,
    ))).receipt
    assert (rejected["status"], quarantined["status"]) == ("REJECT", "QUARANTINE")
    temporary = store.receipts_dir / ".receipt.json.tmp-interrupted"
    temporary.write_bytes(b"keep an interrupted writer's temporary file")
    before = _store_snapshot(tmp_path)

    reader = PDXEvidenceStore(tmp_path, read_only=True)
    rows = list(reader.iter_accepted_observations())
    assert _store_snapshot(tmp_path) == before
    assert len(rows) == 2
    assert [item.receipt_id for item in rows] == sorted([first["receipt_id"], second["receipt_id"]])
    assert {item.capture_id for item in rows} == {CAPTURE_ID}
    assert rows == list(reader.iter_accepted_observations(engagement_id="engagement-alpha", target_id=TARGET_ID))
    assert list(reader.iter_accepted_observations(target_id=OTHER_TARGET_ID)) == []
    assert list(reader.iter_accepted_observations(engagement_id="another-engagement")) == []
    partial = next(item for item in rows if item.receipt_id == second["receipt_id"])
    assert "identity_non_joinable_signal_only" in partial.caveats
    assert "source_observation_truncated" in partial.caveats
    assert "observation_already_imported" in partial.caveats
    assert partial.proof_state == "signal_only_no_belief_attempt_result_evidence"
    exported = partial.to_dict()
    exported["caveats"].clear()
    assert partial.caveats
    serialized = json.dumps([item.to_dict() for item in rows])
    for absent in ("request_bytes", "response_bytes", "request_sha256", "response_sha256", "pdx_cas_references"):
        assert absent not in serialized
    assert _store_snapshot(tmp_path) == before


@pytest.mark.parametrize("missing", ["store", "lock", "receipts"])
def test_read_only_open_refuses_incomplete_stores_without_creating_files(tmp_path, missing):
    root = tmp_path / "journal"
    if missing != "store":
        store = PDXEvidenceStore(root)
        if missing == "lock":
            store.lock_path.unlink()
        else:
            store.receipts_dir.rmdir()
    before = _store_snapshot(root)
    with pytest.raises(PDXEvidenceStoreError):
        PDXEvidenceStore(root, read_only=True)
    assert _store_snapshot(root) == before


@pytest.mark.parametrize("operation", ["register", "import_bytes", "import_file"])
def test_read_only_instance_rejects_mutating_operations(tmp_path, operation):
    _accepted_store(tmp_path)
    reader = PDXEvidenceStore(tmp_path, read_only=True)
    before = _store_snapshot(tmp_path)
    with pytest.raises(PDXEvidenceStoreError, match="read-only"):
        if operation == "register":
            reader.register_engagement(_engagement())
        elif operation == "import_bytes":
            reader.import_attestation_bytes(_raw(_attestation()))
        else:
            reader.import_attestation_file(tmp_path / "never-read.json")
    assert _store_snapshot(tmp_path) == before


@pytest.mark.parametrize("corruption", [
    "status_type", "accept_with_reason", "duplicate_capture", "proof_promotion",
    "raw_bytes", "nonaccept_refs", "unsupported_schema",
])
def test_reader_rejects_rehashed_invalid_receipts(tmp_path, corruption):
    _, receipt = _accepted_store(tmp_path)
    if corruption == "status_type":
        receipt["status"] = []
    elif corruption == "accept_with_reason":
        receipt["reason_codes"] = ["target_not_authorized"]
    elif corruption == "duplicate_capture":
        receipt["observation_refs"] *= 2
    elif corruption == "proof_promotion":
        receipt["observation_refs"][0]["proof_state"] = "verified"
    elif corruption == "raw_bytes":
        receipt["observation_refs"][0]["request_bytes"] = "secret"
    elif corruption == "nonaccept_refs":
        receipt["status"] = "QUARANTINE"
        receipt["reason_codes"] = ["target_not_authorized"]
    else:
        receipt["schema_version"] = "belief.pdx_attestation_receipt.v999"
    _rewrite_receipt(tmp_path, receipt)
    reader = PDXEvidenceStore(tmp_path, read_only=True)
    with pytest.raises(PDXEvidenceStoreError, match="corrupt"):
        reader.iter_accepted_observations()


@pytest.mark.parametrize("raw", [b'{"status":"ACCEPT","status":"REJECT"}', b"[" * 2000 + b"]" * 2000])
@pytest.mark.parametrize("filtered", [False, True])
def test_reader_validates_entire_snapshot_before_exposing_any_rows(tmp_path, raw, filtered):
    store, _ = _accepted_store(tmp_path)
    # This malformed receipt sorts after the accepted one. An eager validation
    # failure must occur at the call, even when no accepted row matches a filter.
    path = store.receipts_dir / "ff" / ("f" * 64 + ".json")
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(raw)
    reader = PDXEvidenceStore(tmp_path, read_only=True)
    with pytest.raises(PDXEvidenceStoreError, match="corrupt"):
        reader.iter_accepted_observations(target_id=OTHER_TARGET_ID if filtered else None)


def test_reader_detects_hash_tampering_and_noncanonical_shards(tmp_path):
    store, receipt = _accepted_store(tmp_path)
    path = next(store.receipts_dir.rglob("*.json"))
    original = path.read_bytes()
    path.write_bytes(original.replace(b"engagement-alpha", b"engagement-other"))
    reader = PDXEvidenceStore(tmp_path, read_only=True)
    with pytest.raises(PDXEvidenceStoreError, match="corrupt"):
        reader.iter_accepted_observations()
    path.write_bytes(original)
    wrong = store.receipts_dir / "wrong" / f'{receipt["raw_sha256"]}.json'
    wrong.parent.mkdir()
    wrong.write_bytes(original)
    with pytest.raises(PDXEvidenceStoreError, match="noncanonical"):
        reader.iter_accepted_observations()


def test_reader_rejects_conflicting_accepted_hashes_even_if_rehashed(tmp_path):
    store, _ = _accepted_store(tmp_path)
    receipt = store.import_attestation_bytes(_raw(_attestation(
        created_at="2026-08-23T10:03:00Z",
    ))).receipt
    receipt["observation_refs"][0]["observation_hash"] = "3" * 64
    _rewrite_receipt(tmp_path, receipt)
    with pytest.raises(PDXEvidenceStoreError, match="capture hash conflict"):
        PDXEvidenceStore(tmp_path, read_only=True).iter_accepted_observations()


def test_reader_enforces_limits_and_does_not_silently_truncate(tmp_path):
    store, _ = _accepted_store(tmp_path)
    store.import_attestation_bytes(b"invalid")
    reader = PDXEvidenceStore(tmp_path, read_only=True)
    total_bytes = sum(path.stat().st_size for path in store.receipts_dir.rglob("*.json"))
    assert len(list(reader.iter_accepted_observations(max_total_bytes=total_bytes))) == 1
    with pytest.raises(PDXEvidenceStoreError, match="max_receipts"):
        reader.iter_accepted_observations(max_receipts=1)
    with pytest.raises(PDXEvidenceStoreError, match="byte limit"):
        reader.iter_accepted_observations(max_total_bytes=total_bytes - 1)
    assert len(list(PDXEvidenceStore(tmp_path, read_only=True, max_input_bytes=16)
                    .iter_accepted_observations())) == 1
    for invalid in (0, -1, True, 1.5):
        with pytest.raises(ValueError):
            reader.iter_accepted_observations(max_receipts=invalid)
    with pytest.raises(ValueError, match="filter"):
        reader.iter_accepted_observations(target_id="*")


def test_reader_returns_a_complete_snapshot_without_retaining_the_process_lock(tmp_path):
    store, _ = _accepted_store(tmp_path)
    reader = PDXEvidenceStore(tmp_path, read_only=True)
    snapshot = reader.iter_accepted_observations()
    store.import_attestation_bytes(_raw(_attestation(created_at="2026-08-23T10:03:00Z")))
    assert len(list(snapshot)) == 1
    assert len(list(reader.iter_accepted_observations())) == 2


def test_cli_lists_signal_only_metadata_without_writes_and_fails_without_partial_output(tmp_path):
    store, _ = _accepted_store(tmp_path)
    store.import_attestation_bytes(b"invalid")
    store.import_attestation_bytes(_raw(_attestation(engagement__scope_sha256="9" * 64)))
    command = [sys.executable, "-m", "belief", "pdx", "list-observations", "--store-dir", str(tmp_path)]
    before = _store_snapshot(tmp_path)
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["schema_version"] == "belief.pdx_accepted_observations.v1"
    assert payload["count"] == 1
    assert payload["observations"][0]["proof_state"] == "signal_only_no_belief_attempt_result_evidence"
    assert _store_snapshot(tmp_path) == before
    filtered = subprocess.run(command + ["--target-id", OTHER_TARGET_ID], capture_output=True, text=True, timeout=30)
    assert filtered.returncode == 0, filtered.stderr
    assert json.loads(filtered.stdout)["count"] == 0
    damaged = next(store.receipts_dir.rglob("*.json"))
    damaged.write_bytes(b"invalid")
    before_error = _store_snapshot(tmp_path)
    error = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert error.returncode == 2
    assert error.stdout == ""
    assert "corrupt" in error.stderr
    assert _store_snapshot(tmp_path) == before_error
    missing = tmp_path / "missing-journal"
    error = subprocess.run(command[:-1] + [str(missing)], capture_output=True, text=True, timeout=30)
    assert error.returncode == 2
    assert error.stdout == ""
    assert not missing.exists()


def test_accepted_observation_adapter_and_round_trip_cannot_promote_reportability(tmp_path):
    from dataclasses import replace

    from belief.audit_case import AuditCase
    from belief.reportability.scoring import assess_audit_case_reportability
    from belief.validation.models import ValidationResult
    from belief.validation.pdx_observation import pdx_observation_to_validation_result
    from belief.validation.proof import assess_validation_result_proof

    _accepted_store(tmp_path)
    observation = next(PDXEvidenceStore(tmp_path, read_only=True).iter_accepted_observations())
    result = pdx_observation_to_validation_result(observation)
    assert result.outcome == "informational"
    assert result.confidence <= 0.5
    assert result.tested is False
    assert result.human_validated is False
    assert result.metadata["positive_evidence"] is False
    assert result.metadata["pdx_observation"] == observation.to_dict()
    assert observation.receipt_id in result.evidence
    replay = ValidationResult.from_dict(result.to_dict())
    assert replay.to_dict() == result.to_dict()
    proof = assess_validation_result_proof(
        replay, proof_index=None, engagement_id=observation.engagement_id,
        target_id=observation.target_id, subject_id=observation.capture_id,
        subject_kind="pdx_observation", plan_id="", subject_sha256="f" * 64,
    )
    assert proof.state == "signal_only"
    baseline = AuditCase(
        case_id="case-pdx", case_type="external_tool_signal", status="needs_review",
        review_priority="medium", confidence=0.5, severity="medium", file="app.py",
        line=1, rule_id="PDX_OBSERVATION", cwe="CWE-862",
    )
    enriched = replace(baseline, metadata={"validation_results": [replay.to_dict()]})
    before = assess_audit_case_reportability(baseline)
    after = assess_audit_case_reportability(enriched)
    assert after.score == before.score
    assert after.verdict == before.verdict
    assert after.proof_state == "signal_only"
    assert after.verdict != "reportable_candidate"
    assert "unverified validation claims ignored" in after.negative_factors


def test_small_input_limit_does_not_break_replay_of_a_larger_rejection_receipt(tmp_path):
    store = PDXEvidenceStore(tmp_path, max_input_bytes=16)
    first = store.import_attestation_bytes(b"invalid")
    replay = store.import_attestation_bytes(b"invalid")
    assert replay.replayed is True
    assert replay.receipt == first.receipt
    assert list(PDXEvidenceStore(tmp_path, read_only=True).iter_accepted_observations()) == []


def test_reader_rejects_a_receipt_above_the_per_file_byte_limit(tmp_path):
    store, _ = _accepted_store(tmp_path)
    path = next(store.receipts_dir.rglob("*.json"))
    with path.open("ab") as handle:
        handle.write(b" " * (2 * 1024 * 1024))
    with pytest.raises(PDXEvidenceStoreError, match="byte limit"):
        PDXEvidenceStore(tmp_path, read_only=True).iter_accepted_observations()


@pytest.mark.parametrize("redirect", ["receipt", "shard"])
def test_reader_rejects_redirected_files_and_directories(tmp_path, redirect):
    store, _ = _accepted_store(tmp_path / "journal")
    external = tmp_path / "elsewhere"
    external.mkdir()
    if redirect == "receipt":
        link = next(store.receipts_dir.rglob("*.json"))
        target = external / "receipt.json"
        target.write_bytes(link.read_bytes())
        link.unlink()
    else:
        link = store.receipts_dir / "unused-shard"
        target = external
    try:
        link.symlink_to(target, target_is_directory=redirect == "shard")
    except OSError:
        pytest.skip("this host does not permit creating test symlinks")
    with pytest.raises(PDXEvidenceStoreError, match="redirected"):
        PDXEvidenceStore(store.root, read_only=True).iter_accepted_observations()
