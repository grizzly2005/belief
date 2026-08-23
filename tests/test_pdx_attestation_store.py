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
    assert hashlib.sha256(schema_path.read_bytes()).hexdigest() == (
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
