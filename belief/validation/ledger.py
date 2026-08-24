"""Restart-safe attempt/result/evidence ledger for validation proof authority.

The serialized ``ValidationProof`` remains an untrusted link.  This module is
the authority-side implementation: it registers an externally pinned scope,
writes an immutable attempt (and its request CAS object) before execution,
publishes at most one terminal record, and rebuilds ``VerifiedProofIndex`` only
from records and bytes that pass every binding check.

The ledger is intentionally opt-in.  In particular, it does not turn fixture
evidence, PDX observations, or external advisory records into proof for an
arbitrary project target.
"""

from __future__ import annotations

import copy
import hashlib
import os
import re
import threading
import uuid
from collections.abc import Callable, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import InitVar, dataclass, field, replace
from datetime import datetime, timezone
from itertools import islice
from pathlib import Path
from typing import Any

from belief.json_contracts import (
    StrictJSONError,
    strict_json_dumps,
    strict_json_loads,
)

from .models import ValidationResult
from .plan_models import ValidationPlan, canonical_digest
from .proof import (
    EVIDENCE_KINDS,
    ProofAuthorityContext,
    ValidationEvidenceRef,
    ValidationProof,
    ValidationProofError,
    VerifiedProofIndex,
    VerifiedProofMaterial,
    validation_result_proof_digest,
)


VALIDATION_LEDGER_SCHEMA_VERSION = "belief.validation_proof_ledger.v1"
VALIDATION_SCOPE_SCHEMA_VERSION = "belief.validation_proof_scope.v1"
VALIDATION_INVENTORY_SCHEMA_VERSION = "belief.validation_scope_inventory.v1"
VALIDATION_ATTEMPT_SCHEMA_VERSION = "belief.validation_attempt.v1"
VALIDATION_TERMINAL_SCHEMA_VERSION = "belief.validation_terminal.v1"
VALIDATION_LEDGER_CANONICALIZATION = "belief-validation-ledger-json-v1"

TERMINAL_STATUSES = frozenset({"completed", "timed_out", "cancelled", "crashed", "failed"})
DEFAULT_MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_TOTAL_EVIDENCE_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_EVIDENCE_REFS = 32
DEFAULT_MAX_RECORD_BYTES = 2 * 1024 * 1024
DEFAULT_MAX_SCOPE_ATTEMPTS = 10_000

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SNAPSHOT_ID_RE = re.compile(r"^vledger_snapshot_[0-9a-f]{24}$")
_LEDGER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_ATTEMPT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_RESERVED_STEMS = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)
_SNAPSHOT_CONSTRUCTION_TOKEN = object()


class ValidationProofLedgerError(ValueError):
    """Raised when durable authority material is invalid or inconsistent."""


@dataclass(frozen=True)
class EvidenceArtifact:
    """Bounded in-memory evidence offered to the content-addressed store."""

    kind: str
    content: bytes
    media_type: str = "application/octet-stream"
    evidence_id: str = ""

    def __post_init__(self) -> None:
        kind = str(self.kind or "").strip().lower()
        if kind not in EVIDENCE_KINDS:
            raise ValidationProofLedgerError(f"unsupported evidence kind: {kind!r}")
        if not isinstance(self.content, bytes):
            raise TypeError("evidence content must be bytes")
        object.__setattr__(self, "kind", kind)
        media_type = str(self.media_type or "").strip().lower()
        if not media_type:
            raise ValidationProofLedgerError("evidence media_type is required")
        object.__setattr__(self, "media_type", media_type)
        if self.evidence_id:
            object.__setattr__(
                self,
                "evidence_id",
                _ledger_identifier(self.evidence_id, "evidence_id"),
            )


@dataclass(frozen=True)
class AttemptHandle:
    attempt_id: str
    engagement_id: str
    target_id: str
    subject_id: str
    subject_kind: str
    plan_id: str
    subject_sha256: str
    plan_sha256: str
    oracle_id: str
    oracle_version: str
    request_ref: ValidationEvidenceRef


@dataclass(frozen=True)
class TerminalReceipt:
    attempt_id: str
    terminal_status: str
    result: ValidationResult | None
    proof: ValidationProof | None
    replayed: bool


@dataclass(frozen=True)
class VerifiedProofSnapshot:
    """One lock-consistent authority/index generation reconstructed from disk."""

    context: ProofAuthorityContext
    proof_index: VerifiedProofIndex
    sealed_results: tuple[ValidationResult, ...]
    ledger_snapshot_id: str
    authority_sha256: str
    unterminated_attempt_ids: tuple[str, ...] = ()
    _construction_token: InitVar[object | None] = None
    _ledger_origin: object = field(init=False, repr=False, compare=False)

    def __post_init__(self, _construction_token: object | None) -> None:
        if _construction_token is not _SNAPSHOT_CONSTRUCTION_TOKEN:
            raise TypeError(
                "VerifiedProofSnapshot can only be created by ValidationProofLedger.load_scope"
            )
        if type(self.context) is not ProofAuthorityContext:
            raise TypeError("verified proof snapshot context is invalid")
        if type(self.proof_index) is not VerifiedProofIndex:
            raise TypeError("verified proof snapshot index is invalid")
        if not isinstance(self.sealed_results, tuple) or any(
            type(result) is not ValidationResult for result in self.sealed_results
        ):
            raise TypeError("verified proof snapshot sealed_results must be a tuple")
        if tuple(sorted(self.sealed_results, key=lambda item: item.result_id)) != (
            self.sealed_results
        ):
            raise ValidationProofLedgerError(
                "verified proof snapshot sealed_results are not canonical"
            )
        snapshot_id = str(self.ledger_snapshot_id or "").strip().lower()
        if not _SNAPSHOT_ID_RE.fullmatch(snapshot_id):
            raise ValidationProofLedgerError("verified proof snapshot id is invalid")
        authority_digest = _sha256(self.authority_sha256, "authority_sha256")
        attempt_ids = self.unterminated_attempt_ids
        if not isinstance(attempt_ids, tuple):
            raise TypeError("verified proof snapshot unterminated_attempt_ids must be a tuple")
        normalized_attempt_ids = tuple(_attempt_identifier(item) for item in attempt_ids)
        if normalized_attempt_ids != tuple(sorted(set(normalized_attempt_ids))):
            raise ValidationProofLedgerError(
                "verified proof snapshot unterminated_attempt_ids are not canonical"
            )
        object.__setattr__(self, "ledger_snapshot_id", snapshot_id)
        object.__setattr__(self, "authority_sha256", authority_digest)
        object.__setattr__(self, "_ledger_origin", _SNAPSHOT_CONSTRUCTION_TOKEN)

    def _authority_inputs(self) -> tuple[VerifiedProofIndex, ProofAuthorityContext]:
        """Return trusted inputs only for a snapshot produced by this module."""

        if getattr(self, "_ledger_origin", None) is not _SNAPSHOT_CONSTRUCTION_TOKEN:
            raise TypeError("proof_snapshot is not a ledger-origin snapshot")
        return self.proof_index, self.context
@dataclass(frozen=True)
class _PreparedEvidence:
    reference: ValidationEvidenceRef
    content: bytes


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(value: Any) -> bytes:
    return strict_json_dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _record_sha256(record: Mapping[str, Any]) -> str:
    document = copy.deepcopy(dict(record))
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        raise ValidationProofLedgerError("ledger record integrity is missing")
    integrity["record_sha256"] = None
    return _canonical_sha256(document)


def _finalize_record(record: dict[str, Any]) -> dict[str, Any]:
    record["integrity"] = {
        "canonicalization": VALIDATION_LEDGER_CANONICALIZATION,
        "record_sha256": None,
    }
    record["integrity"]["record_sha256"] = _record_sha256(record)
    return record


def _validate_record_integrity(record: Mapping[str, Any]) -> str:
    integrity = record.get("integrity")
    if not isinstance(integrity, Mapping) or set(integrity) != {
        "canonicalization",
        "record_sha256",
    }:
        raise ValidationProofLedgerError("ledger record integrity is invalid")
    if integrity["canonicalization"] != VALIDATION_LEDGER_CANONICALIZATION:
        raise ValidationProofLedgerError("unsupported ledger canonicalization")
    supplied = _sha256(integrity["record_sha256"], "record_sha256")
    expected = _record_sha256(record)
    if supplied != expected:
        raise ValidationProofLedgerError("ledger record digest mismatch")
    return expected


def _parse_timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValidationProofLedgerError(f"{field_name} must be an ISO timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationProofLedgerError(f"{field_name} must be an ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationProofLedgerError(f"{field_name} requires an offset")
    return value


def _sha256(value: Any, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise ValidationProofLedgerError(f"{field_name} must be lowercase SHA-256")
    return text


def _ledger_identifier(value: Any, field_name: str) -> str:
    text = str(value or "").strip()
    if not _LEDGER_ID_RE.fullmatch(text):
        raise ValidationProofLedgerError(f"{field_name} is invalid")
    return text


def _attempt_identifier(value: Any) -> str:
    text = str(value or "").strip()
    if (
        not _ATTEMPT_ID_RE.fullmatch(text)
        or text.split(".", 1)[0].upper() in _WINDOWS_RESERVED_STEMS
    ):
        raise ValidationProofLedgerError("attempt_id is not a portable filename")
    return text


def _scope_digest(context: ProofAuthorityContext) -> str:
    return _canonical_sha256(
        {
            "engagement_id": context.engagement_id,
            "target_id": context.target_id,
        }
    )


def _canonical_result(result: ValidationResult) -> tuple[ValidationResult, dict[str, Any]]:
    if not isinstance(result, ValidationResult):
        raise TypeError("terminal result must be a ValidationResult")
    payload = result.to_dict()
    metadata = payload.get("metadata")
    if isinstance(metadata, dict) and "validation_proof" in metadata:
        raise ValidationProofLedgerError("terminal result already contains a validation proof")
    try:
        canonical = ValidationResult.from_dict(copy.deepcopy(payload))
        identity_payload = copy.deepcopy(payload)
        identity_payload["result_id"] = ""
        expected_identity = ValidationResult.from_dict(identity_payload).result_id
    except (TypeError, ValueError) as exc:
        raise ValidationProofLedgerError("terminal result is invalid") from exc
    if canonical.to_dict() != payload:
        raise ValidationProofLedgerError("terminal result is not canonical")
    if canonical.result_id != expected_identity:
        raise ValidationProofLedgerError("terminal result_id does not match canonical content")
    return canonical, payload


class ValidationProofLedger:
    """Immutable file journal plus SHA-256 CAS for trusted proof material."""

    def __init__(
        self,
        root: str | Path = "belief_validation_ledger",
        *,
        max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES,
        max_total_evidence_bytes: int = DEFAULT_MAX_TOTAL_EVIDENCE_BYTES,
        max_evidence_refs: int = DEFAULT_MAX_EVIDENCE_REFS,
        max_record_bytes: int = DEFAULT_MAX_RECORD_BYTES,
        max_scope_attempts: int = DEFAULT_MAX_SCOPE_ATTEMPTS,
    ) -> None:
        if (
            max_evidence_bytes <= 0
            or max_total_evidence_bytes < max_evidence_bytes
            or max_evidence_refs < 3
            or max_record_bytes <= 0
            or max_scope_attempts <= 0
        ):
            raise ValueError("validation ledger evidence bounds are invalid")
        self.root = Path(root).expanduser().resolve()
        self.max_evidence_bytes = max_evidence_bytes
        self.max_total_evidence_bytes = max_total_evidence_bytes
        self.max_evidence_refs = max_evidence_refs
        self.max_record_bytes = max_record_bytes
        self.max_scope_attempts = max_scope_attempts
        self.cas_dir = self.root / "cas" / "sha256"
        self.scopes_dir = self.root / "scopes" / "sha256"
        self.lock_path = self.root / ".ledger.lock"
        self._lock = threading.RLock()
        self.cas_dir.mkdir(parents=True, exist_ok=True)
        self.scopes_dir.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
                os.fsync(handle.fileno())
        with self._exclusive():
            self._cleanup_temporary_files()

    def register_scope(
        self,
        context: ProofAuthorityContext,
        *,
        authority_sha256: str,
        registered_at: str | None = None,
    ) -> dict[str, Any]:
        """Create an immutable scope manifest pinned by external authority."""

        context = self._context(context)
        authority_digest = _sha256(authority_sha256, "authority_sha256")
        timestamp = _parse_timestamp(
            registered_at or _utc_now(),
            "registered_at",
        )
        record = _finalize_record(
            {
                "schema_version": VALIDATION_SCOPE_SCHEMA_VERSION,
                "ledger_schema_version": VALIDATION_LEDGER_SCHEMA_VERSION,
                "scope_sha256": _scope_digest(context),
                "engagement_id": context.engagement_id,
                "target_id": context.target_id,
                "authority_version": 1,
                "authority_sha256": authority_digest,
                "registered_at": timestamp,
            }
        )
        destination = self._scope_manifest_path(context)
        record_bytes = self._record_bytes(record)
        with self._exclusive():
            if destination.is_file():
                stored = self._load_scope_manifest(
                    context,
                    expected_authority_sha256=authority_digest,
                )
                self._recover_scope_transactions(context)
                self._load_scope_inventory(context)
                return copy.deepcopy(stored)
            destination.parent.mkdir(parents=True, exist_ok=True)
            inventory_path = self._scope_inventory_path(context)
            if inventory_path.is_file():
                inventory = self._load_scope_inventory(context)
                if inventory["attempts"] or inventory["terminals"]:
                    raise ValidationProofLedgerError("unregistered scope inventory is not empty")
            else:
                inventory = self._new_scope_inventory(context)
                self._atomic_write(
                    inventory_path,
                    self._record_bytes(inventory),
                )
            self._atomic_write(destination, record_bytes)
        return copy.deepcopy(record)

    def begin_attempt(
        self,
        context: ProofAuthorityContext,
        plan: ValidationPlan,
        *,
        expected_authority_sha256: str,
        subject_sha256: str,
        request_bytes: bytes,
        oracle_id: str,
        oracle_version: str,
        request_media_type: str = "application/json",
        attempt_id: str = "",
        started_at: str | None = None,
    ) -> AttemptHandle:
        """Persist the request and immutable attempt before a caller spawns work."""

        context = self._context(context)
        if not isinstance(plan, ValidationPlan):
            raise TypeError("validation ledger requires a canonical ValidationPlan")
        if plan.plan_id != ValidationPlan.from_dict(plan.to_dict()).plan_id:
            raise ValidationProofLedgerError("validation plan identity mismatch")
        authority_digest = _sha256(
            expected_authority_sha256,
            "expected_authority_sha256",
        )
        subject_digest = _sha256(subject_sha256, "subject_sha256")
        plan_digest = canonical_digest(plan.to_dict())
        source_digest = str(
            plan.metadata.get("proof_subject_sha256")
            or plan.metadata.get("source_case_sha256")
            or plan.metadata.get("source_seed_sha256")
            or ""
        ).lower()
        if source_digest and source_digest != subject_digest:
            raise ValidationProofLedgerError(
                "subject_sha256 does not match the validation plan source snapshot"
            )
        identifier = _attempt_identifier(
            attempt_id or f"vattempt_{uuid.uuid4().hex}",
        )
        timestamp = _parse_timestamp(started_at or _utc_now(), "started_at")
        oracle = _ledger_identifier(oracle_id, "oracle_id")
        oracle_revision = _ledger_identifier(oracle_version, "oracle_version")
        request = self._prepare_evidence(
            EvidenceArtifact(
                kind="request",
                content=request_bytes,
                media_type=request_media_type,
                evidence_id=f"validation-request:{identifier}",
            )
        )
        scope_digest = _scope_digest(context)
        record = _finalize_record(
            {
                "schema_version": VALIDATION_ATTEMPT_SCHEMA_VERSION,
                "ledger_schema_version": VALIDATION_LEDGER_SCHEMA_VERSION,
                "attempt_id": identifier,
                "scope_sha256": scope_digest,
                "engagement_id": context.engagement_id,
                "target_id": context.target_id,
                "subject_id": _ledger_identifier(plan.subject_id, "subject_id"),
                "subject_kind": _ledger_identifier(
                    plan.subject_kind,
                    "subject_kind",
                ),
                "subject_sha256": subject_digest,
                "plan_id": _ledger_identifier(plan.plan_id, "plan_id"),
                "plan_sha256": plan_digest,
                "oracle_id": oracle,
                "oracle_version": oracle_revision,
                "request_ref": request.reference.to_dict(),
                "started_at": timestamp,
            }
        )
        record_bytes = self._record_bytes(record)
        with self._exclusive():
            self._load_scope_manifest(
                context,
                expected_authority_sha256=authority_digest,
            )
            self._recover_scope_transactions(context)
            inventory = self._load_scope_inventory(context)
            destination = self._attempt_path(context, identifier)
            if destination.is_file():
                stored = self._load_attempt_path(context, destination)
                if self._attempt_semantic(stored) != self._attempt_semantic(record):
                    raise ValidationProofLedgerError(
                        "attempt_id is already bound to different content"
                    )
                self._append_scope_inventory_entry(
                    context,
                    field_name="attempts",
                    record=stored,
                )
                return self._attempt_handle(stored)
            if len(inventory["attempts"]) >= self.max_scope_attempts:
                raise ValidationProofLedgerError("scope exceeds configured attempt limit")
            self._write_prepared_evidence(request)
            self._publish_record_transactionally(
                context,
                field_name="attempts",
                record=record,
                record_bytes=record_bytes,
            )
        return self._attempt_handle(record)

    def finish_attempt(
        self,
        attempt: AttemptHandle,
        *,
        terminal_status: str,
        result: ValidationResult | None,
        response_bytes: bytes | None = None,
        response_media_type: str = "application/json",
        evidence: Sequence[EvidenceArtifact] = (),
        finished_at: str | None = None,
    ) -> TerminalReceipt:
        """Publish one generic terminal record without granting proof authority.

        A caller-supplied result and opaque response are durable audit material,
        not an oracle verdict.  This method therefore never emits a
        ``ValidationProof``.  The bounded registered-fixture runner below owns
        the only proof-producing path in this slice.
        """

        return self._finish_attempt(
            attempt,
            terminal_status=terminal_status,
            result=result,
            response_bytes=response_bytes,
            response_media_type=response_media_type,
            evidence=evidence,
            finished_at=finished_at,
            publish_proof=False,
        )

    def _finish_attempt(
        self,
        attempt: AttemptHandle,
        *,
        terminal_status: str,
        result: ValidationResult | None,
        response_bytes: bytes | None = None,
        response_media_type: str = "application/json",
        evidence: Sequence[EvidenceArtifact] = (),
        finished_at: str | None = None,
        publish_proof: bool,
    ) -> TerminalReceipt:
        """Create one terminal; proof publication is private and policy-bound."""

        if not isinstance(attempt, AttemptHandle):
            raise TypeError("finish_attempt requires an AttemptHandle")
        status = str(terminal_status or "").strip().lower()
        if status not in TERMINAL_STATUSES:
            raise ValidationProofLedgerError(f"unsupported terminal status: {status!r}")
        context = ProofAuthorityContext(
            engagement_id=attempt.engagement_id,
            target_id=attempt.target_id,
        )
        timestamp = _parse_timestamp(finished_at or _utc_now(), "finished_at")
        with self._exclusive():
            self._recover_scope_transactions(context)
            stored_attempt = self._load_attempt_path(
                context,
                self._attempt_path(context, attempt.attempt_id),
            )
            self._require_scope_inventory_entry(
                context,
                field_name="attempts",
                record=stored_attempt,
            )
            if self._attempt_handle(stored_attempt) != attempt:
                raise ValidationProofLedgerError("attempt handle does not match durable attempt")
            prepared, canonical_result, proof = self._prepare_terminal_material(
                stored_attempt,
                status=status,
                result=result,
                response_bytes=response_bytes,
                response_media_type=response_media_type,
                evidence=evidence,
                publish_proof=publish_proof,
            )
            refs = tuple(
                sorted(
                    (item.reference for item in prepared),
                    key=lambda item: (item.evidence_id, item.kind, item.sha256),
                )
            )
            record = _finalize_record(
                {
                    "schema_version": VALIDATION_TERMINAL_SCHEMA_VERSION,
                    "ledger_schema_version": VALIDATION_LEDGER_SCHEMA_VERSION,
                    "attempt_id": attempt.attempt_id,
                    "scope_sha256": stored_attempt["scope_sha256"],
                    "engagement_id": attempt.engagement_id,
                    "target_id": attempt.target_id,
                    "terminal_status": status,
                    "finished_at": timestamp,
                    "result": (
                        canonical_result.to_dict() if canonical_result is not None else None
                    ),
                    "proof": proof.to_dict() if proof is not None else None,
                    "evidence_refs": [item.to_dict() for item in refs],
                }
            )
            record_bytes = self._record_bytes(record)
            destination = self._terminal_path(context, attempt.attempt_id)
            if destination.is_file():
                stored_terminal = self._load_terminal_path(
                    context,
                    destination,
                    stored_attempt,
                )
                if self._terminal_semantic(stored_terminal) != self._terminal_semantic(record):
                    raise ValidationProofLedgerError(
                        "attempt already has a different terminal result"
                    )
                self._append_scope_inventory_entry(
                    context,
                    field_name="terminals",
                    record=stored_terminal,
                )
                return self._terminal_receipt(stored_terminal, replayed=True)
            for item in prepared:
                self._write_prepared_evidence(item)
            self._publish_record_transactionally(
                context,
                field_name="terminals",
                record=record,
                record_bytes=record_bytes,
            )
        return self._terminal_receipt(record, replayed=False)

    def _finish_registered_fixture_attempt(
        self,
        attempt: AttemptHandle,
        *,
        plan: ValidationPlan,
        fixture_id: str,
        terminal_status: str,
        result: ValidationResult,
        response: Any,
    ) -> TerminalReceipt:
        """Authorize proof only for a response produced by the closed fixture path."""

        response_bytes = self._validate_registered_fixture_terminal(
            attempt,
            plan=plan,
            fixture_id=fixture_id,
            terminal_status=terminal_status,
            result=result,
            response=response,
        )
        return self._finish_attempt(
            attempt,
            terminal_status=terminal_status,
            result=result,
            response_bytes=response_bytes,
            response_media_type=("application/vnd.belief.validation-worker-response.v4+json"),
            publish_proof=True,
        )

    def resume_attempt(
        self,
        context: ProofAuthorityContext,
        *,
        expected_authority_sha256: str,
        attempt_id: str,
    ) -> AttemptHandle:
        """Reload one immutable attempt after restart without trusting a handle."""

        context = self._context(context)
        authority_digest = _sha256(
            expected_authority_sha256,
            "expected_authority_sha256",
        )
        identifier = _attempt_identifier(attempt_id)
        with self._exclusive():
            self._load_scope_manifest(
                context,
                expected_authority_sha256=authority_digest,
            )
            self._recover_scope_transactions(context)
            record = self._load_attempt_path(
                context,
                self._attempt_path(context, identifier),
            )
            self._require_scope_inventory_entry(
                context,
                field_name="attempts",
                record=record,
            )
        return self._attempt_handle(record)

    def load_scope(
        self,
        context: ProofAuthorityContext,
        *,
        expected_authority_sha256: str,
        expected_ledger_snapshot_id: str | None = None,
    ) -> VerifiedProofSnapshot:
        """Rebuild a lock-consistent proof index; any corruption fails closed."""

        context = self._context(context)
        authority_digest = _sha256(
            expected_authority_sha256,
            "expected_authority_sha256",
        )
        snapshot_pin = None
        if expected_ledger_snapshot_id is not None:
            snapshot_pin = str(expected_ledger_snapshot_id or "").strip().lower()
            if not _SNAPSHOT_ID_RE.fullmatch(snapshot_pin):
                raise ValidationProofLedgerError("expected_ledger_snapshot_id is invalid")
        materials: list[VerifiedProofMaterial] = []
        sealed_results: list[ValidationResult] = []
        unterminated_attempt_ids: tuple[str, ...] = ()
        snapshot_records: list[tuple[str, str]] = []
        with self._exclusive():
            manifest = self._load_scope_manifest(
                context,
                expected_authority_sha256=authority_digest,
            )
            snapshot_records.append(("scope", manifest["integrity"]["record_sha256"]))
            if snapshot_pin is not None and self._scope_has_pending_transactions(context):
                raise ValidationProofLedgerError(
                    "pending ledger transaction requires unpinned recovery"
                )
            self._recover_scope_transactions(context)
            inventory = self._load_scope_inventory(context)
            snapshot_records.append(("inventory", inventory["integrity"]["record_sha256"]))
            inventory_attempts = {
                item["attempt_id"]: item["record_sha256"] for item in inventory["attempts"]
            }
            inventory_terminals = {
                item["attempt_id"]: item["record_sha256"] for item in inventory["terminals"]
            }
            directory = self._scope_directory(context)
            attempts: dict[str, dict[str, Any]] = {}
            attempts_dir = directory / "attempts"
            if attempts_dir.exists():
                attempt_paths = tuple(
                    islice(
                        attempts_dir.glob("*.json"),
                        self.max_scope_attempts + 1,
                    )
                )
                if len(attempt_paths) > self.max_scope_attempts:
                    raise ValidationProofLedgerError("scope exceeds configured attempt limit")
                for path in sorted(attempt_paths):
                    record = self._load_attempt_path(context, path)
                    if path.name != f"{record['attempt_id']}.json":
                        raise ValidationProofLedgerError("attempt path does not match attempt_id")
                    if record["attempt_id"] in attempts:
                        raise ValidationProofLedgerError("duplicate durable attempt_id")
                    if (
                        inventory_attempts.get(record["attempt_id"])
                        != record["integrity"]["record_sha256"]
                    ):
                        raise ValidationProofLedgerError(
                            "attempt record does not match scope inventory"
                        )
                    attempts[record["attempt_id"]] = record
                    snapshot_records.append(
                        (
                            f"attempt:{record['attempt_id']}",
                            record["integrity"]["record_sha256"],
                        )
                    )
            if set(attempts) != set(inventory_attempts):
                raise ValidationProofLedgerError("scope inventory attempt set is incomplete")
            terminals_dir = directory / "terminals"
            seen_terminals: set[str] = set()
            if terminals_dir.exists():
                terminal_paths = tuple(
                    islice(
                        terminals_dir.glob("*.json"),
                        self.max_scope_attempts + 1,
                    )
                )
                if len(terminal_paths) > self.max_scope_attempts:
                    raise ValidationProofLedgerError("scope exceeds configured terminal limit")
                for path in sorted(terminal_paths):
                    identifier = path.stem
                    attempt_record = attempts.get(identifier)
                    if attempt_record is None:
                        raise ValidationProofLedgerError("terminal result has no durable attempt")
                    terminal = self._load_terminal_path(
                        context,
                        path,
                        attempt_record,
                    )
                    if path.name != f"{terminal['attempt_id']}.json":
                        raise ValidationProofLedgerError("terminal path does not match attempt_id")
                    if terminal["attempt_id"] in seen_terminals:
                        raise ValidationProofLedgerError("duplicate terminal result for attempt")
                    if (
                        inventory_terminals.get(terminal["attempt_id"])
                        != terminal["integrity"]["record_sha256"]
                    ):
                        raise ValidationProofLedgerError(
                            "terminal record does not match scope inventory"
                        )
                    seen_terminals.add(terminal["attempt_id"])
                    snapshot_records.append(
                        (
                            f"terminal:{terminal['attempt_id']}",
                            terminal["integrity"]["record_sha256"],
                        )
                    )
                    material = self._material_from_records(
                        attempt_record,
                        terminal,
                    )
                    if material is None:
                        continue
                    materials.append(material)
                    result = ValidationResult.from_dict(terminal["result"])
                    metadata = dict(result.metadata)
                    metadata["validation_proof"] = material.proof.to_dict()
                    sealed_results.append(replace(result, metadata=metadata))
            if seen_terminals != set(inventory_terminals):
                raise ValidationProofLedgerError("scope inventory terminal set is incomplete")
            unterminated_attempt_ids = tuple(sorted(set(attempts).difference(seen_terminals)))

        snapshot_id = (
            "vledger_snapshot_"
            + _canonical_sha256(
                {
                    "scope_sha256": _scope_digest(context),
                    "records": sorted(snapshot_records),
                }
            )[:24]
        )
        if snapshot_pin is not None and snapshot_id != snapshot_pin:
            raise ValidationProofLedgerError("ledger snapshot does not match the external pin")
        return VerifiedProofSnapshot(
            context=context,
            proof_index=VerifiedProofIndex(materials),
            sealed_results=tuple(sorted(sealed_results, key=lambda item: item.result_id)),
            ledger_snapshot_id=snapshot_id,
            authority_sha256=authority_digest,
            unterminated_attempt_ids=unterminated_attempt_ids,
            _construction_token=_SNAPSHOT_CONSTRUCTION_TOKEN,
        )

    def _prepare_terminal_material(
        self,
        attempt: Mapping[str, Any],
        *,
        status: str,
        result: ValidationResult | None,
        response_bytes: bytes | None,
        response_media_type: str,
        evidence: Sequence[EvidenceArtifact],
        publish_proof: bool,
    ) -> tuple[
        tuple[_PreparedEvidence, ...],
        ValidationResult | None,
        ValidationProof | None,
    ]:
        request_ref = ValidationEvidenceRef.from_dict(attempt["request_ref"])
        request_content = self._read_cas(request_ref.sha256)
        prepared: list[_PreparedEvidence] = [_PreparedEvidence(request_ref, request_content)]
        if response_bytes is not None:
            prepared.append(
                self._prepare_evidence(
                    EvidenceArtifact(
                        kind="response",
                        content=response_bytes,
                        media_type=response_media_type,
                        evidence_id=("validation-response:" + str(attempt["attempt_id"])),
                    )
                )
            )
        canonical_result: ValidationResult | None = None
        proof: ValidationProof | None = None
        if result is not None:
            if response_bytes is None:
                raise ValidationProofLedgerError(
                    "terminal result requires captured response evidence"
                )
            canonical_result, payload = _canonical_result(result)
            if (
                canonical_result.subject_id != attempt["subject_id"]
                or canonical_result.subject_kind != attempt["subject_kind"]
            ):
                raise ValidationProofLedgerError("terminal result subject does not match attempt")
            metadata = canonical_result.metadata
            if (
                metadata.get("validation_plan_id") != attempt["plan_id"]
                or metadata.get("validation_plan_digest") != attempt["plan_sha256"]
            ):
                raise ValidationProofLedgerError(
                    "terminal result plan binding does not match attempt"
                )
            if status != "completed" and canonical_result.outcome != "inconclusive":
                raise ValidationProofLedgerError(
                    "non-completed terminal cannot publish a conclusive outcome"
                )
            result_bytes = _canonical_json_bytes(payload)
            result_artifact = self._prepare_evidence(
                EvidenceArtifact(
                    kind="artifact",
                    content=result_bytes,
                    media_type="application/vnd.belief.validation-result.v1+json",
                    evidence_id=f"validation-result:{canonical_result.result_id}",
                )
            )
            if result_artifact.reference.sha256 != validation_result_proof_digest(canonical_result):
                raise ValidationProofLedgerError("terminal result artifact digest mismatch")
            prepared.append(result_artifact)
        elif status == "completed":
            raise ValidationProofLedgerError("completed terminal requires a validation result")
        for artifact in evidence:
            if not isinstance(artifact, EvidenceArtifact):
                raise TypeError("additional evidence must be EvidenceArtifact values")
            if artifact.kind in {"request", "response"}:
                raise ValidationProofLedgerError(
                    "additional evidence kind is reserved by the ledger"
                )
            prepared.append(self._prepare_evidence(artifact))
        prepared = self._dedupe_prepared(prepared)
        if len(prepared) > self.max_evidence_refs:
            raise ValidationProofLedgerError("terminal evidence exceeds reference limit")
        if sum(len(item.content) for item in prepared) > self.max_total_evidence_bytes:
            raise ValidationProofLedgerError("terminal evidence exceeds total byte limit")
        if canonical_result is not None and publish_proof:
            if attempt["subject_kind"] != "validation_contract_seed" or not str(
                attempt["target_id"]
            ).startswith("registered-fixture:"):
                raise ValidationProofLedgerError(
                    "only registered fixture seeds can publish durable proof"
                )
            refs = tuple(item.reference for item in prepared)
            proof = ValidationProof(
                engagement_id=str(attempt["engagement_id"]),
                target_id=str(attempt["target_id"]),
                subject_id=str(attempt["subject_id"]),
                subject_kind=str(attempt["subject_kind"]),
                plan_id=str(attempt["plan_id"]),
                attempt_id=str(attempt["attempt_id"]),
                result_id=canonical_result.result_id,
                outcome=canonical_result.outcome,
                oracle_id=str(attempt["oracle_id"]),
                oracle_version=str(attempt["oracle_version"]),
                evidence_refs=refs,
            )
        return tuple(prepared), canonical_result, proof

    def _validate_registered_fixture_terminal(
        self,
        attempt: AttemptHandle,
        *,
        plan: ValidationPlan,
        fixture_id: str,
        terminal_status: str,
        result: ValidationResult,
        response: Any,
    ) -> bytes:
        from .evidence_policy import evaluate_evidence
        from .execution_models import ValidationExecutionContext
        from .executors.base import conclusive_safe_outcome
        from .worker.contracts import WorkerResponse
        from .worker.process import ISOLATED_WEB_WORKER_ADAPTER

        if not isinstance(plan, ValidationPlan):
            raise TypeError("registered fixture proof requires a ValidationPlan")
        if not isinstance(response, WorkerResponse):
            raise TypeError("registered fixture proof requires a WorkerResponse")
        canonical_response = WorkerResponse.from_dict(response.to_dict())
        response_bytes = _canonical_json_bytes(canonical_response.to_dict())
        expected_target = f"registered-fixture:{fixture_id}"
        plan_digest = canonical_digest(plan.to_dict())
        if (
            attempt.target_id != expected_target
            or attempt.subject_kind != "validation_contract_seed"
            or attempt.subject_id != plan.subject_id
            or attempt.plan_id != plan.plan_id
            or attempt.plan_sha256 != plan_digest
            or attempt.oracle_id != f"isolated-web:{plan.case_type}"
        ):
            raise ValidationProofLedgerError(
                "registered fixture proof does not match its durable attempt"
            )

        request_payload = strict_json_loads(self._read_cas(attempt.request_ref.sha256))
        if not isinstance(request_payload, Mapping):
            raise ValidationProofLedgerError(
                "registered fixture request is not an execution context"
            )
        try:
            execution_context = ValidationExecutionContext.from_dict(request_payload)
        except (TypeError, ValueError) as exc:
            raise ValidationProofLedgerError("registered fixture request is not canonical") from exc
        if (
            execution_context.validation_plan_id != plan.plan_id
            or execution_context.expected_plan_digest != plan_digest
            or execution_context.case_type != plan.case_type
            or execution_context.fixture_id != fixture_id
            or execution_context.adapter != ISOLATED_WEB_WORKER_ADAPTER
        ):
            raise ValidationProofLedgerError("registered fixture request binding mismatch")

        expected_worker_status = {
            "completed": "completed",
            "timed_out": "timed_out",
            "cancelled": "cancelled",
            "crashed": "crashed",
        }.get(canonical_response.worker_status, "failed")
        config = execution_context.config
        attestation = canonical_response.attestation
        response_bindings_match = (
            canonical_response.fixture_id == fixture_id
            and canonical_response.validation_plan_id == plan.plan_id
            and canonical_response.validation_plan_digest == plan_digest
            and canonical_response.correlation_id == config.get("correlation_id")
            and terminal_status == expected_worker_status
            and attestation.source_revision == execution_context.source_revision
            and attestation.fixture_registry_digest == config.get("fixture_registry_digest")
            and attestation.fixture_source_digest == config.get("fixture_source_digest")
            and attestation.fixture_descriptor_digest == config.get("fixture_descriptor_digest")
            and attestation.fixture_execution_bundle_digest
            == config.get("fixture_execution_bundle_digest")
            and attestation.fixture_code_object_digest == config.get("fixture_code_object_digest")
        )
        if not response_bindings_match:
            raise ValidationProofLedgerError("registered fixture response binding mismatch")

        decision = evaluate_evidence(
            canonical_response.observations,
            completed=canonical_response.worker_status == "completed",
            safe_outcome=conclusive_safe_outcome(plan),
        )
        isolated_worker = result.metadata.get("isolated_worker")
        expected_worker_metadata = {
            "worker_status": canonical_response.worker_status,
            "evidence_digest": canonical_response.evidence_digest,
            "attestation_digest": canonical_response.attestation_digest,
            "semantic_digest": canonical_response.semantic_digest,
            "attestation": attestation.to_dict(),
        }
        execution = result.metadata.get("execution")
        if (
            result.outcome != decision.outcome
            or result.tested != decision.conclusive
            or isolated_worker != expected_worker_metadata
            or not isinstance(execution, Mapping)
            or execution.get("validation_plan_id") != plan.plan_id
            or execution.get("validation_plan_digest") != plan_digest
            or execution.get("subject_id") != plan.subject_id
            or execution.get("fixture_id") != fixture_id
            or execution.get("fixture_digest") != execution_context.fixture_digest
            or execution.get("adapter") != ISOLATED_WEB_WORKER_ADAPTER
            or execution.get("source_revision") != execution_context.source_revision
            or execution.get("outcome") != decision.outcome
        ):
            raise ValidationProofLedgerError(
                "registered fixture result is not derived from its worker response"
            )
        return response_bytes

    def _validate_stored_registered_fixture_proof(
        self,
        attempt: Mapping[str, Any],
        *,
        terminal_status: str,
        result: ValidationResult,
        response_ref: ValidationEvidenceRef,
    ) -> None:
        """Recompute the closed-fixture bindings during every reconstruction."""

        from .evidence_policy import evaluate_evidence
        from .execution_models import ValidationExecutionContext
        from .worker.contracts import WorkerResponse
        from .worker.process import ISOLATED_WEB_WORKER_ADAPTER

        expected_fixture = str(attempt["target_id"]).removeprefix("registered-fixture:")
        request_ref = ValidationEvidenceRef.from_dict(attempt["request_ref"])
        if (
            not expected_fixture
            or attempt["subject_kind"] != "validation_contract_seed"
            or not str(attempt["oracle_id"]).startswith("isolated-web:")
            or request_ref.media_type
            != "application/vnd.belief.validation-execution-context.v1+json"
            or response_ref.media_type
            != "application/vnd.belief.validation-worker-response.v4+json"
        ):
            raise ValidationProofLedgerError(
                "stored proof is outside the registered fixture policy"
            )
        try:
            request_payload = strict_json_loads(self._read_cas(request_ref.sha256))
            response_payload = strict_json_loads(self._read_cas(response_ref.sha256))
            if not isinstance(request_payload, Mapping) or not isinstance(
                response_payload,
                Mapping,
            ):
                raise TypeError("fixture evidence envelopes must be objects")
            execution_context = ValidationExecutionContext.from_dict(request_payload)
            response = WorkerResponse.from_dict(response_payload)
        except (StrictJSONError, TypeError, ValueError) as exc:
            raise ValidationProofLedgerError(
                "stored registered fixture evidence is invalid"
            ) from exc

        config = execution_context.config
        attestation = response.attestation
        expected_terminal_status = {
            "completed": "completed",
            "timed_out": "timed_out",
            "cancelled": "cancelled",
            "crashed": "crashed",
        }.get(response.worker_status, "failed")
        oracle_case_type = str(attempt["oracle_id"]).removeprefix("isolated-web:")
        if (
            execution_context.validation_plan_id != attempt["plan_id"]
            or execution_context.expected_plan_digest != attempt["plan_sha256"]
            or execution_context.case_type != oracle_case_type
            or execution_context.fixture_id != expected_fixture
            or execution_context.adapter != ISOLATED_WEB_WORKER_ADAPTER
            or response.fixture_id != expected_fixture
            or response.validation_plan_id != attempt["plan_id"]
            or response.validation_plan_digest != attempt["plan_sha256"]
            or response.schema_version != attempt["oracle_version"]
            or response.correlation_id != config.get("correlation_id")
            or terminal_status != expected_terminal_status
            or attestation.source_revision != execution_context.source_revision
            or attestation.fixture_registry_digest != config.get("fixture_registry_digest")
            or attestation.fixture_source_digest != config.get("fixture_source_digest")
            or attestation.fixture_descriptor_digest != config.get("fixture_descriptor_digest")
            or attestation.fixture_execution_bundle_digest
            != config.get("fixture_execution_bundle_digest")
            or attestation.fixture_code_object_digest != config.get("fixture_code_object_digest")
        ):
            raise ValidationProofLedgerError("stored registered fixture evidence binding mismatch")

        safe_outcome = "false_positive" if result.outcome == "false_positive" else "enforced"
        decision = evaluate_evidence(
            response.observations,
            completed=response.worker_status == "completed",
            safe_outcome=safe_outcome,
        )
        expected_worker_metadata = {
            "worker_status": response.worker_status,
            "evidence_digest": response.evidence_digest,
            "attestation_digest": response.attestation_digest,
            "semantic_digest": response.semantic_digest,
            "attestation": attestation.to_dict(),
        }
        execution = result.metadata.get("execution")
        if (
            result.outcome != decision.outcome
            or result.tested != decision.conclusive
            or result.metadata.get("isolated_worker") != expected_worker_metadata
            or not isinstance(execution, Mapping)
            or execution.get("validation_plan_id") != attempt["plan_id"]
            or execution.get("validation_plan_digest") != attempt["plan_sha256"]
            or execution.get("subject_id") != attempt["subject_id"]
            or execution.get("fixture_id") != expected_fixture
            or execution.get("fixture_digest") != execution_context.fixture_digest
            or execution.get("adapter") != ISOLATED_WEB_WORKER_ADAPTER
            or execution.get("source_revision") != execution_context.source_revision
            or execution.get("outcome") != decision.outcome
        ):
            raise ValidationProofLedgerError(
                "stored result is not derived from its registered fixture response"
            )

    def _material_from_records(
        self,
        attempt: Mapping[str, Any],
        terminal: Mapping[str, Any],
    ) -> VerifiedProofMaterial | None:
        if terminal["result"] is None or terminal["proof"] is None:
            return None
        result = ValidationResult.from_dict(terminal["result"])
        proof = ValidationProof.from_dict(terminal["proof"])
        refs = tuple(ValidationEvidenceRef.from_dict(item) for item in terminal["evidence_refs"])
        if refs != proof.evidence_refs:
            raise ValidationProofLedgerError("terminal evidence references do not match proof")
        evidence_bindings = {item.evidence_id: item for item in refs}
        evidence_sizes = {item.evidence_id: len(self._read_cas(item.sha256)) for item in refs}
        material = VerifiedProofMaterial(
            proof=proof,
            engagement_id=str(attempt["engagement_id"]),
            target_id=str(attempt["target_id"]),
            subject_id=str(attempt["subject_id"]),
            subject_kind=str(attempt["subject_kind"]),
            plan_id=str(attempt["plan_id"]),
            attempt_id=str(attempt["attempt_id"]),
            result_id=result.result_id,
            outcome=result.outcome,
            oracle_id=str(attempt["oracle_id"]),
            oracle_version=str(attempt["oracle_version"]),
            subject_sha256=str(attempt["subject_sha256"]),
            plan_sha256=str(attempt["plan_sha256"]),
            result_sha256=validation_result_proof_digest(result),
            evidence_bindings=evidence_bindings,
            evidence_sha256={item.evidence_id: item.sha256 for item in refs},
            evidence_sizes=evidence_sizes,
        )
        try:
            material.validate()
        except ValidationProofError as exc:
            raise ValidationProofLedgerError("terminal proof material is inconsistent") from exc
        return material

    def _prepare_evidence(self, artifact: EvidenceArtifact) -> _PreparedEvidence:
        if len(artifact.content) > self.max_evidence_bytes:
            raise ValidationProofLedgerError("evidence exceeds configured byte limit")
        digest = hashlib.sha256(artifact.content).hexdigest()
        identifier = artifact.evidence_id or (
            "validation-evidence:"
            + _canonical_sha256(
                {
                    "kind": artifact.kind,
                    "media_type": artifact.media_type,
                    "sha256": digest,
                }
            )[:32]
        )
        reference = ValidationEvidenceRef(
            evidence_id=identifier,
            kind=artifact.kind,
            sha256=digest,
            media_type=artifact.media_type,
        )
        return _PreparedEvidence(reference=reference, content=artifact.content)

    @staticmethod
    def _dedupe_prepared(
        prepared: Sequence[_PreparedEvidence],
    ) -> list[_PreparedEvidence]:
        by_id: dict[str, _PreparedEvidence] = {}
        for item in prepared:
            previous = by_id.get(item.reference.evidence_id)
            if previous is not None and previous != item:
                raise ValidationProofLedgerError("evidence_id is bound to conflicting content")
            by_id[item.reference.evidence_id] = item
        return list(by_id.values())

    def _write_prepared_evidence(self, item: _PreparedEvidence) -> None:
        destination = self._cas_path(item.reference.sha256)
        if destination.is_file():
            if self._read_cas(item.reference.sha256) != item.content:
                raise ValidationProofLedgerError("CAS digest collision")
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write(destination, item.content)

    def _read_cas(self, digest: str) -> bytes:
        normalized = _sha256(digest, "CAS sha256")
        path = self._cas_path(normalized)
        try:
            size = path.stat().st_size
            if size > self.max_evidence_bytes:
                raise ValidationProofLedgerError("CAS object exceeds configured byte limit")
            content = path.read_bytes()
        except ValidationProofLedgerError:
            raise
        except OSError as exc:
            raise ValidationProofLedgerError("CAS object is missing") from exc
        if len(content) != size or hashlib.sha256(content).hexdigest() != normalized:
            raise ValidationProofLedgerError("CAS object digest mismatch")
        return content

    def _load_scope_manifest(
        self,
        context: ProofAuthorityContext,
        *,
        expected_authority_sha256: str,
    ) -> dict[str, Any]:
        record = self._read_json(self._scope_manifest_path(context))
        expected_keys = {
            "schema_version",
            "ledger_schema_version",
            "scope_sha256",
            "engagement_id",
            "target_id",
            "authority_version",
            "authority_sha256",
            "registered_at",
            "integrity",
        }
        if set(record) != expected_keys:
            raise ValidationProofLedgerError("scope manifest keys are not exact")
        if (
            record["schema_version"] != VALIDATION_SCOPE_SCHEMA_VERSION
            or record["ledger_schema_version"] != VALIDATION_LEDGER_SCHEMA_VERSION
            or record["scope_sha256"] != _scope_digest(context)
            or record["engagement_id"] != context.engagement_id
            or record["target_id"] != context.target_id
            or record["authority_version"] != 1
            or record["authority_sha256"] != expected_authority_sha256
        ):
            raise ValidationProofLedgerError("scope authority binding mismatch")
        _parse_timestamp(record["registered_at"], "registered_at")
        _validate_record_integrity(record)
        return record

    def _new_scope_inventory(
        self,
        context: ProofAuthorityContext,
    ) -> dict[str, Any]:
        return _finalize_record(
            {
                "schema_version": VALIDATION_INVENTORY_SCHEMA_VERSION,
                "ledger_schema_version": VALIDATION_LEDGER_SCHEMA_VERSION,
                "scope_sha256": _scope_digest(context),
                "revision": 0,
                "attempts": [],
                "terminals": [],
            }
        )

    def _load_scope_inventory(
        self,
        context: ProofAuthorityContext,
    ) -> dict[str, Any]:
        record = self._read_json(self._scope_inventory_path(context))
        if set(record) != {
            "schema_version",
            "ledger_schema_version",
            "scope_sha256",
            "revision",
            "attempts",
            "terminals",
            "integrity",
        }:
            raise ValidationProofLedgerError("scope inventory keys are not exact")
        _validate_record_integrity(record)
        if (
            record["schema_version"] != VALIDATION_INVENTORY_SCHEMA_VERSION
            or record["ledger_schema_version"] != VALIDATION_LEDGER_SCHEMA_VERSION
            or record["scope_sha256"] != _scope_digest(context)
        ):
            raise ValidationProofLedgerError("scope inventory binding mismatch")
        revision = record["revision"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 0:
            raise ValidationProofLedgerError("scope inventory revision is invalid")
        normalized: dict[str, list[dict[str, str]]] = {}
        for field_name in ("attempts", "terminals"):
            values = record[field_name]
            if not isinstance(values, list):
                raise ValidationProofLedgerError(f"scope inventory {field_name} are invalid")
            if len(values) > self.max_scope_attempts:
                raise ValidationProofLedgerError(
                    f"scope exceeds configured {field_name[:-1]} limit"
                )
            entries: list[dict[str, str]] = []
            for value in values:
                if not isinstance(value, dict) or set(value) != {
                    "attempt_id",
                    "record_sha256",
                }:
                    raise ValidationProofLedgerError(
                        f"scope inventory {field_name} entry is invalid"
                    )
                entries.append(
                    {
                        "attempt_id": _attempt_identifier(value["attempt_id"]),
                        "record_sha256": _sha256(
                            value["record_sha256"],
                            "inventory record_sha256",
                        ),
                    }
                )
            if entries != sorted(entries, key=lambda item: item["attempt_id"]):
                raise ValidationProofLedgerError(f"scope inventory {field_name} are not canonical")
            if len({item["attempt_id"] for item in entries}) != len(entries):
                raise ValidationProofLedgerError(f"scope inventory {field_name} contain duplicates")
            normalized[field_name] = entries
        if revision != len(normalized["attempts"]) + len(normalized["terminals"]):
            raise ValidationProofLedgerError("scope inventory revision mismatch")
        attempt_ids = {item["attempt_id"] for item in normalized["attempts"]}
        if any(item["attempt_id"] not in attempt_ids for item in normalized["terminals"]):
            raise ValidationProofLedgerError("scope inventory terminal has no registered attempt")
        return record

    def _append_scope_inventory_entry(
        self,
        context: ProofAuthorityContext,
        *,
        field_name: str,
        record: Mapping[str, Any],
    ) -> dict[str, Any]:
        if field_name not in {"attempts", "terminals"}:
            raise AssertionError("unsupported scope inventory field")
        inventory = self._load_scope_inventory(context)
        attempt_id = _attempt_identifier(record["attempt_id"])
        record_sha256 = _sha256(
            record["integrity"]["record_sha256"],
            "record_sha256",
        )
        entries = list(inventory[field_name])
        existing = next(
            (item for item in entries if item["attempt_id"] == attempt_id),
            None,
        )
        expected = {
            "attempt_id": attempt_id,
            "record_sha256": record_sha256,
        }
        if existing is not None:
            if existing != expected:
                raise ValidationProofLedgerError(
                    "scope inventory entry conflicts with durable record"
                )
            return inventory
        if len(entries) >= self.max_scope_attempts:
            raise ValidationProofLedgerError(f"scope exceeds configured {field_name[:-1]} limit")
        if field_name == "terminals" and attempt_id not in {
            item["attempt_id"] for item in inventory["attempts"]
        }:
            raise ValidationProofLedgerError("scope inventory terminal has no registered attempt")
        entries.append(expected)
        entries.sort(key=lambda item: item["attempt_id"])
        updated = copy.deepcopy(inventory)
        updated.pop("integrity", None)
        updated[field_name] = entries
        updated["revision"] = int(inventory["revision"]) + 1
        finalized = _finalize_record(updated)
        self._atomic_replace(
            self._scope_inventory_path(context),
            self._record_bytes(finalized),
        )
        return finalized

    def _publish_record_transactionally(
        self,
        context: ProofAuthorityContext,
        *,
        field_name: str,
        record: Mapping[str, Any],
        record_bytes: bytes,
    ) -> None:
        """Durably declare a record before publishing it and its inventory entry."""

        if field_name not in {"attempts", "terminals"}:
            raise AssertionError("unsupported transactional record field")
        expected_bytes = self._record_bytes(record)
        if record_bytes != expected_bytes:
            raise ValidationProofLedgerError("transactional record bytes are not canonical")
        pending = self._pending_record_path(
            context,
            field_name=field_name,
            attempt_id=_attempt_identifier(record["attempt_id"]),
        )
        if pending.is_file():
            stored = self._read_json(pending)
            _validate_record_integrity(stored)
            if stored != dict(record):
                raise ValidationProofLedgerError("pending ledger transaction conflicts with record")
        else:
            self._atomic_write(pending, record_bytes)
        self._roll_forward_pending_record(
            context,
            field_name=field_name,
            pending_path=pending,
            record=dict(record),
        )

    def _recover_scope_transactions(
        self,
        context: ProofAuthorityContext,
    ) -> None:
        """Roll forward only records carrying a durable pre-publication intent."""

        pending_root = self._scope_directory(context) / "pending"
        if not pending_root.exists():
            return
        for field_name in ("attempts", "terminals"):
            pending_dir = pending_root / field_name
            if not pending_dir.exists():
                continue
            paths = tuple(
                islice(
                    pending_dir.glob("*.json"),
                    self.max_scope_attempts + 1,
                )
            )
            if len(paths) > self.max_scope_attempts:
                raise ValidationProofLedgerError(
                    f"scope exceeds configured pending {field_name[:-1]} limit"
                )
            for path in sorted(paths):
                identifier = _attempt_identifier(path.stem)
                if path.name != f"{identifier}.json":
                    raise ValidationProofLedgerError(
                        "pending ledger transaction path is not canonical"
                    )
                if field_name == "attempts":
                    record = self._load_attempt_path(context, path)
                else:
                    attempt = self._load_attempt_path(
                        context,
                        self._attempt_path(context, identifier),
                    )
                    self._require_scope_inventory_entry(
                        context,
                        field_name="attempts",
                        record=attempt,
                    )
                    record = self._load_terminal_path(context, path, attempt)
                if record["attempt_id"] != identifier:
                    raise ValidationProofLedgerError(
                        "pending ledger transaction attempt_id mismatch"
                    )
                self._roll_forward_pending_record(
                    context,
                    field_name=field_name,
                    pending_path=path,
                    record=record,
                )

    def _roll_forward_pending_record(
        self,
        context: ProofAuthorityContext,
        *,
        field_name: str,
        pending_path: Path,
        record: Mapping[str, Any],
    ) -> None:
        attempt_id = _attempt_identifier(record["attempt_id"])
        destination = (
            self._attempt_path(context, attempt_id)
            if field_name == "attempts"
            else self._terminal_path(context, attempt_id)
        )
        if destination.is_file():
            stored = self._read_json(destination)
            _validate_record_integrity(stored)
            if stored != dict(record):
                raise ValidationProofLedgerError(
                    "pending ledger transaction conflicts with durable record"
                )
        else:
            self._atomic_write(destination, self._record_bytes(record))
        self._append_scope_inventory_entry(
            context,
            field_name=field_name,
            record=record,
        )
        self._remove_durable_file(pending_path)

    def _require_scope_inventory_entry(
        self,
        context: ProofAuthorityContext,
        *,
        field_name: str,
        record: Mapping[str, Any],
    ) -> None:
        inventory = self._load_scope_inventory(context)
        attempt_id = str(record["attempt_id"])
        expected_digest = str(record["integrity"]["record_sha256"])
        matches = tuple(item for item in inventory[field_name] if item["attempt_id"] == attempt_id)
        if len(matches) != 1 or matches[0]["record_sha256"] != expected_digest:
            raise ValidationProofLedgerError("durable record is missing from the scope inventory")

    def _load_attempt_path(
        self,
        context: ProofAuthorityContext,
        path: Path,
    ) -> dict[str, Any]:
        record = self._read_json(path)
        expected_keys = {
            "schema_version",
            "ledger_schema_version",
            "attempt_id",
            "scope_sha256",
            "engagement_id",
            "target_id",
            "subject_id",
            "subject_kind",
            "subject_sha256",
            "plan_id",
            "plan_sha256",
            "oracle_id",
            "oracle_version",
            "request_ref",
            "started_at",
            "integrity",
        }
        if set(record) != expected_keys:
            raise ValidationProofLedgerError("attempt record keys are not exact")
        if (
            record["schema_version"] != VALIDATION_ATTEMPT_SCHEMA_VERSION
            or record["ledger_schema_version"] != VALIDATION_LEDGER_SCHEMA_VERSION
            or record["scope_sha256"] != _scope_digest(context)
            or record["engagement_id"] != context.engagement_id
            or record["target_id"] != context.target_id
        ):
            raise ValidationProofLedgerError("attempt scope binding mismatch")
        _attempt_identifier(record["attempt_id"])
        for field_name in (
            "subject_id",
            "subject_kind",
            "plan_id",
            "oracle_id",
            "oracle_version",
        ):
            _ledger_identifier(record[field_name], field_name)
        _sha256(record["subject_sha256"], "subject_sha256")
        _sha256(record["plan_sha256"], "plan_sha256")
        request_ref = ValidationEvidenceRef.from_dict(record["request_ref"])
        if (
            request_ref.kind != "request"
            or request_ref.evidence_id != f"validation-request:{record['attempt_id']}"
        ):
            raise ValidationProofLedgerError("attempt request_ref kind is invalid")
        self._read_cas(request_ref.sha256)
        _parse_timestamp(record["started_at"], "started_at")
        _validate_record_integrity(record)
        return record

    def _load_terminal_path(
        self,
        context: ProofAuthorityContext,
        path: Path,
        attempt: Mapping[str, Any],
    ) -> dict[str, Any]:
        record = self._read_json(path)
        expected_keys = {
            "schema_version",
            "ledger_schema_version",
            "attempt_id",
            "scope_sha256",
            "engagement_id",
            "target_id",
            "terminal_status",
            "finished_at",
            "result",
            "proof",
            "evidence_refs",
            "integrity",
        }
        if set(record) != expected_keys:
            raise ValidationProofLedgerError("terminal record keys are not exact")
        _validate_record_integrity(record)
        if (
            record["schema_version"] != VALIDATION_TERMINAL_SCHEMA_VERSION
            or record["ledger_schema_version"] != VALIDATION_LEDGER_SCHEMA_VERSION
            or record["attempt_id"] != attempt["attempt_id"]
            or record["scope_sha256"] != _scope_digest(context)
            or record["engagement_id"] != context.engagement_id
            or record["target_id"] != context.target_id
            or record["terminal_status"] not in TERMINAL_STATUSES
        ):
            raise ValidationProofLedgerError("terminal attempt binding mismatch")
        _parse_timestamp(record["finished_at"], "finished_at")
        refs_value = record["evidence_refs"]
        if not isinstance(refs_value, list) or len(refs_value) > self.max_evidence_refs:
            raise ValidationProofLedgerError("terminal evidence_refs are invalid")
        refs = tuple(ValidationEvidenceRef.from_dict(item) for item in refs_value)
        if refs != tuple(
            sorted(
                refs,
                key=lambda item: (item.evidence_id, item.kind, item.sha256),
            )
        ) or len({item.evidence_id for item in refs}) != len(refs):
            raise ValidationProofLedgerError("terminal evidence_refs are not canonical")
        request_ref = ValidationEvidenceRef.from_dict(attempt["request_ref"])
        request_refs = tuple(item for item in refs if item.kind == "request")
        if request_refs != (request_ref,):
            raise ValidationProofLedgerError("terminal request artifact binding mismatch")
        response_refs = tuple(item for item in refs if item.kind == "response")
        expected_response_id = f"validation-response:{attempt['attempt_id']}"
        if len(response_refs) > 1 or (
            response_refs and response_refs[0].evidence_id != expected_response_id
        ):
            raise ValidationProofLedgerError("terminal response artifact binding mismatch")
        total = 0
        for reference in refs:
            total += len(self._read_cas(reference.sha256))
        if total > self.max_total_evidence_bytes:
            raise ValidationProofLedgerError("terminal evidence exceeds total limit")
        if record["result"] is None:
            if record["proof"] is not None or record["terminal_status"] == "completed":
                raise ValidationProofLedgerError("terminal result/proof presence is inconsistent")
        else:
            result = ValidationResult.from_dict(record["result"])
            canonical, payload = _canonical_result(result)
            if payload != record["result"]:
                raise ValidationProofLedgerError("terminal result is not canonical")
            if (
                canonical.subject_id != attempt["subject_id"]
                or canonical.subject_kind != attempt["subject_kind"]
            ):
                raise ValidationProofLedgerError("terminal result subject does not match attempt")
            metadata = canonical.metadata
            if (
                metadata.get("validation_plan_id") != attempt["plan_id"]
                or metadata.get("validation_plan_digest") != attempt["plan_sha256"]
            ):
                raise ValidationProofLedgerError(
                    "terminal result plan binding does not match attempt"
                )
            if record["terminal_status"] != "completed" and canonical.outcome != "inconclusive":
                raise ValidationProofLedgerError("non-completed terminal has conclusive outcome")
            if len(response_refs) != 1:
                raise ValidationProofLedgerError(
                    "terminal result requires one captured worker response"
                )
            if record["proof"] is not None:
                proof = ValidationProof.from_dict(record["proof"])
                if attempt["subject_kind"] != "validation_contract_seed" or not str(
                    attempt["target_id"]
                ).startswith("registered-fixture:"):
                    raise ValidationProofLedgerError(
                        "terminal proof is outside the registered fixture policy"
                    )
                if proof.evidence_refs != refs:
                    raise ValidationProofLedgerError("terminal proof evidence set mismatch")
                proof_bindings = {
                    "engagement_id": attempt["engagement_id"],
                    "target_id": attempt["target_id"],
                    "subject_id": attempt["subject_id"],
                    "subject_kind": attempt["subject_kind"],
                    "plan_id": attempt["plan_id"],
                    "attempt_id": attempt["attempt_id"],
                    "result_id": canonical.result_id,
                    "outcome": canonical.outcome,
                    "oracle_id": attempt["oracle_id"],
                    "oracle_version": attempt["oracle_version"],
                }
                mismatches = tuple(
                    field_name
                    for field_name, expected in proof_bindings.items()
                    if getattr(proof, field_name) != expected
                )
                if mismatches:
                    raise ValidationProofLedgerError(
                        "terminal proof binding mismatch: " + ", ".join(mismatches)
                    )
            result_refs = [
                item
                for item in refs
                if item.evidence_id == f"validation-result:{canonical.result_id}"
            ]
            if (
                len(result_refs) != 1
                or result_refs[0].kind != "artifact"
                or result_refs[0].media_type != "application/vnd.belief.validation-result.v1+json"
                or result_refs[0].sha256 != validation_result_proof_digest(canonical)
            ):
                raise ValidationProofLedgerError("terminal result artifact binding mismatch")
            if record["proof"] is not None:
                self._validate_stored_registered_fixture_proof(
                    attempt,
                    terminal_status=str(record["terminal_status"]),
                    result=canonical,
                    response_ref=response_refs[0],
                )
        return record

    @staticmethod
    def _attempt_semantic(record: Mapping[str, Any]) -> dict[str, Any]:
        value = copy.deepcopy(dict(record))
        value.pop("started_at", None)
        value.pop("integrity", None)
        return value

    @staticmethod
    def _terminal_semantic(record: Mapping[str, Any]) -> dict[str, Any]:
        value = copy.deepcopy(dict(record))
        value.pop("finished_at", None)
        value.pop("integrity", None)
        return value

    @staticmethod
    def _attempt_handle(record: Mapping[str, Any]) -> AttemptHandle:
        return AttemptHandle(
            attempt_id=str(record["attempt_id"]),
            engagement_id=str(record["engagement_id"]),
            target_id=str(record["target_id"]),
            subject_id=str(record["subject_id"]),
            subject_kind=str(record["subject_kind"]),
            plan_id=str(record["plan_id"]),
            subject_sha256=str(record["subject_sha256"]),
            plan_sha256=str(record["plan_sha256"]),
            oracle_id=str(record["oracle_id"]),
            oracle_version=str(record["oracle_version"]),
            request_ref=ValidationEvidenceRef.from_dict(record["request_ref"]),
        )

    @staticmethod
    def _terminal_receipt(
        record: Mapping[str, Any],
        *,
        replayed: bool,
    ) -> TerminalReceipt:
        result = (
            ValidationResult.from_dict(record["result"]) if record["result"] is not None else None
        )
        proof = ValidationProof.from_dict(record["proof"]) if record["proof"] is not None else None
        if result is not None and proof is not None:
            metadata = dict(result.metadata)
            metadata["validation_proof"] = proof.to_dict()
            result = replace(result, metadata=metadata)
        return TerminalReceipt(
            attempt_id=str(record["attempt_id"]),
            terminal_status=str(record["terminal_status"]),
            result=result,
            proof=proof,
            replayed=replayed,
        )

    @staticmethod
    def _context(context: ProofAuthorityContext) -> ProofAuthorityContext:
        if not isinstance(context, ProofAuthorityContext):
            raise TypeError("validation ledger requires ProofAuthorityContext")
        return context

    def _scope_directory(self, context: ProofAuthorityContext) -> Path:
        digest = _scope_digest(context)
        return self.scopes_dir / digest[:2] / digest

    def _scope_manifest_path(self, context: ProofAuthorityContext) -> Path:
        return self._scope_directory(context) / "authority.json"

    def _scope_inventory_path(self, context: ProofAuthorityContext) -> Path:
        return self._scope_directory(context) / "inventory.json"

    def _attempt_path(self, context: ProofAuthorityContext, attempt_id: str) -> Path:
        return self._scope_directory(context) / "attempts" / f"{attempt_id}.json"

    def _terminal_path(self, context: ProofAuthorityContext, attempt_id: str) -> Path:
        return self._scope_directory(context) / "terminals" / f"{attempt_id}.json"

    def _pending_record_path(
        self,
        context: ProofAuthorityContext,
        *,
        field_name: str,
        attempt_id: str,
    ) -> Path:
        if field_name not in {"attempts", "terminals"}:
            raise AssertionError("unsupported pending record field")
        return (
            self._scope_directory(context)
            / "pending"
            / field_name
            / f"{_attempt_identifier(attempt_id)}.json"
        )

    def _scope_has_pending_transactions(
        self,
        context: ProofAuthorityContext,
    ) -> bool:
        pending_root = self._scope_directory(context) / "pending"
        return any(
            next((pending_root / field_name).glob("*.json"), None) is not None
            for field_name in ("attempts", "terminals")
        )

    def _cas_path(self, digest: str) -> Path:
        return self.cas_dir / digest[:2] / digest

    def _read_json(self, path: Path) -> dict[str, Any]:
        try:
            if path.stat().st_size > self.max_record_bytes:
                raise ValidationProofLedgerError(
                    "durable ledger record exceeds configured byte limit"
                )
            raw = path.read_bytes()
            if len(raw) > self.max_record_bytes:
                raise ValidationProofLedgerError(
                    "durable ledger record exceeds configured byte limit"
                )
            value = strict_json_loads(raw)
        except ValidationProofLedgerError:
            raise
        except (OSError, StrictJSONError, RecursionError, TypeError, ValueError) as exc:
            raise ValidationProofLedgerError(
                f"cannot load durable ledger record: {path.name}"
            ) from exc
        if not isinstance(value, dict):
            raise ValidationProofLedgerError("durable ledger record must be an object")
        return value

    def _record_bytes(self, record: Mapping[str, Any]) -> bytes:
        data = _canonical_json_bytes(record) + b"\n"
        if len(data) > self.max_record_bytes:
            raise ValidationProofLedgerError("durable ledger record exceeds configured byte limit")
        return data

    @staticmethod
    def _atomic_write(destination: Path, data: bytes) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".{destination.name}.tmp-{uuid.uuid4().hex}"
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, destination)
            ValidationProofLedger._fsync_directory(destination.parent)
        except FileExistsError as exc:
            raise ValidationProofLedgerError(
                f"refusing to overwrite durable ledger path: {destination.name}"
            ) from exc
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _atomic_replace(destination: Path, data: bytes) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.parent / f".{destination.name}.tmp-{uuid.uuid4().hex}"
        try:
            with temporary.open("xb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
            ValidationProofLedger._fsync_directory(destination.parent)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _remove_durable_file(path: Path) -> None:
        try:
            path.unlink()
        except OSError as exc:
            raise ValidationProofLedgerError(
                f"cannot clear completed ledger transaction: {path.name}"
            ) from exc
        ValidationProofLedger._fsync_directory(path.parent)

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        if os.name == "nt":
            return
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _cleanup_temporary_files(self) -> None:
        for path in self.root.rglob(".*.tmp-*"):
            try:
                if path.is_file():
                    path.unlink()
            except OSError:
                continue

    @contextmanager
    def _exclusive(self):
        with self._lock:
            with self.lock_path.open("r+b") as handle:
                if os.name == "nt":
                    import msvcrt

                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
                    try:
                        yield
                    finally:
                        handle.seek(0)
                        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    try:
                        yield
                    finally:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def run_registered_fixture_validation_with_ledger(
    ledger: ValidationProofLedger,
    authority_context: ProofAuthorityContext,
    plan: ValidationPlan,
    *,
    expected_authority_sha256: str,
    fixture_id: str,
    source_revision: str,
    test_parameters: Mapping[str, Any] | None = None,
    timeout_ms: int = 5_000,
    correlation_id: str = "",
    on_handle: Callable[[Any], None] | None = None,
) -> ValidationResult:
    """Execute one registered fixture with an attempt durable before spawn.

    This deliberately cannot authorize an arbitrary project target.  The
    authority target must be the exact registered-fixture identity and the plan
    subject must be a validation contract seed.  Promotion for real audit-case
    targets requires a separately designed executor and authority policy.
    """

    if not isinstance(ledger, ValidationProofLedger):
        raise TypeError("ledger must be a ValidationProofLedger")
    if not isinstance(plan, ValidationPlan):
        raise TypeError("plan must be a ValidationPlan")
    expected_target = f"registered-fixture:{fixture_id}"
    if (
        plan.subject_kind != "validation_contract_seed"
        or authority_context.target_id != expected_target
    ):
        raise ValidationProofLedgerError(
            "durable fixture validation cannot authorize a project target"
        )
    subject_sha256 = str(plan.metadata.get("proof_subject_sha256") or "").lower()
    if not _SHA256_RE.fullmatch(subject_sha256):
        raise ValidationProofLedgerError("validation plan lacks a proof subject snapshot digest")

    from .worker.contracts import WORKER_RESPONSE_SCHEMA_VERSION
    from .worker.process import (
        build_isolated_web_context,
        run_isolated_web_validation_plan,
    )

    execution_context = build_isolated_web_context(
        plan,
        fixture_id=fixture_id,
        source_revision=source_revision,
        test_parameters=test_parameters,
        timeout_ms=timeout_ms,
        correlation_id=correlation_id,
    )
    attempt = ledger.begin_attempt(
        authority_context,
        plan,
        expected_authority_sha256=expected_authority_sha256,
        subject_sha256=subject_sha256,
        request_bytes=_canonical_json_bytes(execution_context.to_dict()),
        request_media_type=("application/vnd.belief.validation-execution-context.v1+json"),
        oracle_id=f"isolated-web:{plan.case_type}",
        oracle_version=WORKER_RESPONSE_SCHEMA_VERSION,
    )
    responses: list[Any] = []
    try:
        result = run_isolated_web_validation_plan(
            plan,
            fixture_id=fixture_id,
            source_revision=source_revision,
            test_parameters=test_parameters,
            timeout_ms=timeout_ms,
            correlation_id=correlation_id,
            on_handle=on_handle,
            on_response=responses.append,
        )
    except Exception as exc:
        ledger.finish_attempt(
            attempt,
            terminal_status="crashed",
            result=None,
            evidence=(
                EvidenceArtifact(
                    kind="log",
                    content=_canonical_json_bytes({"exception_type": type(exc).__name__}),
                    media_type="application/json",
                ),
            ),
        )
        raise
    if len(responses) != 1:
        ledger.finish_attempt(
            attempt,
            terminal_status="failed",
            result=None,
            evidence=(
                EvidenceArtifact(
                    kind="log",
                    content=b'{"error":"worker_response_missing"}',
                    media_type="application/json",
                ),
            ),
        )
        raise ValidationProofLedgerError("isolated worker returned no durable response")
    response = responses[0]
    status = {
        "completed": "completed",
        "timed_out": "timed_out",
        "cancelled": "cancelled",
        "crashed": "crashed",
    }.get(str(response.worker_status), "failed")
    receipt = ledger._finish_registered_fixture_attempt(
        attempt,
        plan=plan,
        fixture_id=fixture_id,
        terminal_status=status,
        result=result,
        response=response,
    )
    if receipt.result is None:
        raise ValidationProofLedgerError("durable worker terminal omitted its result")
    return receipt.result


__all__ = [
    "DEFAULT_MAX_EVIDENCE_BYTES",
    "DEFAULT_MAX_EVIDENCE_REFS",
    "DEFAULT_MAX_RECORD_BYTES",
    "DEFAULT_MAX_SCOPE_ATTEMPTS",
    "DEFAULT_MAX_TOTAL_EVIDENCE_BYTES",
    "TERMINAL_STATUSES",
    "VALIDATION_ATTEMPT_SCHEMA_VERSION",
    "VALIDATION_INVENTORY_SCHEMA_VERSION",
    "VALIDATION_LEDGER_SCHEMA_VERSION",
    "VALIDATION_SCOPE_SCHEMA_VERSION",
    "VALIDATION_TERMINAL_SCHEMA_VERSION",
    "AttemptHandle",
    "EvidenceArtifact",
    "TerminalReceipt",
    "ValidationProofLedger",
    "ValidationProofLedgerError",
    "VerifiedProofSnapshot",
    "run_registered_fixture_validation_with_ledger",
]
