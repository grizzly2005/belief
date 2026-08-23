"""Durable, metadata-only import journal for PDX observation attestations."""

from __future__ import annotations

import copy
import hashlib
import os
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

from belief.json_contracts import StrictJSONError, strict_json_dumps, strict_json_loads

from .attestation import (
    ATTESTATION_ID_RE,
    CAPTURE_ID_RE,
    ENDPOINT_ID_RE,
    OPAQUE_REF_RE,
    PDXAttestationError,
    SHA256_RE,
    TARGET_ID_RE,
    parse_attestation,
    parse_datetime,
    parse_engagement,
)

RECEIPT_SCHEMA_VERSION = "belief.pdx_attestation_receipt.v1"
RECEIPT_CANONICALIZATION = "belief-pdx-attestation-receipt-json-v1"
DEFAULT_MAX_INPUT_BYTES = 2 * 1024 * 1024


class PDXEvidenceStoreError(ValueError):
    """Raised when the durable registry or journal is internally inconsistent."""


@dataclass(frozen=True)
class AttestationImportResult:
    receipt: dict[str, Any]
    replayed: bool

    def to_dict(self) -> dict[str, Any]:
        return {"receipt": copy.deepcopy(self.receipt), "replayed": self.replayed}


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json_bytes(value: Any) -> bytes:
    return strict_json_dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _receipt_sha256(value: Mapping[str, Any]) -> str:
    document = copy.deepcopy(dict(value))
    document["receipt_id"] = None
    document["integrity"]["receipt_sha256"] = None
    return hashlib.sha256(_canonical_json_bytes(document)).hexdigest()


def _finalize_receipt(value: dict[str, Any]) -> dict[str, Any]:
    digest = _receipt_sha256(value)
    value["integrity"]["receipt_sha256"] = digest
    value["receipt_id"] = f"belief:pdx-receipt:sha256:{digest}"
    return value


def _validate_receipt(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PDXEvidenceStoreError("receipt must be an object")
    expected = {
        "schema_version",
        "receipt_id",
        "import_id",
        "raw_sha256",
        "received_at",
        "status",
        "attestation_id",
        "engagement_id",
        "engagement_version",
        "reason_codes",
        "caveats",
        "observation_refs",
        "integrity",
    }
    if set(value) != expected:
        raise PDXEvidenceStoreError("receipt keys are not exact")
    if value["schema_version"] != RECEIPT_SCHEMA_VERSION:
        raise PDXEvidenceStoreError("unsupported receipt schema")
    raw_hash = value["raw_sha256"]
    if not isinstance(raw_hash, str) or len(raw_hash) != 64 or any(char not in "0123456789abcdef" for char in raw_hash):
        raise PDXEvidenceStoreError("receipt raw_sha256 is invalid")
    if value["import_id"] != f"belief:pdx-import:sha256:{raw_hash}":
        raise PDXEvidenceStoreError("receipt import_id does not bind raw_sha256")
    parse_datetime(value["received_at"], "receipt.received_at")
    if value["status"] not in {"ACCEPT", "QUARANTINE", "REJECT"}:
        raise PDXEvidenceStoreError("receipt status is invalid")
    if (
        not isinstance(value["reason_codes"], list)
        or any(not isinstance(item, str) or not item for item in value["reason_codes"])
        or value["reason_codes"] != sorted(set(value["reason_codes"]))
    ):
        raise PDXEvidenceStoreError("receipt reason_codes are not canonical")
    if (
        not isinstance(value["caveats"], list)
        or any(not isinstance(item, str) or not item for item in value["caveats"])
        or value["caveats"] != sorted(set(value["caveats"]))
    ):
        raise PDXEvidenceStoreError("receipt caveats are not canonical")
    refs = value["observation_refs"]
    if not isinstance(refs, list):
        raise PDXEvidenceStoreError("receipt observation_refs must be a list")
    for ref in refs:
        if not isinstance(ref, dict) or set(ref) != {
            "capture_id", "observation_hash", "target_id", "endpoint_id", "proof_state"
        }:
            raise PDXEvidenceStoreError("receipt observation reference is invalid")
        if ref["proof_state"] != "signal_only_no_belief_attempt_result_evidence":
            raise PDXEvidenceStoreError("receipt observation proof_state is invalid")
        if not isinstance(ref["capture_id"], str) or not CAPTURE_ID_RE.fullmatch(ref["capture_id"]):
            raise PDXEvidenceStoreError("receipt capture_id is invalid")
        if not isinstance(ref["observation_hash"], str) or not SHA256_RE.fullmatch(ref["observation_hash"]):
            raise PDXEvidenceStoreError("receipt observation_hash is invalid")
        if not isinstance(ref["target_id"], str) or not TARGET_ID_RE.fullmatch(ref["target_id"]):
            raise PDXEvidenceStoreError("receipt target_id is invalid")
        if not isinstance(ref["endpoint_id"], str) or not ENDPOINT_ID_RE.fullmatch(ref["endpoint_id"]):
            raise PDXEvidenceStoreError("receipt endpoint_id is invalid")
    if refs != sorted(refs, key=lambda item: item["capture_id"]):
        raise PDXEvidenceStoreError("receipt observation_refs are not canonical")
    if value["status"] != "ACCEPT" and refs:
        raise PDXEvidenceStoreError("non-accepted receipts cannot expose observation references")
    if value["status"] == "REJECT":
        if any(value[name] is not None for name in ("attestation_id", "engagement_id", "engagement_version")):
            raise PDXEvidenceStoreError("rejected receipt contains untrusted attestation identity")
    else:
        if not isinstance(value["attestation_id"], str) or not ATTESTATION_ID_RE.fullmatch(value["attestation_id"]):
            raise PDXEvidenceStoreError("receipt attestation_id is invalid")
        if not isinstance(value["engagement_id"], str) or not OPAQUE_REF_RE.fullmatch(value["engagement_id"]):
            raise PDXEvidenceStoreError("receipt engagement_id is invalid")
        if (
            not isinstance(value["engagement_version"], int)
            or isinstance(value["engagement_version"], bool)
            or value["engagement_version"] < 1
        ):
            raise PDXEvidenceStoreError("receipt engagement_version is invalid")
    integrity = value["integrity"]
    if not isinstance(integrity, dict) or set(integrity) != {"canonicalization", "receipt_sha256"}:
        raise PDXEvidenceStoreError("receipt integrity object is invalid")
    if integrity["canonicalization"] != RECEIPT_CANONICALIZATION:
        raise PDXEvidenceStoreError("unsupported receipt canonicalization")
    digest = _receipt_sha256(value)
    if integrity["receipt_sha256"] != digest:
        raise PDXEvidenceStoreError("receipt digest mismatch")
    if value["receipt_id"] != f"belief:pdx-receipt:sha256:{digest}":
        raise PDXEvidenceStoreError("receipt_id mismatch")
    return copy.deepcopy(value)


class PDXEvidenceStore:
    """Immutable engagement registry and restart-safe attestation journal.

    The store persists only engagement metadata and import receipts.  It never
    persists the source attestation, HTTP bytes, headers, or PDX CAS paths.
    """

    def __init__(self, root: str | Path = "belief_pdx_evidence", *, max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES):
        if max_input_bytes <= 0:
            raise ValueError("max_input_bytes must be positive")
        self.root = Path(root).expanduser().resolve()
        self.max_input_bytes = max_input_bytes
        self.engagements_dir = self.root / "engagements"
        self.receipts_dir = self.root / "receipts" / "sha256"
        self.lock_path = self.root / ".import.lock"
        self._lock = threading.RLock()
        self.engagements_dir.mkdir(parents=True, exist_ok=True)
        self.receipts_dir.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as handle:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
        with self._exclusive():
            self._cleanup_temporary_files()

    def register_engagement(self, value: Any, *, registered_at: str | None = None) -> dict[str, Any]:
        engagement = parse_engagement(value)
        if registered_at is not None:
            parse_datetime(registered_at, "registered_at")
        content = _canonical_json_bytes(engagement)
        content_hash = hashlib.sha256(content).hexdigest()
        directory = self._engagement_directory(engagement["engagement_id"])
        version = engagement["engagement_version"]
        destination = directory / f"v{version:010d}-{content_hash}.json"
        with self._exclusive():
            existing = sorted(directory.glob(f"v{version:010d}-*.json")) if directory.exists() else []
            if len(existing) > 1:
                raise PDXEvidenceStoreError("multiple immutable registrations exist for one engagement version")
            if existing:
                stored = self._load_engagement_path(existing[0])
                if stored != engagement:
                    raise PDXEvidenceStoreError("engagement id/version is already registered with different content")
                status = "already_present"
            else:
                self._atomic_write(destination, content + b"\n")
                status = "registered"
        return {
            "schema_version": engagement["schema_version"],
            "status": status,
            "engagement_id": engagement["engagement_id"],
            "engagement_version": version,
            "registration_sha256": content_hash,
        }

    def import_attestation_file(
        self, path: str | Path, *, received_at: str | None = None
    ) -> AttestationImportResult:
        source = Path(path)
        try:
            size = source.stat().st_size
            if size > self.max_input_bytes:
                raise PDXAttestationError("attestation exceeds the configured byte limit")
            raw = source.read_bytes()
        except PDXAttestationError:
            raise
        except OSError as exc:
            raise PDXEvidenceStoreError(f"cannot read attestation input: {exc}") from exc
        if len(raw) > self.max_input_bytes:
            raise PDXAttestationError("attestation exceeds the configured byte limit")
        return self.import_attestation_bytes(raw, received_at=received_at)

    def import_attestation_bytes(
        self, raw: bytes, *, received_at: str | None = None
    ) -> AttestationImportResult:
        if not isinstance(raw, bytes):
            raise TypeError("raw attestation must be bytes")
        if len(raw) > self.max_input_bytes:
            raise PDXAttestationError("attestation exceeds the configured byte limit")
        timestamp = received_at or _utc_now()
        parse_datetime(timestamp, "received_at")
        raw_hash = hashlib.sha256(raw).hexdigest()

        with self._exclusive():
            existing = self._receipt_path(raw_hash)
            if existing.is_file():
                return AttestationImportResult(self._load_receipt(existing, raw_hash), replayed=True)

            try:
                decoded = strict_json_loads(raw)
                attestation = parse_attestation(decoded)
            except (StrictJSONError, PDXAttestationError, RecursionError, TypeError, ValueError):
                receipt = self._make_receipt(
                    raw_hash=raw_hash,
                    received_at=timestamp,
                    status="REJECT",
                    reason_codes=["invalid_attestation"],
                )
                self._write_receipt(receipt)
                return AttestationImportResult(receipt, replayed=False)

            reasons: set[str] = set()
            caveats: set[str] = {
                "observation_attestation_is_signal_only",
                "no_belief_attempt_result_or_evidence",
            }
            projected = attestation["engagement"]
            try:
                engagement = self._load_engagement(
                    projected["engagement_id"], projected["engagement_version"]
                )
            except PDXEvidenceStoreError:
                engagement = None
                reasons.add("engagement_registry_corrupt")
            if engagement is None and not reasons:
                reasons.add("engagement_not_registered")
            if engagement is not None:
                if engagement["status"] != "active":
                    reasons.add("engagement_not_active")
                for field in ("scope_ref", "scope_sha256", "authorization_ref"):
                    if projected[field] != engagement[field]:
                        reasons.add(f"{field}_mismatch")
                valid_from = parse_datetime(engagement["valid_from"], "engagement.valid_from")
                valid_until = parse_datetime(engagement["valid_until"], "engagement.valid_until")
                authorized_targets = set(engagement["target_ids"])
                for observation in attestation["observations"]:
                    observed_at = parse_datetime(observation["observed_at"], "observation.observed_at")
                    if not valid_from <= observed_at <= valid_until:
                        reasons.add("observation_outside_engagement_validity")
                    if observation["identity"]["target_id"] not in authorized_targets:
                        reasons.add("target_not_authorized")

            prior_claims = self._accepted_capture_claims()
            for observation in attestation["observations"]:
                prior_hash = prior_claims.get(observation["capture_id"])
                if prior_hash is not None and prior_hash != observation["observation_hash"]:
                    reasons.add("capture_id_hash_conflict")
                elif prior_hash == observation["observation_hash"]:
                    caveats.add("observation_already_imported")
                if observation["identity"]["correlation_state"] == "non_joinable":
                    caveats.add("identity_non_joinable_signal_only")
                if observation["truncated_any"]:
                    caveats.add("source_observation_truncated")
                if any(state == "producer_declared" for state in observation["payload_integrity"].values()):
                    caveats.add("one_or_more_full_payload_hashes_are_producer_declared")

            status = "QUARANTINE" if reasons else "ACCEPT"
            references = []
            if status == "ACCEPT":
                references = [
                    {
                        "capture_id": observation["capture_id"],
                        "observation_hash": observation["observation_hash"],
                        "target_id": observation["identity"]["target_id"],
                        "endpoint_id": observation["identity"]["endpoint_id"],
                        "proof_state": "signal_only_no_belief_attempt_result_evidence",
                    }
                    for observation in attestation["observations"]
                ]
            receipt = self._make_receipt(
                raw_hash=raw_hash,
                received_at=timestamp,
                status=status,
                attestation=attestation,
                reason_codes=sorted(reasons),
                caveats=sorted(caveats),
                observation_refs=references,
            )
            self._write_receipt(receipt)
            return AttestationImportResult(receipt, replayed=False)

    def _make_receipt(
        self,
        *,
        raw_hash: str,
        received_at: str,
        status: str,
        attestation: Mapping[str, Any] | None = None,
        reason_codes: list[str] | None = None,
        caveats: list[str] | None = None,
        observation_refs: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        projected = attestation["engagement"] if attestation is not None else None
        receipt = {
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "receipt_id": "belief:pdx-receipt:sha256:" + ("0" * 64),
            "import_id": f"belief:pdx-import:sha256:{raw_hash}",
            "raw_sha256": raw_hash,
            "received_at": received_at,
            "status": status,
            "attestation_id": attestation["attestation_id"] if attestation is not None else None,
            "engagement_id": projected["engagement_id"] if projected is not None else None,
            "engagement_version": projected["engagement_version"] if projected is not None else None,
            "reason_codes": sorted(set(reason_codes or [])),
            "caveats": sorted(set(caveats or [])),
            "observation_refs": sorted(observation_refs or [], key=lambda item: item["capture_id"]),
            "integrity": {
                "canonicalization": RECEIPT_CANONICALIZATION,
                "receipt_sha256": "0" * 64,
            },
        }
        return _validate_receipt(_finalize_receipt(receipt))

    def _accepted_capture_claims(self) -> dict[str, str]:
        claims: dict[str, str] = {}
        for path in sorted(self.receipts_dir.rglob("*.json")):
            receipt = self._load_receipt(path, path.stem)
            if receipt["status"] != "ACCEPT":
                continue
            for reference in receipt["observation_refs"]:
                capture_id = reference["capture_id"]
                observation_hash = reference["observation_hash"]
                prior = claims.get(capture_id)
                if prior is not None and prior != observation_hash:
                    raise PDXEvidenceStoreError("accepted receipt journal contains a capture hash conflict")
                claims[capture_id] = observation_hash
        return claims

    def _engagement_directory(self, engagement_id: str) -> Path:
        digest = hashlib.sha256(engagement_id.encode("utf-8")).hexdigest()
        return self.engagements_dir / digest[:2] / digest

    def _load_engagement(self, engagement_id: str, version: int) -> dict[str, Any] | None:
        directory = self._engagement_directory(engagement_id)
        matches = sorted(directory.glob(f"v{version:010d}-*.json")) if directory.exists() else []
        if not matches:
            return None
        if len(matches) != 1:
            raise PDXEvidenceStoreError("multiple immutable registrations exist for one engagement version")
        engagement = self._load_engagement_path(matches[0])
        if engagement["engagement_id"] != engagement_id or engagement["engagement_version"] != version:
            raise PDXEvidenceStoreError("engagement registration path does not match its content")
        return engagement

    def _load_engagement_path(self, path: Path) -> dict[str, Any]:
        try:
            raw = path.read_bytes()
            engagement = parse_engagement(strict_json_loads(raw))
        except (OSError, StrictJSONError, PDXAttestationError) as exc:
            raise PDXEvidenceStoreError("engagement registration is corrupt") from exc
        digest = hashlib.sha256(_canonical_json_bytes(engagement)).hexdigest()
        if not path.name.endswith(f"-{digest}.json"):
            raise PDXEvidenceStoreError("engagement registration content hash mismatch")
        return engagement

    def _receipt_path(self, raw_hash: str) -> Path:
        return self.receipts_dir / raw_hash[:2] / f"{raw_hash}.json"

    def _write_receipt(self, receipt: Mapping[str, Any]) -> None:
        receipt = _validate_receipt(receipt)
        destination = self._receipt_path(receipt["raw_sha256"])
        self._atomic_write(destination, _canonical_json_bytes(receipt) + b"\n")

    def _load_receipt(self, path: Path, expected_raw_hash: str) -> dict[str, Any]:
        try:
            value = strict_json_loads(path.read_bytes())
            receipt = _validate_receipt(value)
        except (OSError, StrictJSONError, PDXEvidenceStoreError, PDXAttestationError) as exc:
            raise PDXEvidenceStoreError("persisted attestation receipt is corrupt") from exc
        if receipt["raw_sha256"] != expected_raw_hash:
            raise PDXEvidenceStoreError("receipt path does not match raw_sha256")
        return receipt

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
        finally:
            temporary.unlink(missing_ok=True)

    def _cleanup_temporary_files(self) -> None:
        for directory in (self.engagements_dir, self.receipts_dir):
            for path in directory.rglob(".*.tmp-*"):
                try:
                    if path.is_file():
                        path.unlink()
                except OSError:
                    continue

    @contextmanager
    def _exclusive(self):
        """Serialize journal decisions across threads and local processes."""

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


__all__ = [
    "AttestationImportResult",
    "PDXEvidenceStore",
    "PDXEvidenceStoreError",
    "RECEIPT_SCHEMA_VERSION",
]
