"""Deterministic in-toto statements for BELIEF validation decisions.

This module emits an in-toto Statement v1 using the vetted Simple
Verification Result (SVR) v0.2 predicate.  BELIEF-specific result, tool,
proof, and evidence bindings live in a monotonic predicate extension: a
generic SVR consumer can ignore them without changing the meaning of the
standard fields.

The returned statement is deliberately *not authenticated*.  DSSE signs the
exact serialized statement bytes together with their payload type; key
selection, signing, certificate identity, and signature verification belong
to an external provenance boundary.  ``prepare_dsse_payload`` only prepares
those two inputs and never creates a signature or an incomplete envelope.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

from belief.json_contracts import StrictJSONError, strict_json_clone, strict_json_dumps
from belief.validation.models import ValidationResult
from belief.validation.proof import (
    VALIDATION_PROOF_STATES,
    ValidationEvidenceRef,
    ValidationProof,
)


IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SIMPLE_VERIFICATION_RESULT_TYPE = "https://in-toto.io/attestation/svr/v0.2"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
BELIEF_VALIDATION_EXTENSION = "beliefValidation"
BELIEF_VALIDATION_EXTENSION_SCHEMA = "belief.in_toto_svr_extension.v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_URI_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*$")
_URI_CHARACTERS_RE = re.compile(r"^[A-Za-z0-9:/?#\[\]@!$&'()*+,;=._~%-]+$")


class InTotoExportError(ValueError):
    """Raised when a BELIEF result cannot form an unambiguous statement."""


@dataclass(frozen=True)
class PolicyReference:
    """One immutable policy resource used by the verifier."""

    uri: str
    sha256: str
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "uri", _uri(self.uri, field_name="policy uri"))
        object.__setattr__(
            self,
            "sha256",
            _sha256(self.sha256, field_name="policy sha256"),
        )
        if not isinstance(self.name, str):
            raise InTotoExportError("policy name must be a string")
        if self.name:
            object.__setattr__(
                self,
                "name",
                _identifier(self.name, field_name="policy name"),
            )

    def to_resource_descriptor(self) -> dict[str, Any]:
        descriptor: dict[str, Any] = {
            "uri": self.uri,
            "digest": {"sha256": self.sha256},
        }
        if self.name:
            descriptor["name"] = self.name
        return descriptor


@dataclass(frozen=True)
class DSSEPayload:
    """Exact bytes and media type to give to a caller-managed DSSE signer."""

    payload_type: str
    payload: bytes


def build_validation_svr_statement(
    result: ValidationResult,
    *,
    proof: ValidationProof | None,
    proof_state: str,
    subject_name: str,
    subject_sha256: str,
    verifier_id: str,
    tool_id: str,
    policies: Sequence[PolicyReference],
    time_created: datetime,
) -> dict[str, Any]:
    """Build a deterministic, unsigned in-toto SVR statement.

    ``proof_state`` is a BELIEF semantic assessment.  This function validates
    its consistency with the typed result/proof but does not establish ledger
    provenance or authenticate the resulting statement.  A caller asserting
    ``verified`` must have obtained that state from BELIEF's trusted proof
    authority before calling this exporter.

    Standard SVR properties describe verified assertions, so unverified states
    leave that array empty and preserve their claims only in the extension.
    ``time_created`` must be the verification time, not the export time.
    """

    if type(result) is not ValidationResult:
        raise TypeError("result must be a ValidationResult")
    if proof is not None and type(proof) is not ValidationProof:
        raise TypeError("proof must be a ValidationProof or None")

    state = _proof_state(proof_state)
    _validate_proof_presence(state, proof)
    _validate_result(result)
    if proof is not None:
        _validate_result_proof_binding(result, proof)

    normalized_policies = _policies(policies)
    artifact_name = _identifier(subject_name, field_name="subject name")
    artifact_sha256 = _sha256(subject_sha256, field_name="subject sha256")
    verifier_uri = _uri(verifier_id, field_name="verifier id")
    tool_uri = _uri(tool_id, field_name="tool id")

    properties = sorted(
        {
            f"BELIEF_PROOF_STATE_{state.upper()}",
            f"BELIEF_VALIDATION_OUTCOME_{result.outcome.upper()}",
        }
    ) if state == "verified" else []
    extension = {
        "schemaVersion": BELIEF_VALIDATION_EXTENSION_SCHEMA,
        "tool": {
            "uri": tool_uri,
            "name": result.source,
        },
        "result": _result_binding(result),
        "proof": _proof_binding(state, proof),
    }

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": artifact_name,
                "digest": {"sha256": artifact_sha256},
            }
        ],
        "predicateType": SIMPLE_VERIFICATION_RESULT_TYPE,
        "predicate": {
            "verifier": {
                "id": verifier_uri,
                "policies": [item.to_resource_descriptor() for item in normalized_policies],
            },
            "timeCreated": _timestamp(time_created),
            "properties": properties,
            BELIEF_VALIDATION_EXTENSION: extension,
        },
    }


def serialize_in_toto_statement(statement: Mapping[str, Any]) -> bytes:
    """Serialize one statement deterministically as strict UTF-8 JSON.

    Deterministic JSON is an interoperability property here, not an
    authentication mechanism.  A DSSE implementation must sign these exact
    bytes and its payload type according to DSSE's pre-authentication encoding.
    """

    if not isinstance(statement, Mapping):
        raise TypeError("statement must be a mapping")
    try:
        detached = strict_json_clone(dict(statement))
        return strict_json_dumps(
            detached,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except StrictJSONError as exc:
        raise InTotoExportError(f"statement is not finite JSON: {exc}") from exc


def prepare_dsse_payload(statement: Mapping[str, Any]) -> DSSEPayload:
    """Return DSSE signing inputs without producing a signature or envelope."""

    return DSSEPayload(
        payload_type=DSSE_PAYLOAD_TYPE,
        payload=serialize_in_toto_statement(statement),
    )


def _validate_result(result: ValidationResult) -> None:
    for field_name in ("result_id", "subject_id", "subject_kind", "source"):
        _identifier(getattr(result, field_name), field_name=field_name)
    if result.method:
        _identifier(result.method, field_name="result method")


def _validate_result_proof_binding(
    result: ValidationResult,
    proof: ValidationProof,
) -> None:
    mismatches = [
        field_name
        for field_name in ("result_id", "subject_id", "subject_kind", "outcome")
        if getattr(result, field_name) != getattr(proof, field_name)
    ]
    if mismatches:
        raise InTotoExportError(
            "validation result/proof binding mismatch: " + ", ".join(mismatches)
        )


def _validate_proof_presence(state: str, proof: ValidationProof | None) -> None:
    if state == "signal_only" and proof is not None:
        raise InTotoExportError("signal_only result cannot carry a validation proof")
    if state != "signal_only" and proof is None:
        raise InTotoExportError(f"{state} proof state requires a validation proof")


def _result_binding(result: ValidationResult) -> dict[str, Any]:
    binding: dict[str, Any] = {
        "resultId": result.result_id,
        "subjectId": result.subject_id,
        "subjectKind": result.subject_kind,
        "source": result.source,
        "outcome": result.outcome,
    }
    if result.method:
        binding["method"] = result.method
    return binding


def _proof_binding(
    state: str,
    proof: ValidationProof | None,
) -> dict[str, Any]:
    if proof is None:
        return {"state": state, "evidence": []}
    return {
        "state": state,
        "proofId": proof.proof_id,
        "engagementId": proof.engagement_id,
        "targetId": proof.target_id,
        "planId": proof.plan_id,
        "attemptId": proof.attempt_id,
        "oracle": {
            "id": proof.oracle_id,
            "version": proof.oracle_version,
        },
        "evidence": [_evidence_descriptor(item) for item in proof.evidence_refs],
    }


def _evidence_descriptor(reference: ValidationEvidenceRef) -> dict[str, Any]:
    return {
        "name": reference.evidence_id,
        "digest": {"sha256": reference.sha256},
        "mediaType": reference.media_type,
        "annotations": {"beliefEvidenceKind": reference.kind},
    }


def _policies(values: Sequence[PolicyReference]) -> tuple[PolicyReference, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise TypeError("policies must be a sequence of PolicyReference values")
    policies = tuple(values)
    if any(type(item) is not PolicyReference for item in policies):
        raise TypeError("policies must contain only PolicyReference values")
    uris = [item.uri for item in policies]
    if len(uris) != len(set(uris)):
        raise InTotoExportError("verifier policies contain duplicate URIs")
    return tuple(sorted(policies, key=lambda item: (item.uri, item.sha256, item.name)))


def _proof_state(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("proof_state must be a string")
    state = value.strip().lower()
    if state not in VALIDATION_PROOF_STATES:
        raise InTotoExportError(f"unsupported proof state: {state!r}")
    return state


def _timestamp(value: datetime) -> str:
    if not isinstance(value, datetime):
        raise TypeError("time_created must be a datetime")
    if value.tzinfo is None or value.utcoffset() is None:
        raise InTotoExportError("time_created must be timezone-aware")
    try:
        normalized = value.astimezone(timezone.utc)
    except (OverflowError, ValueError) as exc:
        raise InTotoExportError("time_created is outside the supported UTC range") from exc
    rendered = (
        f"{normalized.year:04d}-{normalized.month:02d}-{normalized.day:02d}"
        f"T{normalized.hour:02d}:{normalized.minute:02d}:{normalized.second:02d}"
    )
    if normalized.microsecond:
        rendered += "." + f"{normalized.microsecond:06d}".rstrip("0")
    return rendered + "Z"


def _identifier(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str):
        raise InTotoExportError(f"{field_name} must be a string")
    text = value.strip()
    if (
        not text
        or text != value
        or len(text) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise InTotoExportError(f"{field_name} is invalid")
    return text


def _sha256(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise InTotoExportError(f"{field_name} must be lowercase SHA-256")
    return value


def _uri(value: Any, *, field_name: str) -> str:
    text = _identifier(value, field_name=field_name)
    invalid_percent_escape = re.search(r"%(?![0-9A-Fa-f]{2})", text)
    if (
        not _URI_CHARACTERS_RE.fullmatch(text)
        or invalid_percent_escape
    ):
        raise InTotoExportError(f"{field_name} must be an absolute URI")
    try:
        parts = urlsplit(text)
        # Accessing port forces urllib to reject malformed bracket/port syntax.
        _ = parts.port
    except ValueError as exc:
        raise InTotoExportError(f"{field_name} must be an absolute URI") from exc
    if (
        not parts.scheme
        or not _URI_SCHEME_RE.fullmatch(text.partition(":")[0])
        or not (parts.netloc or parts.path)
        or (parts.netloc and parts.netloc != parts.netloc.lower())
        or (parts.scheme in {"http", "https"} and not parts.hostname)
    ):
        raise InTotoExportError(
            f"{field_name} must be an absolute, case-normalized URI"
        )
    return text


__all__ = [
    "BELIEF_VALIDATION_EXTENSION",
    "BELIEF_VALIDATION_EXTENSION_SCHEMA",
    "DSSE_PAYLOAD_TYPE",
    "DSSEPayload",
    "IN_TOTO_STATEMENT_TYPE",
    "InTotoExportError",
    "PolicyReference",
    "SIMPLE_VERIFICATION_RESULT_TYPE",
    "build_validation_svr_statement",
    "prepare_dsse_payload",
    "serialize_in_toto_statement",
]
