"""Strict trust-boundary models for PDX observation attestations.

These objects are passive signals.  They contain no BELIEF attempt, result, or
evidence and therefore cannot establish that a vulnerability was tested.
"""

from __future__ import annotations

import copy
import hashlib
import re
from datetime import datetime
from typing import Any, Mapping

from belief.json_contracts import strict_json_clone, strict_json_dumps

ATTESTATION_SCHEMA_VERSION = "pdx.observation_attestation.v1"
ATTESTATION_CANONICALIZATION = "pdx-observation-attestation-json-v1"
ENGAGEMENT_SCHEMA_VERSION = "belief.pdx_engagement.v1"
MAX_OBSERVATIONS = 64

OPAQUE_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,511}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
CAPTURE_ID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
TARGET_ID_RE = re.compile(r"^pdx:target:sha256:[0-9a-f]{64}$")
ENDPOINT_ID_RE = re.compile(r"^pdx:endpoint:sha256:[0-9a-f]{64}$")
CONTEXT_ID_RE = re.compile(r"^pdx:context:sha256:[0-9a-f]{64}$")
ATTESTATION_ID_RE = re.compile(r"^pdx:observation-attestation:sha256:[0-9a-f]{64}$")

SUPPLIED_IDENTITY_NAMES = (
    "engagement",
    "session",
    "actor",
    "role",
    "tenant",
    "workflow",
    "workflow_step",
)


class PDXAttestationError(ValueError):
    """Raised when an attestation or engagement document is not exact."""


def _object(value: Any, path: str, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PDXAttestationError(f"{path} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise PDXAttestationError(f"{path} keys are not exact (missing={missing}, extra={extra})")
    return value


def _string(value: Any, path: str, *, pattern: re.Pattern[str] | None = None, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise PDXAttestationError(f"{path} must be a non-empty bounded string")
    if pattern is not None and not pattern.fullmatch(value):
        raise PDXAttestationError(f"{path} has an invalid format")
    return value


def _positive_int(value: Any, path: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise PDXAttestationError(f"{path} must be a positive integer")
    return value


def parse_datetime(value: Any, path: str) -> datetime:
    text = _string(value, path, maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PDXAttestationError(f"{path} must be an ISO-8601 date-time") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PDXAttestationError(f"{path} must include an explicit UTC offset")
    return parsed


def canonical_attestation_bytes(value: Mapping[str, Any]) -> bytes:
    document = copy.deepcopy(dict(value))
    try:
        document["attestation_id"] = None
        document["integrity"]["attestation_sha256"] = None
    except (KeyError, TypeError) as exc:
        raise PDXAttestationError("attestation integrity fields are missing") from exc
    # This is a cross-repository canonicalization contract.  PDX hashes the
    # literal UTF-8 representation (ensure_ascii=False), so BELIEF must use the
    # same bytes for non-ASCII but schema-valid producer metadata.
    return strict_json_dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def attestation_sha256(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_attestation_bytes(value)).hexdigest()


def parse_engagement(value: Any) -> dict[str, Any]:
    document = strict_json_clone(value)
    document = _object(
        document,
        "engagement",
        {
            "schema_version",
            "engagement_id",
            "engagement_version",
            "status",
            "owner_ref",
            "scope_ref",
            "scope_sha256",
            "authorization_ref",
            "policy_ref",
            "budget_ref",
            "valid_from",
            "valid_until",
            "target_ids",
        },
    )
    if document["schema_version"] != ENGAGEMENT_SCHEMA_VERSION:
        raise PDXAttestationError("unsupported engagement schema_version")
    _string(document["engagement_id"], "engagement.engagement_id", pattern=OPAQUE_REF_RE)
    _positive_int(document["engagement_version"], "engagement.engagement_version")
    if document["status"] not in {"active", "suspended", "closed"}:
        raise PDXAttestationError("engagement.status is not supported")
    for name in ("owner_ref", "scope_ref", "authorization_ref", "policy_ref", "budget_ref"):
        _string(document[name], f"engagement.{name}", pattern=OPAQUE_REF_RE)
    _string(document["scope_sha256"], "engagement.scope_sha256", pattern=SHA256_RE, maximum=64)
    valid_from = parse_datetime(document["valid_from"], "engagement.valid_from")
    valid_until = parse_datetime(document["valid_until"], "engagement.valid_until")
    if valid_from >= valid_until:
        raise PDXAttestationError("engagement validity interval must be non-empty")
    targets = document["target_ids"]
    if not isinstance(targets, list) or not targets or len(targets) > 4096:
        raise PDXAttestationError("engagement.target_ids must contain 1..4096 target ids")
    for index, target in enumerate(targets):
        _string(target, f"engagement.target_ids[{index}]", pattern=TARGET_ID_RE, maximum=82)
    if targets != sorted(set(targets)):
        raise PDXAttestationError("engagement.target_ids must be unique and lexically sorted")
    return document


def _parse_projection_engagement(value: Any) -> dict[str, Any]:
    document = _object(
        value,
        "attestation.engagement",
        {"engagement_id", "engagement_version", "scope_ref", "scope_sha256", "authorization_ref"},
    )
    _string(document["engagement_id"], "attestation.engagement.engagement_id", pattern=OPAQUE_REF_RE)
    _positive_int(document["engagement_version"], "attestation.engagement.engagement_version")
    _string(document["scope_ref"], "attestation.engagement.scope_ref", pattern=OPAQUE_REF_RE)
    _string(document["scope_sha256"], "attestation.engagement.scope_sha256", pattern=SHA256_RE, maximum=64)
    _string(document["authorization_ref"], "attestation.engagement.authorization_ref", pattern=OPAQUE_REF_RE)
    return document


def _parse_observation(value: Any, index: int, engagement_id: str) -> dict[str, Any]:
    path = f"attestation.observations[{index}]"
    document = _object(
        value,
        path,
        {
            "capture_id",
            "observed_at",
            "observation_hash",
            "request_sha256",
            "response_sha256",
            "contract_state",
            "truncated_any",
            "payload_integrity",
            "identity",
        },
    )
    _string(document["capture_id"], f"{path}.capture_id", pattern=CAPTURE_ID_RE, maximum=36)
    parse_datetime(document["observed_at"], f"{path}.observed_at")
    for name in ("observation_hash", "request_sha256", "response_sha256"):
        _string(document[name], f"{path}.{name}", pattern=SHA256_RE, maximum=64)
    if document["contract_state"] != "accepted":
        raise PDXAttestationError(f"{path}.contract_state must be accepted")
    if not isinstance(document["truncated_any"], bool):
        raise PDXAttestationError(f"{path}.truncated_any must be boolean")

    payload_integrity = _object(
        document["payload_integrity"],
        f"{path}.payload_integrity",
        {"request_raw", "request_body", "response_raw", "response_body"},
    )
    for name, state in payload_integrity.items():
        if state not in {"verified", "producer_declared"}:
            raise PDXAttestationError(f"{path}.payload_integrity.{name} is invalid")
    if not document["truncated_any"] and any(state != "verified" for state in payload_integrity.values()):
        raise PDXAttestationError(f"{path} complete payloads must all have verified full hashes")

    identity = _object(
        document["identity"],
        f"{path}.identity",
        {
            "identity_state",
            "engagement_id",
            "target_id",
            "endpoint_id",
            "correlation_state",
            "correlation_key",
            "missing",
        },
    )
    if identity["identity_state"] not in {"partial", "complete"}:
        raise PDXAttestationError(f"{path}.identity.identity_state is invalid")
    _string(identity["engagement_id"], f"{path}.identity.engagement_id", pattern=OPAQUE_REF_RE)
    if identity["engagement_id"] != engagement_id:
        raise PDXAttestationError(f"{path}.identity engagement does not match the attestation")
    _string(identity["target_id"], f"{path}.identity.target_id", pattern=TARGET_ID_RE, maximum=82)
    _string(identity["endpoint_id"], f"{path}.identity.endpoint_id", pattern=ENDPOINT_ID_RE, maximum=84)
    missing = identity["missing"]
    if not isinstance(missing, list) or any(item not in SUPPLIED_IDENTITY_NAMES for item in missing):
        raise PDXAttestationError(f"{path}.identity.missing is invalid")
    if missing != sorted(set(missing), key=SUPPLIED_IDENTITY_NAMES.index):
        raise PDXAttestationError(f"{path}.identity.missing is not unique and canonical")
    if identity["correlation_state"] == "joinable":
        _string(identity["correlation_key"], f"{path}.identity.correlation_key", pattern=CONTEXT_ID_RE, maximum=83)
        if identity["identity_state"] != "complete" or missing:
            raise PDXAttestationError(f"{path}.identity joinable state is inconsistent")
    elif identity["correlation_state"] == "non_joinable":
        if identity["correlation_key"] is not None or identity["identity_state"] != "partial" or not missing:
            raise PDXAttestationError(f"{path}.identity non_joinable state is inconsistent")
    else:
        raise PDXAttestationError(f"{path}.identity.correlation_state is invalid")
    return document


def parse_attestation(value: Any) -> dict[str, Any]:
    document = strict_json_clone(value)
    document = _object(
        document,
        "attestation",
        {
            "schema_version",
            "attestation_id",
            "created_at",
            "engagement",
            "producer",
            "observations",
            "loss_manifest",
            "integrity",
        },
    )
    if document["schema_version"] != ATTESTATION_SCHEMA_VERSION:
        raise PDXAttestationError("unsupported attestation schema_version")
    _string(document["attestation_id"], "attestation.attestation_id", pattern=ATTESTATION_ID_RE, maximum=99)
    parse_datetime(document["created_at"], "attestation.created_at")
    engagement = _parse_projection_engagement(document["engagement"])

    producer = _object(
        document["producer"],
        "attestation.producer",
        {"tool_id", "exporter_version", "observation_contract", "observation_canonicalization"},
    )
    if producer["tool_id"] != "pdx":
        raise PDXAttestationError("attestation.producer.tool_id must be pdx")
    _string(producer["exporter_version"], "attestation.producer.exporter_version", maximum=128)
    if producer["observation_contract"] != "pdx.http_observation.v2":
        raise PDXAttestationError("unsupported source observation contract")
    if producer["observation_canonicalization"] != "pdx-json-digest-v1":
        raise PDXAttestationError("unsupported source observation canonicalization")

    observations = document["observations"]
    if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_OBSERVATIONS:
        raise PDXAttestationError("attestation.observations must contain 1..64 entries")
    for index, observation in enumerate(observations):
        _parse_observation(observation, index, engagement["engagement_id"])
    capture_ids = [item["capture_id"] for item in observations]
    if capture_ids != sorted(set(capture_ids)):
        raise PDXAttestationError("attestation observations must be unique and lexically sorted")

    loss = _object(
        document["loss_manifest"],
        "attestation.loss_manifest",
        {"projection", "omitted", "cas_exposed", "source_truncated_capture_ids", "projected_fields_lossless"},
    )
    if loss["projection"] != "metadata-and-digests-only":
        raise PDXAttestationError("unsupported attestation projection")
    expected_omitted = ["request_bytes", "response_bytes", "headers", "timing", "pdx_cas_references"]
    if loss["omitted"] != expected_omitted or loss["cas_exposed"] is not False:
        raise PDXAttestationError("attestation loss manifest does not exclude bytes and CAS")
    if loss["projected_fields_lossless"] is not True:
        raise PDXAttestationError("attestation projected fields must be lossless")
    expected_truncated = [item["capture_id"] for item in observations if item["truncated_any"]]
    if loss["source_truncated_capture_ids"] != expected_truncated:
        raise PDXAttestationError("attestation loss manifest truncation list is inconsistent")

    integrity = _object(
        document["integrity"],
        "attestation.integrity",
        {"canonicalization", "attestation_sha256"},
    )
    if integrity["canonicalization"] != ATTESTATION_CANONICALIZATION:
        raise PDXAttestationError("unsupported attestation canonicalization")
    _string(integrity["attestation_sha256"], "attestation.integrity.attestation_sha256", pattern=SHA256_RE, maximum=64)
    digest = attestation_sha256(document)
    if integrity["attestation_sha256"] != digest:
        raise PDXAttestationError("attestation canonical digest mismatch")
    if document["attestation_id"] != f"pdx:observation-attestation:sha256:{digest}":
        raise PDXAttestationError("attestation_id does not match canonical digest")
    return document


__all__ = [
    "ATTESTATION_SCHEMA_VERSION",
    "ENGAGEMENT_SCHEMA_VERSION",
    "PDXAttestationError",
    "attestation_sha256",
    "canonical_attestation_bytes",
    "parse_attestation",
    "parse_datetime",
    "parse_engagement",
]
