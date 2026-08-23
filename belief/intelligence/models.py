"""Immutable context-only records for external security intelligence.

These types deliberately have no conversion path to ``Finding`` or
``AuditCase``. External records can inform a human review, but they are never
proof and are never eligible for automatic promotion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from belief.json_contracts import StrictJSONError, strict_json_loads

from .canonical import canonical_json, normalize_retrieval_timestamp, require_https_url


INTELLIGENCE_SCHEMA_VERSION = "belief.external_intelligence.v1"
CONTEXT_ONLY_CLASSIFICATION = "context_only"

ParserStatus = Literal["parsed", "parsed_empty"]
FreshnessState = Literal[
    "unknown",
    "not_evaluated",
    "fresh",
    "stale",
    "source_in_future",
]
LicenseStatus = Literal["declared", "provider_documented", "unknown"]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class LicenseMetadata:
    """License provenance, including an explicit unknown state."""

    identifier: str
    status: LicenseStatus
    terms_url: str | None = None
    attribution: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.identifier, str) or not self.identifier.strip():
            raise ValueError("license identifier must be non-empty")
        if self.status not in {"declared", "provider_documented", "unknown"}:
            raise ValueError("invalid license status")
        if self.terms_url is not None:
            require_https_url(self.terms_url, field="license terms_url")
        if self.attribution is not None and not self.attribution.strip():
            raise ValueError("license attribution must be non-empty when present")

    @classmethod
    def unknown(cls) -> "LicenseMetadata":
        return cls(identifier="unknown", status="unknown")

    def to_dict(self) -> dict[str, str | None]:
        return {
            "identifier": self.identifier,
            "status": self.status,
            "terms_url": self.terms_url,
            "attribution": self.attribution,
        }


@dataclass(frozen=True, slots=True)
class FreshnessMetadata:
    """Observed source time plus an optional, explicit caller freshness policy."""

    state: FreshnessState
    basis: str | None
    source_published_at: str | None
    source_modified_at: str | None
    age_seconds: int | None
    max_age_seconds: int | None

    def __post_init__(self) -> None:
        if self.state not in {
            "unknown",
            "not_evaluated",
            "fresh",
            "stale",
            "source_in_future",
        }:
            raise ValueError("invalid freshness state")
        if self.basis not in {None, "source_published_at", "source_modified_at"}:
            raise ValueError("invalid freshness basis")
        if self.max_age_seconds is not None and self.max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative")
        if self.age_seconds is not None and not isinstance(self.age_seconds, int):
            raise ValueError("age_seconds must be an integer when present")

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "basis": self.basis,
            "source_published_at": self.source_published_at,
            "source_modified_at": self.source_modified_at,
            "age_seconds": self.age_seconds,
            "max_age_seconds": self.max_age_seconds,
        }


@dataclass(frozen=True, slots=True)
class ExternalIntelligenceRecord:
    """One immutable, non-proof provider occurrence.

    ``occurrence_index`` is intentionally retained so duplicate provider rows
    remain separate. The canonical payload is stored as an immutable string;
    ``payload()`` returns a detached copy for inspection.
    """

    provider: str
    source_url: str
    record_id: str
    normalized_query_sha256: str
    retrieved_at_utc: str
    source_revision: str | None
    raw_response_sha256: str
    freshness: FreshnessMetadata
    license: LicenseMetadata
    parser_status: Literal["parsed"]
    parser_version: str
    occurrence_index: int
    identifiers: tuple[str, ...]
    summary: str
    canonical_payload_json: str
    schema_version: str = field(default=INTELLIGENCE_SCHEMA_VERSION, init=False)
    classification: Literal["context_only"] = field(
        default=CONTEXT_ONLY_CLASSIFICATION,
        init=False,
    )
    proof_eligible: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        _non_empty(self.provider, "provider")
        require_https_url(self.source_url)
        _non_empty(self.record_id, "record_id")
        _sha256(self.normalized_query_sha256, "normalized_query_sha256")
        normalized_time = normalize_retrieval_timestamp(self.retrieved_at_utc)
        if normalized_time != self.retrieved_at_utc:
            raise ValueError("retrieved_at_utc must use canonical UTC form")
        if self.source_revision is not None:
            _non_empty(self.source_revision, "source_revision")
        _sha256(self.raw_response_sha256, "raw_response_sha256")
        if self.parser_status != "parsed":
            raise ValueError("record parser_status must be parsed")
        _non_empty(self.parser_version, "parser_version")
        if self.occurrence_index < 0:
            raise ValueError("occurrence_index must be non-negative")
        if not isinstance(self.identifiers, tuple):
            raise TypeError("identifiers must be an immutable tuple")
        for identifier in self.identifiers:
            _non_empty(identifier, "identifier")
        if not isinstance(self.summary, str):
            raise TypeError("summary must be a string")
        try:
            payload = strict_json_loads(self.canonical_payload_json)
        except (StrictJSONError, TypeError) as exc:
            raise ValueError(f"canonical_payload_json is invalid: {exc}") from exc
        if canonical_json(payload) != self.canonical_payload_json:
            raise ValueError("canonical_payload_json is not canonical")

    def payload(self) -> Any:
        """Return a detached JSON value; mutation cannot alter this record."""

        return strict_json_loads(self.canonical_payload_json)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "proof_eligible": self.proof_eligible,
            "provider": self.provider,
            "source_url": self.source_url,
            "record_id": self.record_id,
            "normalized_query_sha256": self.normalized_query_sha256,
            "retrieved_at_utc": self.retrieved_at_utc,
            "source_revision": self.source_revision,
            "raw_response_sha256": self.raw_response_sha256,
            "freshness": self.freshness.to_dict(),
            "license": self.license.to_dict(),
            "parser_status": self.parser_status,
            "parser_version": self.parser_version,
            "occurrence_index": self.occurrence_index,
            "identifiers": list(self.identifiers),
            "summary": self.summary,
            "payload": self.payload(),
        }


@dataclass(frozen=True, slots=True)
class ExternalIntelligenceBatch:
    """Immutable result of parsing one exact provider response."""

    provider: str
    source_url: str
    normalized_query_sha256: str
    retrieved_at_utc: str
    source_revision: str | None
    raw_response_sha256: str
    license: LicenseMetadata
    parser_status: ParserStatus
    parser_version: str
    records: tuple[ExternalIntelligenceRecord, ...]
    schema_version: str = field(default=INTELLIGENCE_SCHEMA_VERSION, init=False)
    classification: Literal["context_only"] = field(
        default=CONTEXT_ONLY_CLASSIFICATION,
        init=False,
    )
    proof_eligible: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        _non_empty(self.provider, "provider")
        require_https_url(self.source_url)
        _sha256(self.normalized_query_sha256, "normalized_query_sha256")
        if normalize_retrieval_timestamp(self.retrieved_at_utc) != self.retrieved_at_utc:
            raise ValueError("retrieved_at_utc must use canonical UTC form")
        if self.source_revision is not None:
            _non_empty(self.source_revision, "source_revision")
        _sha256(self.raw_response_sha256, "raw_response_sha256")
        _non_empty(self.parser_version, "parser_version")
        if not isinstance(self.records, tuple):
            raise TypeError("records must be an immutable tuple")
        expected_status = "parsed" if self.records else "parsed_empty"
        if self.parser_status != expected_status:
            raise ValueError(f"parser_status must be {expected_status}")
        for index, record in enumerate(self.records):
            if record.occurrence_index != index:
                raise ValueError("record occurrence indexes must remain contiguous and ordered")
            for field_name in (
                "provider",
                "source_url",
                "normalized_query_sha256",
                "retrieved_at_utc",
                "raw_response_sha256",
                "parser_version",
            ):
                if getattr(record, field_name) != getattr(self, field_name):
                    raise ValueError(f"record {field_name} does not match its batch")
            if record.license != self.license:
                raise ValueError("record license does not match its batch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "proof_eligible": self.proof_eligible,
            "provider": self.provider,
            "source_url": self.source_url,
            "normalized_query_sha256": self.normalized_query_sha256,
            "retrieved_at_utc": self.retrieved_at_utc,
            "source_revision": self.source_revision,
            "raw_response_sha256": self.raw_response_sha256,
            "license": self.license.to_dict(),
            "parser_status": self.parser_status,
            "parser_version": self.parser_version,
            "records": [record.to_dict() for record in self.records],
        }


def concatenate_context_records(
    *batches: ExternalIntelligenceBatch,
) -> tuple[ExternalIntelligenceRecord, ...]:
    """Concatenate occurrences without identity merging, scoring, or promotion."""

    return tuple(record for batch in batches for record in batch.records)


def _non_empty(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")


def _sha256(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")


__all__ = [
    "CONTEXT_ONLY_CLASSIFICATION",
    "INTELLIGENCE_SCHEMA_VERSION",
    "ExternalIntelligenceBatch",
    "ExternalIntelligenceRecord",
    "FreshnessMetadata",
    "FreshnessState",
    "LicenseMetadata",
    "LicenseStatus",
    "ParserStatus",
    "concatenate_context_records",
]
