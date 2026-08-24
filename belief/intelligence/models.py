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

from .canonical import (
    canonical_json,
    canonical_json_sha256,
    normalize_retrieval_timestamp,
    require_https_url,
)


INTELLIGENCE_SCHEMA_VERSION = "belief.external_intelligence.v1"
INTELLIGENCE_PAGE_SCHEMA_VERSION = "belief.external_intelligence_page.v1"
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
PaginationMode = Literal["none", "offset", "cursor"]

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PAGE_HEADER_NAMES = frozenset(
    {
        "content-type",
        "date",
        "deprecation",
        "etag",
        "last-modified",
        "link",
        "retry-after",
        "sunset",
        "x-github-api-version-selected",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
        "x-ratelimit-used",
    }
)


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


@dataclass(frozen=True, slots=True)
class PaginationMetadata:
    """Provider page state without claiming snapshot isolation."""

    mode: PaginationMode
    request_position: int | str | None
    next_position: int | str | None
    page_size: int
    provider_total: int | None
    page_complete: bool
    collection_complete: bool

    def __post_init__(self) -> None:
        if self.mode not in {"none", "offset", "cursor"}:
            raise ValueError("invalid pagination mode")
        _non_negative_int(self.page_size, "page_size")
        if self.provider_total is not None:
            _non_negative_int(self.provider_total, "provider_total")
        if not isinstance(self.page_complete, bool):
            raise TypeError("page_complete must be a boolean")
        if not isinstance(self.collection_complete, bool):
            raise TypeError("collection_complete must be a boolean")
        if not self.page_complete:
            raise ValueError("parsed page envelopes must contain one complete page")
        if self.collection_complete and self.next_position is not None:
            raise ValueError("complete collections must not expose a next position")
        if not self.collection_complete and self.next_position is None:
            raise ValueError("incomplete collections require a next position")

        if self.mode == "none":
            if self.request_position is not None or self.next_position is not None:
                raise ValueError("non-paginated sources must not expose positions")
            if self.provider_total is not None:
                raise ValueError("non-paginated sources must not expose a provider total")
            if not self.collection_complete:
                raise ValueError("non-paginated pages must be collection-complete")
        elif self.mode == "offset":
            _non_negative_int(self.request_position, "request_position")
            if self.next_position is not None:
                _non_negative_int(self.next_position, "next_position")
            if self.provider_total is None:
                raise ValueError("offset pagination requires provider_total")
        else:
            _optional_position_string(self.request_position, "request_position")
            _optional_position_string(self.next_position, "next_position")
            if self.provider_total is not None:
                raise ValueError("cursor pagination must not invent a provider total")

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "request_position": self.request_position,
            "next_position": self.next_position,
            "page_size": self.page_size,
            "provider_total": self.provider_total,
            "page_complete": self.page_complete,
            "collection_complete": self.collection_complete,
        }


@dataclass(frozen=True, slots=True)
class RateLimitMetadata:
    """Documented policy plus response-observed quota state."""

    policy_limit: int | None
    policy_window_seconds: int | None
    observed_limit: int | None
    remaining: int | None
    used: int | None
    reset_epoch_seconds: int | None
    retry_after_seconds: int | None
    resource: str | None

    def __post_init__(self) -> None:
        if (self.policy_limit is None) != (self.policy_window_seconds is None):
            raise ValueError("rate-limit policy limit and window must be present together")
        for field_name in (
            "policy_limit",
            "policy_window_seconds",
            "observed_limit",
            "remaining",
            "used",
            "reset_epoch_seconds",
            "retry_after_seconds",
        ):
            value = getattr(self, field_name)
            if value is not None:
                _non_negative_int(value, field_name)
        if (
            self.observed_limit is not None
            and self.remaining is not None
            and self.remaining > self.observed_limit
        ):
            raise ValueError("remaining quota must not exceed the observed limit")
        if self.resource is not None:
            _non_empty(self.resource, "rate-limit resource")

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_limit": self.policy_limit,
            "policy_window_seconds": self.policy_window_seconds,
            "observed_limit": self.observed_limit,
            "remaining": self.remaining,
            "used": self.used,
            "reset_epoch_seconds": self.reset_epoch_seconds,
            "retry_after_seconds": self.retry_after_seconds,
            "resource": self.resource,
        }


@dataclass(frozen=True, slots=True)
class ExternalIntelligencePage:
    """One immutable provider page plus safe transport provenance."""

    provider: str
    endpoint_url: str
    request_url: str
    api_contract_version: str
    collection_query_sha256: str
    request_query_sha256: str
    selected_response_headers: tuple[tuple[str, str], ...]
    selected_response_headers_sha256: str
    response_generated_at_utc: str | None
    pagination: PaginationMetadata
    rate_limit: RateLimitMetadata
    batch: ExternalIntelligenceBatch
    schema_version: str = field(default=INTELLIGENCE_PAGE_SCHEMA_VERSION, init=False)
    classification: Literal["context_only"] = field(
        default=CONTEXT_ONLY_CLASSIFICATION,
        init=False,
    )
    proof_eligible: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        _non_empty(self.provider, "provider")
        require_https_url(self.endpoint_url, field="endpoint_url")
        require_https_url(self.request_url, field="request_url")
        _non_empty(self.api_contract_version, "api_contract_version")
        _sha256(self.collection_query_sha256, "collection_query_sha256")
        _sha256(self.request_query_sha256, "request_query_sha256")
        _sha256(
            self.selected_response_headers_sha256,
            "selected_response_headers_sha256",
        )
        if not isinstance(self.selected_response_headers, tuple):
            raise TypeError("selected_response_headers must be an immutable tuple")
        previous_name: str | None = None
        for name, value in self.selected_response_headers:
            if not isinstance(name, str) or name != name.lower() or not name:
                raise ValueError("selected response header names must be lowercase")
            if name not in _SAFE_PAGE_HEADER_NAMES:
                raise ValueError("response header is not safe page provenance")
            if previous_name is not None and name <= previous_name:
                raise ValueError("selected response headers must be uniquely sorted")
            if not isinstance(value, str) or "\r" in value or "\n" in value:
                raise ValueError("selected response header values must be safe strings")
            previous_name = name
        expected_headers_digest = canonical_json_sha256(
            [[name, value] for name, value in self.selected_response_headers]
        )
        if expected_headers_digest != self.selected_response_headers_sha256:
            raise ValueError("selected response header digest does not match")
        if self.response_generated_at_utc is not None:
            if (
                normalize_retrieval_timestamp(self.response_generated_at_utc)
                != self.response_generated_at_utc
            ):
                raise ValueError("response_generated_at_utc must use canonical UTC form")
        if self.batch.provider != self.provider:
            raise ValueError("page provider does not match its batch")
        if self.batch.source_url != self.endpoint_url:
            raise ValueError("page endpoint does not match its batch")
        if self.batch.normalized_query_sha256 != self.request_query_sha256:
            raise ValueError("page request query digest does not match its batch")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "proof_eligible": self.proof_eligible,
            "provider": self.provider,
            "endpoint_url": self.endpoint_url,
            "request_url": self.request_url,
            "api_contract_version": self.api_contract_version,
            "collection_query_sha256": self.collection_query_sha256,
            "request_query_sha256": self.request_query_sha256,
            "selected_response_headers": [list(item) for item in self.selected_response_headers],
            "selected_response_headers_sha256": self.selected_response_headers_sha256,
            "response_generated_at_utc": self.response_generated_at_utc,
            "pagination": self.pagination.to_dict(),
            "rate_limit": self.rate_limit.to_dict(),
            "batch": self.batch.to_dict(),
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


def _non_negative_int(value: object, field_name: str) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")


def _optional_position_string(value: object, field_name: str) -> None:
    if value is None:
        return
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError(f"{field_name} must be a bounded non-empty string")
    if any(ord(character) <= 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{field_name} must not contain whitespace or controls")


__all__ = [
    "CONTEXT_ONLY_CLASSIFICATION",
    "INTELLIGENCE_PAGE_SCHEMA_VERSION",
    "INTELLIGENCE_SCHEMA_VERSION",
    "ExternalIntelligenceBatch",
    "ExternalIntelligencePage",
    "ExternalIntelligenceRecord",
    "FreshnessMetadata",
    "FreshnessState",
    "LicenseMetadata",
    "LicenseStatus",
    "PaginationMetadata",
    "PaginationMode",
    "ParserStatus",
    "RateLimitMetadata",
    "concatenate_context_records",
]
