"""Strict deterministic parsers for supported public intelligence feeds."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Mapping

from belief.json_contracts import StrictJSONError, strict_json_loads

from .canonical import (
    canonical_json,
    canonical_json_sha256,
    normalize_retrieval_timestamp,
    parse_source_timestamp,
    require_https_url,
    sha256_bytes,
)
from .errors import IntelligenceSchemaError, MalformedIntelligenceJSONError
from .models import (
    ExternalIntelligenceBatch,
    ExternalIntelligenceRecord,
    FreshnessMetadata,
    LicenseMetadata,
)


OSV_QUERY_PARSER_VERSION = "belief.intelligence.osv_query.v1"
CISA_KEV_PARSER_VERSION = "belief.intelligence.cisa_kev.v1"


def parse_osv_query_response(
    raw_response: bytes | bytearray,
    *,
    query: Mapping[str, Any],
    source_url: str,
    retrieved_at_utc: str | datetime,
    license_metadata: LicenseMetadata | None = None,
    freshness_max_age_seconds: int | None = None,
) -> ExternalIntelligenceBatch:
    """Parse one OSV ``/v1/query`` response without deduplication or promotion."""

    raw = _raw_bytes(raw_response)
    payload = _strict_payload(raw)
    root = _object(payload, "$")
    vulnerabilities = _required_list(root, "vulns", "$")
    if "next_page_token" in root:
        next_page_token = _optional_string(root, "next_page_token", "$")
        if next_page_token and next_page_token.strip():
            raise IntelligenceSchemaError(
                "response is incomplete; pagination is not supported by this parser",
                path="$.next_page_token",
            )

    normalized_url = require_https_url(source_url)
    retrieval = normalize_retrieval_timestamp(retrieved_at_utc)
    query_sha256 = canonical_json_sha256(dict(query))
    response_sha256 = sha256_bytes(raw)
    license_value = license_metadata or LicenseMetadata.unknown()
    records: list[ExternalIntelligenceRecord] = []

    for index, candidate in enumerate(vulnerabilities):
        path = f"$.vulns[{index}]"
        vulnerability = _object(candidate, path)
        record_id = _required_non_empty_string(vulnerability, "id", path)
        _validate_osv_vulnerability(vulnerability, path)

        aliases = _optional_string_list(vulnerability, "aliases", path)
        published = _optional_string(vulnerability, "published", path)
        modified = _optional_string(vulnerability, "modified", path)
        summary = _optional_string(vulnerability, "summary", path)
        details = _optional_string(vulnerability, "details", path)
        freshness = _freshness(
            retrieved_at_utc=retrieval,
            source_published_at=published,
            source_modified_at=modified,
            max_age_seconds=freshness_max_age_seconds,
            path=path,
        )
        records.append(
            ExternalIntelligenceRecord(
                provider="osv",
                source_url=normalized_url,
                record_id=record_id,
                normalized_query_sha256=query_sha256,
                retrieved_at_utc=retrieval,
                source_revision=modified,
                raw_response_sha256=response_sha256,
                freshness=freshness,
                license=license_value,
                parser_status="parsed",
                parser_version=OSV_QUERY_PARSER_VERSION,
                occurrence_index=index,
                identifiers=(record_id, *aliases),
                summary=summary or details or "",
                canonical_payload_json=canonical_json(vulnerability),
            )
        )

    return ExternalIntelligenceBatch(
        provider="osv",
        source_url=normalized_url,
        normalized_query_sha256=query_sha256,
        retrieved_at_utc=retrieval,
        source_revision=None,
        raw_response_sha256=response_sha256,
        license=license_value,
        parser_status="parsed" if records else "parsed_empty",
        parser_version=OSV_QUERY_PARSER_VERSION,
        records=tuple(records),
    )


def parse_cisa_kev_catalog(
    raw_response: bytes | bytearray,
    *,
    query: Mapping[str, Any],
    source_url: str,
    retrieved_at_utc: str | datetime,
    license_metadata: LicenseMetadata | None = None,
    freshness_max_age_seconds: int | None = None,
) -> ExternalIntelligenceBatch:
    """Parse a CISA KEV JSON catalog while preserving every source occurrence."""

    raw = _raw_bytes(raw_response)
    payload = _strict_payload(raw)
    root = _object(payload, "$")
    _required_non_empty_string(root, "title", "$")
    catalog_version = _required_non_empty_string(root, "catalogVersion", "$")
    date_released = _required_non_empty_string(root, "dateReleased", "$")
    vulnerabilities = _required_list(root, "vulnerabilities", "$")
    if "count" not in root:
        raise IntelligenceSchemaError("required field is missing", path="$.count")
    declared_count = root["count"]
    if not isinstance(declared_count, int) or isinstance(declared_count, bool):
        raise IntelligenceSchemaError("must be an integer", path="$.count")
    if declared_count < 0:
        raise IntelligenceSchemaError("must be non-negative", path="$.count")
    if declared_count != len(vulnerabilities):
        raise IntelligenceSchemaError(
            "does not match the vulnerabilities array length",
            path="$.count",
        )

    normalized_url = require_https_url(source_url)
    retrieval = normalize_retrieval_timestamp(retrieved_at_utc)
    query_sha256 = canonical_json_sha256(dict(query))
    response_sha256 = sha256_bytes(raw)
    license_value = license_metadata or LicenseMetadata.unknown()
    records: list[ExternalIntelligenceRecord] = []

    for index, candidate in enumerate(vulnerabilities):
        path = f"$.vulnerabilities[{index}]"
        vulnerability = _object(candidate, path)
        record_id = _required_non_empty_string(vulnerability, "cveID", path)
        _validate_cisa_vulnerability(vulnerability, path)
        date_added = _required_non_empty_string(vulnerability, "dateAdded", path)
        freshness = _freshness(
            retrieved_at_utc=retrieval,
            source_published_at=date_added,
            source_modified_at=date_released,
            max_age_seconds=freshness_max_age_seconds,
            path=path,
        )
        records.append(
            ExternalIntelligenceRecord(
                provider="cisa_kev",
                source_url=normalized_url,
                record_id=record_id,
                normalized_query_sha256=query_sha256,
                retrieved_at_utc=retrieval,
                source_revision=catalog_version,
                raw_response_sha256=response_sha256,
                freshness=freshness,
                license=license_value,
                parser_status="parsed",
                parser_version=CISA_KEV_PARSER_VERSION,
                occurrence_index=index,
                identifiers=(record_id,),
                summary=_required_string(vulnerability, "vulnerabilityName", path),
                canonical_payload_json=canonical_json(vulnerability),
            )
        )

    return ExternalIntelligenceBatch(
        provider="cisa_kev",
        source_url=normalized_url,
        normalized_query_sha256=query_sha256,
        retrieved_at_utc=retrieval,
        source_revision=catalog_version,
        raw_response_sha256=response_sha256,
        license=license_value,
        parser_status="parsed" if records else "parsed_empty",
        parser_version=CISA_KEV_PARSER_VERSION,
        records=tuple(records),
    )


def _raw_bytes(value: bytes | bytearray) -> bytes:
    if not isinstance(value, (bytes, bytearray)):
        raise TypeError("raw_response must be bytes")
    return bytes(value)


def _strict_payload(raw: bytes) -> Any:
    try:
        return strict_json_loads(raw)
    except StrictJSONError as exc:
        raise MalformedIntelligenceJSONError(str(exc)) from exc


def _validate_osv_vulnerability(value: dict[str, Any], path: str) -> None:
    for field_name in ("schema_version", "published", "modified", "withdrawn", "summary", "details"):
        _optional_string(value, field_name, path)
    for field_name in ("aliases", "related", "upstream"):
        _optional_string_list(value, field_name, path)
    for field_name in ("affected", "severity", "credits"):
        if field_name not in value:
            continue
        entries = _required_list(value, field_name, path)
        for index, entry in enumerate(entries):
            _object(entry, f"{path}.{field_name}[{index}]")
    if "database_specific" in value:
        _object(value["database_specific"], f"{path}.database_specific")
    if "references" in value:
        references = _required_list(value, "references", path)
        for index, candidate in enumerate(references):
            reference_path = f"{path}.references[{index}]"
            reference = _object(candidate, reference_path)
            _required_non_empty_string(reference, "url", reference_path)
            _optional_string(reference, "type", reference_path)


def _validate_cisa_vulnerability(value: dict[str, Any], path: str) -> None:
    required_non_empty = (
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
    )
    for field_name in required_non_empty:
        _required_non_empty_string(value, field_name, path)
    _required_string(value, "notes", path)
    _optional_string_list(value, "cwes", path)


def _freshness(
    *,
    retrieved_at_utc: str,
    source_published_at: str | None,
    source_modified_at: str | None,
    max_age_seconds: int | None,
    path: str,
) -> FreshnessMetadata:
    if max_age_seconds is not None and (
        not isinstance(max_age_seconds, int)
        or isinstance(max_age_seconds, bool)
        or max_age_seconds < 0
    ):
        raise ValueError("freshness_max_age_seconds must be a non-negative integer")

    timestamps: dict[str, datetime] = {}
    for field_name, raw_value in (
        ("source_published_at", source_published_at),
        ("source_modified_at", source_modified_at),
    ):
        if raw_value is None:
            continue
        try:
            timestamps[field_name] = parse_source_timestamp(raw_value)
        except ValueError as exc:
            raise IntelligenceSchemaError(str(exc), path=f"{path}.{field_name}") from exc

    basis = "source_modified_at" if source_modified_at is not None else (
        "source_published_at" if source_published_at is not None else None
    )
    if basis is None:
        return FreshnessMetadata(
            state="unknown",
            basis=None,
            source_published_at=source_published_at,
            source_modified_at=source_modified_at,
            age_seconds=None,
            max_age_seconds=max_age_seconds,
        )

    retrieved = parse_source_timestamp(retrieved_at_utc)
    age_seconds = int((retrieved - timestamps[basis]).total_seconds())
    if age_seconds < 0:
        state = "source_in_future"
    elif max_age_seconds is None:
        state = "not_evaluated"
    elif age_seconds <= max_age_seconds:
        state = "fresh"
    else:
        state = "stale"
    return FreshnessMetadata(
        state=state,
        basis=basis,
        source_published_at=source_published_at,
        source_modified_at=source_modified_at,
        age_seconds=age_seconds,
        max_age_seconds=max_age_seconds,
    )


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntelligenceSchemaError("must be an object", path=path)
    return value


def _required_list(value: dict[str, Any], key: str, path: str) -> list[Any]:
    if key not in value:
        raise IntelligenceSchemaError("required field is missing", path=f"{path}.{key}")
    candidate = value[key]
    if not isinstance(candidate, list):
        raise IntelligenceSchemaError("must be an array", path=f"{path}.{key}")
    return candidate


def _required_string(value: dict[str, Any], key: str, path: str) -> str:
    if key not in value:
        raise IntelligenceSchemaError("required field is missing", path=f"{path}.{key}")
    candidate = value[key]
    if not isinstance(candidate, str):
        raise IntelligenceSchemaError("must be a string", path=f"{path}.{key}")
    return candidate


def _required_non_empty_string(value: dict[str, Any], key: str, path: str) -> str:
    candidate = _required_string(value, key, path)
    if not candidate.strip():
        raise IntelligenceSchemaError("must be a non-empty string", path=f"{path}.{key}")
    return candidate


def _optional_string(value: dict[str, Any], key: str, path: str) -> str | None:
    if key not in value or value[key] is None:
        return None
    candidate = value[key]
    if not isinstance(candidate, str):
        raise IntelligenceSchemaError("must be a string or null", path=f"{path}.{key}")
    return candidate


def _optional_string_list(value: dict[str, Any], key: str, path: str) -> tuple[str, ...]:
    if key not in value or value[key] is None:
        return ()
    candidate = value[key]
    if not isinstance(candidate, list):
        raise IntelligenceSchemaError("must be an array", path=f"{path}.{key}")
    result = []
    for index, entry in enumerate(candidate):
        if not isinstance(entry, str) or not entry.strip():
            raise IntelligenceSchemaError(
                "must be a non-empty string",
                path=f"{path}.{key}[{index}]",
            )
        result.append(entry)
    return tuple(result)


__all__ = [
    "CISA_KEV_PARSER_VERSION",
    "OSV_QUERY_PARSER_VERSION",
    "parse_cisa_kev_catalog",
    "parse_osv_query_response",
]
