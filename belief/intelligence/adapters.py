"""Strict context-only adapters for NVD and GitHub advisory pages."""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .canonical import (
    canonical_json,
    canonical_json_sha256,
    normalize_retrieval_timestamp,
    sha256_bytes,
)
from .errors import IntelligenceSchemaError
from .models import (
    ExternalIntelligenceBatch,
    ExternalIntelligencePage,
    ExternalIntelligenceRecord,
    LicenseMetadata,
    PaginationMetadata,
    RateLimitMetadata,
)
from .parsers import _freshness, _strict_payload
from .providers import (
    GITHUB_API_VERSION,
    GITHUB_GLOBAL_ADVISORIES_URL,
    NVD_CVE_API_URL,
    build_github_advisory_url,
    build_nvd_cve_url,
    github_collection_query,
    normalize_github_advisory_query,
    normalize_nvd_cve_query,
    nvd_collection_query,
    query_from_github_url,
)
from .transport import HTTPFetchResponse, MAX_HTTP_RESPONSE_BYTES


NVD_CVE_PARSER_VERSION = "belief.intelligence.nvd_cve_2_0.v1"
GITHUB_ADVISORY_PARSER_VERSION = "belief.intelligence.github_global_advisory.v1"

NVD_LICENSE_METADATA = LicenseMetadata(
    identifier="NIST-PUBLIC-DOMAIN-US",
    status="provider_documented",
    terms_url="https://nvd.nist.gov/developers/terms-of-use",
    attribution="This product uses the NVD API but is not endorsed or certified by the NVD.",
)
GITHUB_ADVISORY_LICENSE_METADATA = LicenseMetadata(
    identifier="CC-BY-4.0",
    status="declared",
    terms_url=(
        "https://docs.github.com/en/site-policy/github-terms/"
        "github-terms-for-additional-products-and-features"
    ),
    attribution="GitHub Advisory Database: https://github.com/advisories",
)

_CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_GHSA_ID_RE = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$")
_NVD_ZERO_OFFSET_TIMESTAMP_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?$"
)
_LINK_SEGMENT_RE = re.compile(r'^\s*<(?P<url>[^>]+)>\s*;\s*rel="(?P<rel>[^"]+)"\s*$')
_SAFE_RESPONSE_HEADERS = frozenset(
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


def parse_nvd_cve_response(
    response: HTTPFetchResponse,
    *,
    query: Mapping[str, Any],
    freshness_max_age_seconds: int | None = None,
) -> ExternalIntelligencePage:
    """Parse one complete NVD CVE 2.0 offset page as non-proof context."""

    _response_type(response)
    normalized_query = normalize_nvd_cve_query(query)
    expected_url = build_nvd_cve_url(normalized_query)
    if response.source_url != expected_url:
        raise IntelligenceSchemaError("does not match the normalized query", path="$.request_url")
    headers = _selected_headers(response.headers)
    _require_json_content_type(headers)
    if len(response.body) > MAX_HTTP_RESPONSE_BYTES:
        raise IntelligenceSchemaError("response exceeds the parser byte bound")

    root = _object(_strict_payload(response.body), "$")
    response_format = _required_non_empty_string(root, "format", "$")
    if response_format != "NVD_CVE":
        raise IntelligenceSchemaError("must be NVD_CVE", path="$.format")
    version = _required_non_empty_string(root, "version", "$")
    if version != "2.0":
        raise IntelligenceSchemaError("must be 2.0", path="$.version")
    generated_at = _normalize_nvd_timestamp(
        _required_non_empty_string(root, "timestamp", "$"), path="$.timestamp"
    )
    results_per_page = _required_int(root, "resultsPerPage", "$", minimum=0, maximum=2000)
    start_index = _required_int(root, "startIndex", "$", minimum=0)
    total_results = _required_int(root, "totalResults", "$", minimum=0)
    vulnerabilities = _required_list(root, "vulnerabilities", "$")
    if len(vulnerabilities) > 2000:
        raise IntelligenceSchemaError("contains more than 2000 records", path="$.vulnerabilities")
    if results_per_page != len(vulnerabilities):
        raise IntelligenceSchemaError(
            "does not match the vulnerabilities array length",
            path="$.resultsPerPage",
        )
    if start_index != normalized_query["startIndex"]:
        raise IntelligenceSchemaError("does not match the requested offset", path="$.startIndex")
    if results_per_page > normalized_query["resultsPerPage"]:
        raise IntelligenceSchemaError("exceeds the requested page size", path="$.resultsPerPage")
    if start_index + results_per_page > total_results:
        raise IntelligenceSchemaError("page extends beyond totalResults", path="$.totalResults")
    if start_index < total_results and not vulnerabilities:
        raise IntelligenceSchemaError(
            "non-final page contains no records", path="$.vulnerabilities"
        )

    query_digest = canonical_json_sha256(normalized_query)
    response_digest = _response_digest(response)
    records: list[ExternalIntelligenceRecord] = []
    for index, candidate in enumerate(vulnerabilities):
        wrapper_path = f"$.vulnerabilities[{index}]"
        wrapper = _object(candidate, wrapper_path)
        cve = _object(_required_field(wrapper, "cve", wrapper_path), f"{wrapper_path}.cve")
        cve_path = f"{wrapper_path}.cve"
        identifier = _matching_identifier(
            _required_non_empty_string(cve, "id", cve_path),
            _CVE_ID_RE,
            path=f"{cve_path}.id",
        )
        if "cveIds" in normalized_query and identifier not in normalized_query["cveIds"]:
            raise IntelligenceSchemaError(
                "does not match the requested cveIds", path=f"{cve_path}.id"
            )
        _required_non_empty_string(cve, "sourceIdentifier", cve_path)
        published = _normalize_nvd_timestamp(
            _required_non_empty_string(cve, "published", cve_path),
            path=f"{cve_path}.published",
        )
        modified = _normalize_nvd_timestamp(
            _required_non_empty_string(cve, "lastModified", cve_path),
            path=f"{cve_path}.lastModified",
        )
        if "lastModStartDate" in normalized_query and not _within_timestamp_range(
            modified,
            normalized_query["lastModStartDate"],
            normalized_query["lastModEndDate"],
        ):
            raise IntelligenceSchemaError(
                "does not match the requested last-modified window",
                path=f"{cve_path}.lastModified",
            )
        _required_non_empty_string(cve, "vulnStatus", cve_path)
        descriptions = _required_list(cve, "descriptions", cve_path)
        summary = _localized_summary(descriptions, path=f"{cve_path}.descriptions")
        _validate_nvd_optional_structures(cve, cve_path)
        freshness = _freshness(
            retrieved_at_utc=response.retrieved_at_utc,
            source_published_at=published,
            source_modified_at=modified,
            max_age_seconds=freshness_max_age_seconds,
            path=cve_path,
        )
        records.append(
            ExternalIntelligenceRecord(
                provider="nvd_cve",
                source_url=NVD_CVE_API_URL,
                record_id=identifier,
                normalized_query_sha256=query_digest,
                retrieved_at_utc=response.retrieved_at_utc,
                source_revision=modified,
                raw_response_sha256=response_digest,
                freshness=freshness,
                license=NVD_LICENSE_METADATA,
                parser_status="parsed",
                parser_version=NVD_CVE_PARSER_VERSION,
                occurrence_index=index,
                identifiers=(identifier,),
                summary=summary,
                canonical_payload_json=canonical_json(cve),
            )
        )

    batch = ExternalIntelligenceBatch(
        provider="nvd_cve",
        source_url=NVD_CVE_API_URL,
        normalized_query_sha256=query_digest,
        retrieved_at_utc=response.retrieved_at_utc,
        source_revision=None,
        raw_response_sha256=response_digest,
        license=NVD_LICENSE_METADATA,
        parser_status="parsed" if records else "parsed_empty",
        parser_version=NVD_CVE_PARSER_VERSION,
        records=tuple(records),
    )
    collection_complete = start_index + results_per_page >= total_results
    next_position = None if collection_complete else start_index + results_per_page
    retry_after = _optional_header_int(headers, "retry-after")
    return _page(
        provider="nvd_cve",
        endpoint_url=NVD_CVE_API_URL,
        response=response,
        api_contract_version="NVD_CVE/2.0",
        collection_query=nvd_collection_query(normalized_query),
        normalized_query=normalized_query,
        headers=headers,
        response_generated_at_utc=generated_at,
        pagination=PaginationMetadata(
            mode="offset",
            request_position=start_index,
            next_position=next_position,
            page_size=results_per_page,
            provider_total=total_results,
            page_complete=True,
            collection_complete=collection_complete,
            collection_status="complete" if collection_complete else "incomplete",
            requested_page_size=normalized_query["resultsPerPage"],
        ),
        rate_limit=RateLimitMetadata(
            policy_limit=None,
            policy_window_seconds=None,
            observed_limit=None,
            remaining=None,
            used=None,
            reset_epoch_seconds=None,
            retry_after_seconds=retry_after,
            resource=None,
        ),
        batch=batch,
    )


def parse_github_advisory_response(
    response: HTTPFetchResponse,
    *,
    query: Mapping[str, Any],
    freshness_max_age_seconds: int | None = None,
) -> ExternalIntelligencePage:
    """Parse one GitHub cursor page without treating an absent Link as completeness."""

    _response_type(response)
    normalized_query = normalize_github_advisory_query(query)
    expected_url = build_github_advisory_url(normalized_query)
    if response.source_url != expected_url:
        raise IntelligenceSchemaError("does not match the normalized query", path="$.request_url")
    headers = _selected_headers(response.headers)
    _require_json_content_type(headers)
    selected_version = headers.get("x-github-api-version-selected")
    if selected_version != GITHUB_API_VERSION:
        raise IntelligenceSchemaError(
            f"must be {GITHUB_API_VERSION}",
            path="$.headers.x-github-api-version-selected",
        )
    if len(response.body) > MAX_HTTP_RESPONSE_BYTES:
        raise IntelligenceSchemaError("response exceeds the parser byte bound")

    advisories = _list(_strict_payload(response.body), "$")
    if len(advisories) > normalized_query["per_page"]:
        raise IntelligenceSchemaError("exceeds the requested page size", path="$")
    next_cursor = _github_next_cursor(
        headers.get("link"),
        collection_query=github_collection_query(normalized_query),
        per_page=normalized_query["per_page"],
        current_cursor=normalized_query.get("after"),
    )

    query_digest = canonical_json_sha256(normalized_query)
    response_digest = _response_digest(response)
    records: list[ExternalIntelligenceRecord] = []
    for index, candidate in enumerate(advisories):
        path = f"$[{index}]"
        advisory = _object(candidate, path)
        ghsa_id = _matching_identifier(
            _required_non_empty_string(advisory, "ghsa_id", path),
            _GHSA_ID_RE,
            path=f"{path}.ghsa_id",
        )
        cve_id = _optional_string(advisory, "cve_id", path)
        if cve_id is not None:
            cve_id = _matching_identifier(cve_id, _CVE_ID_RE, path=f"{path}.cve_id")
        summary = _required_string(advisory, "summary", path)
        advisory_type = _required_non_empty_string(advisory, "type", path)
        if advisory_type not in {"reviewed", "malware", "unreviewed"}:
            raise IntelligenceSchemaError("has an unknown advisory type", path=f"{path}.type")
        if advisory_type != normalized_query["type"]:
            raise IntelligenceSchemaError(
                "does not match the requested advisory type", path=f"{path}.type"
            )
        severity = _required_non_empty_string(advisory, "severity", path)
        if severity not in {"unknown", "low", "medium", "high", "critical"}:
            raise IntelligenceSchemaError("has an unknown severity", path=f"{path}.severity")
        if "severity" in normalized_query and severity != normalized_query["severity"]:
            raise IntelligenceSchemaError(
                "does not match the requested severity", path=f"{path}.severity"
            )
        published = _normalize_source_timestamp(
            _required_non_empty_string(advisory, "published_at", path),
            path=f"{path}.published_at",
        )
        modified = _normalize_source_timestamp(
            _required_non_empty_string(advisory, "updated_at", path),
            path=f"{path}.updated_at",
        )
        withdrawn = _optional_string(advisory, "withdrawn_at", path)
        if withdrawn is not None:
            _normalize_source_timestamp(withdrawn, path=f"{path}.withdrawn_at")
        identifiers = _github_identifiers(advisory, path, ghsa_id=ghsa_id, cve_id=cve_id)
        if "ghsa_id" in normalized_query and ghsa_id != normalized_query["ghsa_id"]:
            raise IntelligenceSchemaError(
                "does not match the requested ghsa_id", path=f"{path}.ghsa_id"
            )
        if "cve_id" in normalized_query and cve_id != normalized_query["cve_id"]:
            raise IntelligenceSchemaError(
                "does not match the requested cve_id", path=f"{path}.cve_id"
            )
        _validate_github_optional_structures(advisory, path)
        if "ecosystem" in normalized_query and not _github_matches_ecosystem(
            advisory, normalized_query["ecosystem"]
        ):
            raise IntelligenceSchemaError(
                "does not match the requested ecosystem", path=f"{path}.vulnerabilities"
            )
        if "modified" in normalized_query and not _within_github_date_range(
            published, modified, normalized_query["modified"]
        ):
            raise IntelligenceSchemaError(
                "does not match the requested modified range", path=f"{path}.updated_at"
            )
        freshness = _freshness(
            retrieved_at_utc=response.retrieved_at_utc,
            source_published_at=published,
            source_modified_at=modified,
            max_age_seconds=freshness_max_age_seconds,
            path=path,
        )
        records.append(
            ExternalIntelligenceRecord(
                provider="github_advisory",
                source_url=GITHUB_GLOBAL_ADVISORIES_URL,
                record_id=ghsa_id,
                normalized_query_sha256=query_digest,
                retrieved_at_utc=response.retrieved_at_utc,
                source_revision=modified,
                raw_response_sha256=response_digest,
                freshness=freshness,
                license=GITHUB_ADVISORY_LICENSE_METADATA,
                parser_status="parsed",
                parser_version=GITHUB_ADVISORY_PARSER_VERSION,
                occurrence_index=index,
                identifiers=identifiers,
                summary=summary,
                canonical_payload_json=canonical_json(advisory),
            )
        )

    batch = ExternalIntelligenceBatch(
        provider="github_advisory",
        source_url=GITHUB_GLOBAL_ADVISORIES_URL,
        normalized_query_sha256=query_digest,
        retrieved_at_utc=response.retrieved_at_utc,
        source_revision=None,
        raw_response_sha256=response_digest,
        license=GITHUB_ADVISORY_LICENSE_METADATA,
        parser_status="parsed" if records else "parsed_empty",
        parser_version=GITHUB_ADVISORY_PARSER_VERSION,
        records=tuple(records),
    )
    rate_limit = _github_rate_limit(headers)
    return _page(
        provider="github_advisory",
        endpoint_url=GITHUB_GLOBAL_ADVISORIES_URL,
        response=response,
        api_contract_version=GITHUB_API_VERSION,
        collection_query=github_collection_query(normalized_query),
        normalized_query=normalized_query,
        headers=headers,
        response_generated_at_utc=None,
        pagination=PaginationMetadata(
            mode="cursor",
            request_position=normalized_query.get("after"),
            next_position=next_cursor,
            page_size=len(records),
            provider_total=None,
            page_complete=True,
            collection_complete=False,
            collection_status="incomplete" if next_cursor is not None else "unknown",
            requested_page_size=normalized_query["per_page"],
        ),
        rate_limit=rate_limit,
        batch=batch,
    )


def _page(
    *,
    provider: str,
    endpoint_url: str,
    response: HTTPFetchResponse,
    api_contract_version: str,
    collection_query: Mapping[str, Any],
    normalized_query: Mapping[str, Any],
    headers: Mapping[str, str],
    response_generated_at_utc: str | None,
    pagination: PaginationMetadata,
    rate_limit: RateLimitMetadata,
    batch: ExternalIntelligenceBatch,
) -> ExternalIntelligencePage:
    selected_headers = tuple(sorted(headers.items()))
    return ExternalIntelligencePage(
        provider=provider,
        endpoint_url=endpoint_url,
        request_url=response.source_url,
        api_contract_version=api_contract_version,
        collection_query_sha256=canonical_json_sha256(dict(collection_query)),
        request_query_sha256=canonical_json_sha256(dict(normalized_query)),
        selected_response_headers=selected_headers,
        selected_response_headers_sha256=canonical_json_sha256(
            [[name, value] for name, value in selected_headers]
        ),
        response_generated_at_utc=response_generated_at_utc,
        raw_response_bytes=len(response.body),
        pagination=pagination,
        rate_limit=rate_limit,
        batch=batch,
    )


def _selected_headers(headers: tuple[tuple[str, str], ...]) -> dict[str, str]:
    if not isinstance(headers, tuple):
        raise TypeError("response headers must be an immutable tuple")
    selected: dict[str, str] = {}
    for name, value in headers:
        if not isinstance(name, str) or not isinstance(value, str):
            raise IntelligenceSchemaError("response headers must contain strings")
        normalized_name = name.lower()
        if normalized_name not in _SAFE_RESPONSE_HEADERS:
            continue
        if normalized_name in selected:
            raise IntelligenceSchemaError(
                "selected response header is duplicated",
                path=f"$.headers.{normalized_name}",
            )
        normalized_value = value.strip()
        if "\r" in normalized_value or "\n" in normalized_value:
            raise IntelligenceSchemaError(
                "response header contains a line break",
                path=f"$.headers.{normalized_name}",
            )
        selected[normalized_name] = normalized_value
    return selected


def _require_json_content_type(headers: Mapping[str, str]) -> None:
    content_type = headers.get("content-type", "")
    if content_type.split(";", 1)[0].strip().lower() not in {
        "application/json",
        "application/vnd.github+json",
    }:
        raise IntelligenceSchemaError(
            "must identify a JSON response", path="$.headers.content-type"
        )


def _github_next_cursor(
    link_header: str | None,
    *,
    collection_query: Mapping[str, Any],
    per_page: int,
    current_cursor: str | None,
) -> str | None:
    if link_header is None:
        return None
    relations: dict[str, str] = {}
    for segment in link_header.split(","):
        match = _LINK_SEGMENT_RE.fullmatch(segment)
        if match is None:
            raise IntelligenceSchemaError("has invalid Link syntax", path="$.headers.link")
        relation = match.group("rel")
        if relation in relations:
            raise IntelligenceSchemaError("contains a duplicate relation", path="$.headers.link")
        relations[relation] = match.group("url")
    next_url = relations.get("next")
    if next_url is None:
        return None
    try:
        next_query = query_from_github_url(next_url)
    except (TypeError, ValueError) as exc:
        raise IntelligenceSchemaError(
            "next link violates the registered endpoint policy", path="$.headers.link"
        ) from exc
    if github_collection_query(next_query) != dict(collection_query):
        raise IntelligenceSchemaError("next link changes collection filters", path="$.headers.link")
    if next_query["per_page"] != per_page:
        raise IntelligenceSchemaError("next link changes page size", path="$.headers.link")
    cursor = next_query.get("after")
    if cursor is None or cursor == current_cursor:
        raise IntelligenceSchemaError("next link must advance the cursor", path="$.headers.link")
    return cursor


def _github_rate_limit(headers: Mapping[str, str]) -> RateLimitMetadata:
    names = {
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-ratelimit-resource",
    }
    present = names.intersection(headers)
    if present and present != names:
        raise IntelligenceSchemaError("GitHub rate-limit state is incomplete", path="$.headers")
    observed_limit = _optional_header_int(headers, "x-ratelimit-limit")
    remaining = _optional_header_int(headers, "x-ratelimit-remaining")
    if observed_limit is not None and remaining is not None and remaining > observed_limit:
        raise IntelligenceSchemaError(
            "remaining quota exceeds the limit", path="$.headers.x-ratelimit-remaining"
        )
    return RateLimitMetadata(
        policy_limit=None,
        policy_window_seconds=None,
        observed_limit=observed_limit,
        remaining=remaining,
        used=_optional_header_int(headers, "x-ratelimit-used"),
        reset_epoch_seconds=_optional_header_int(headers, "x-ratelimit-reset"),
        retry_after_seconds=_optional_header_int(headers, "retry-after"),
        resource=headers.get("x-ratelimit-resource"),
    )


def _optional_header_int(headers: Mapping[str, str], name: str) -> int | None:
    value = headers.get(name)
    if value is None:
        return None
    try:
        parsed = int(value)
    except ValueError as exc:
        raise IntelligenceSchemaError(
            "must be a non-negative integer", path=f"$.headers.{name}"
        ) from exc
    if parsed < 0:
        raise IntelligenceSchemaError("must be a non-negative integer", path=f"$.headers.{name}")
    return parsed


def _normalize_nvd_timestamp(value: str, *, path: str) -> str:
    candidate = f"{value}Z" if _NVD_ZERO_OFFSET_TIMESTAMP_RE.fullmatch(value) else value
    return _normalize_source_timestamp(candidate, path=path)


def _normalize_source_timestamp(value: str, *, path: str) -> str:
    try:
        return normalize_retrieval_timestamp(value)
    except (TypeError, ValueError) as exc:
        raise IntelligenceSchemaError(str(exc), path=path) from exc


def _localized_summary(descriptions: list[Any], *, path: str) -> str:
    if not descriptions:
        raise IntelligenceSchemaError("must not be empty", path=path)
    candidates: list[tuple[str, str]] = []
    for index, candidate in enumerate(descriptions):
        item_path = f"{path}[{index}]"
        description = _object(candidate, item_path)
        language = _required_non_empty_string(description, "lang", item_path)
        value = _required_non_empty_string(description, "value", item_path)
        candidates.append((language, value))
    for language, value in candidates:
        if language.lower() == "en":
            return value
    return candidates[0][1]


def _validate_nvd_optional_structures(cve: dict[str, Any], path: str) -> None:
    for name in ("metrics",):
        if name in cve:
            _object(cve[name], f"{path}.{name}")
    for name in ("weaknesses", "configurations", "references", "vendorComments", "cveTags"):
        if name in cve:
            _list(cve[name], f"{path}.{name}")


def _github_identifiers(
    advisory: dict[str, Any],
    path: str,
    *,
    ghsa_id: str,
    cve_id: str | None,
) -> tuple[str, ...]:
    raw_identifiers = _required_list(advisory, "identifiers", path)
    identifiers: list[str] = []
    typed: list[tuple[str, str]] = []
    for index, candidate in enumerate(raw_identifiers):
        item_path = f"{path}.identifiers[{index}]"
        item = _object(candidate, item_path)
        identifier_type = _required_non_empty_string(item, "type", item_path)
        identifier_value = _required_non_empty_string(item, "value", item_path)
        typed.append((identifier_type, identifier_value))
        identifiers.append(identifier_value)
    if ("GHSA", ghsa_id) not in typed:
        raise IntelligenceSchemaError(
            "must contain the record GHSA identifier", path=f"{path}.identifiers"
        )
    if cve_id is not None and ("CVE", cve_id) not in typed:
        raise IntelligenceSchemaError(
            "must contain the record CVE identifier", path=f"{path}.identifiers"
        )
    return tuple(identifiers)


def _validate_github_optional_structures(advisory: dict[str, Any], path: str) -> None:
    for name in ("vulnerabilities", "cwes", "references", "credits"):
        if name not in advisory:
            continue
        values = _list(advisory[name], f"{path}.{name}")
        if name == "references":
            for index, value in enumerate(values):
                if not isinstance(value, str) or not value.strip():
                    raise IntelligenceSchemaError(
                        "must contain non-empty strings", path=f"{path}.{name}[{index}]"
                    )
        else:
            for index, value in enumerate(values):
                _object(value, f"{path}.{name}[{index}]")
    for name in ("cvss", "cvss_severities", "epss"):
        if name in advisory and advisory[name] is not None:
            _object(advisory[name], f"{path}.{name}")


def _github_matches_ecosystem(advisory: dict[str, Any], ecosystem: str) -> bool:
    vulnerabilities = advisory.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        return False
    for candidate in vulnerabilities:
        if not isinstance(candidate, dict):
            continue
        package = candidate.get("package")
        if isinstance(package, dict) and package.get("ecosystem") == ecosystem:
            return True
    return False


def _within_github_date_range(published: str, modified: str, date_range: str) -> bool:
    start, end = date_range.split("..", 1)
    return start <= published[:10] <= end or start <= modified[:10] <= end


def _within_timestamp_range(value: str, start: str, end: str) -> bool:
    return _as_datetime(start) <= _as_datetime(value) <= _as_datetime(end)


def _as_datetime(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00" if value.endswith("Z") else value)


def _response_type(response: object) -> None:
    if not isinstance(response, HTTPFetchResponse):
        raise TypeError("response must be an HTTPFetchResponse")


def _response_digest(response: HTTPFetchResponse) -> str:
    return sha256_bytes(response.body)


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise IntelligenceSchemaError("must be an object", path=path)
    return value


def _list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise IntelligenceSchemaError("must be an array", path=path)
    return value


def _required_field(value: dict[str, Any], key: str, path: str) -> Any:
    if key not in value:
        raise IntelligenceSchemaError("required field is missing", path=f"{path}.{key}")
    return value[key]


def _required_list(value: dict[str, Any], key: str, path: str) -> list[Any]:
    return _list(_required_field(value, key, path), f"{path}.{key}")


def _required_string(value: dict[str, Any], key: str, path: str) -> str:
    candidate = _required_field(value, key, path)
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
    if not isinstance(value[key], str):
        raise IntelligenceSchemaError("must be a string or null", path=f"{path}.{key}")
    return value[key]


def _required_int(
    value: dict[str, Any],
    key: str,
    path: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    candidate = _required_field(value, key, path)
    if not isinstance(candidate, int) or isinstance(candidate, bool):
        raise IntelligenceSchemaError("must be an integer", path=f"{path}.{key}")
    if candidate < minimum or (maximum is not None and candidate > maximum):
        raise IntelligenceSchemaError("is outside the accepted bounds", path=f"{path}.{key}")
    return candidate


def _matching_identifier(value: str, pattern: re.Pattern[str], *, path: str) -> str:
    if pattern.fullmatch(value) is None:
        raise IntelligenceSchemaError("has an invalid identifier format", path=path)
    return value


__all__ = [
    "GITHUB_ADVISORY_LICENSE_METADATA",
    "GITHUB_ADVISORY_PARSER_VERSION",
    "NVD_CVE_PARSER_VERSION",
    "NVD_LICENSE_METADATA",
    "parse_github_advisory_response",
    "parse_nvd_cve_response",
]
