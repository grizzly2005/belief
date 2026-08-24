"""Strict provider endpoint and query policies for external intelligence."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Literal
from urllib.parse import parse_qsl, urlencode, urlsplit

from .canonical import normalize_retrieval_timestamp, require_https_url


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CISA_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_GLOBAL_ADVISORIES_URL = "https://api.github.com/advisories"
GITHUB_API_VERSION = "2026-03-10"

ProviderName = Literal["osv", "cisa_kev", "nvd_cve", "github_advisory"]

_CVE_ID_RE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_GHSA_ID_RE = re.compile(r"^GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}$")
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_GITHUB_CURSOR_RE = re.compile(r"^[^\x00-\x20\x7f]{1,2048}$")
_GITHUB_MODIFIED_RANGE_RE = re.compile(
    r"^(?P<start>[0-9]{4}-[0-9]{2}-[0-9]{2})\.\."
    r"(?P<end>[0-9]{4}-[0-9]{2}-[0-9]{2})$"
)

_NVD_QUERY_KEYS = frozenset(
    {"cveIds", "lastModStartDate", "lastModEndDate", "resultsPerPage", "startIndex"}
)
_GITHUB_QUERY_KEYS = frozenset(
    {
        "ghsa_id",
        "cve_id",
        "type",
        "ecosystem",
        "severity",
        "modified",
        "after",
        "direction",
        "per_page",
        "sort",
    }
)
_GITHUB_TYPES = frozenset({"reviewed", "malware", "unreviewed"})
_GITHUB_ECOSYSTEMS = frozenset(
    {
        "rubygems",
        "npm",
        "pip",
        "maven",
        "nuget",
        "composer",
        "go",
        "rust",
        "erlang",
        "actions",
        "pub",
        "other",
        "swift",
    }
)
_GITHUB_SEVERITIES = frozenset({"unknown", "low", "medium", "high", "critical"})


def normalize_nvd_cve_query(query: Mapping[str, Any]) -> dict[str, Any]:
    """Return the bounded semantic query accepted by the NVD adapter."""

    source = _query_mapping(query)
    _reject_unknown_keys(source, _NVD_QUERY_KEYS, provider="NVD")

    identifiers = _normalize_cve_ids(source.get("cveIds"))
    has_start = "lastModStartDate" in source
    has_end = "lastModEndDate" in source
    if has_start != has_end:
        raise ValueError("NVD last-modified queries require both date bounds")
    if identifiers and has_start:
        raise ValueError("NVD cveIds and last-modified query modes are mutually exclusive")
    if not identifiers and not has_start:
        raise ValueError("NVD queries require cveIds or a bounded last-modified window")

    normalized: dict[str, Any] = {}
    if identifiers:
        normalized["cveIds"] = list(identifiers)
    else:
        start = _normalize_offset_timestamp(source["lastModStartDate"], "lastModStartDate")
        end = _normalize_offset_timestamp(source["lastModEndDate"], "lastModEndDate")
        if end < start:
            raise ValueError("NVD lastModEndDate must not precede lastModStartDate")
        if end - start > timedelta(days=120):
            raise ValueError("NVD last-modified windows must not exceed 120 days")
        normalized["lastModStartDate"] = normalize_retrieval_timestamp(start)
        normalized["lastModEndDate"] = normalize_retrieval_timestamp(end)

    default_page_size = 100 if identifiers else 2000
    normalized["resultsPerPage"] = _bounded_int(
        source.get("resultsPerPage", default_page_size),
        field="resultsPerPage",
        minimum=1,
        maximum=2000,
    )
    normalized["startIndex"] = _bounded_int(
        source.get("startIndex", 0),
        field="startIndex",
        minimum=0,
        maximum=2**31 - 1,
    )
    return normalized


def nvd_collection_query(query: Mapping[str, Any]) -> dict[str, Any]:
    """Return NVD filters without page-size or offset state."""

    normalized = normalize_nvd_cve_query(query)
    return {
        key: value
        for key, value in normalized.items()
        if key not in {"resultsPerPage", "startIndex"}
    }


def build_nvd_cve_url(query: Mapping[str, Any]) -> str:
    """Build a canonical NVD CVE URL from a validated bounded query."""

    normalized = normalize_nvd_cve_query(query)
    items: list[tuple[str, str]] = []
    if "cveIds" in normalized:
        items.append(("cveIds", ",".join(normalized["cveIds"])))
    else:
        items.extend(
            (
                ("lastModStartDate", normalized["lastModStartDate"]),
                ("lastModEndDate", normalized["lastModEndDate"]),
            )
        )
    items.extend(
        (
            ("resultsPerPage", str(normalized["resultsPerPage"])),
            ("startIndex", str(normalized["startIndex"])),
        )
    )
    return f"{NVD_CVE_API_URL}?{urlencode(items, safe=',:')}"


def normalize_github_advisory_query(query: Mapping[str, Any]) -> dict[str, Any]:
    """Return the bounded semantic query accepted by the GitHub adapter."""

    source = _query_mapping(query)
    _reject_unknown_keys(source, _GITHUB_QUERY_KEYS, provider="GitHub")
    if not any(key in source for key in ("ghsa_id", "cve_id", "modified")):
        raise ValueError("GitHub advisory queries require ghsa_id, cve_id, or modified")

    normalized: dict[str, Any] = {}
    if "ghsa_id" in source:
        normalized["ghsa_id"] = _matching_string(
            source["ghsa_id"], _GHSA_ID_RE, field="ghsa_id"
        )
    if "cve_id" in source:
        normalized["cve_id"] = _matching_string(
            source["cve_id"], _CVE_ID_RE, field="cve_id"
        )

    advisory_type = _choice(source.get("type", "reviewed"), _GITHUB_TYPES, field="type")
    normalized["type"] = advisory_type
    if "ecosystem" in source:
        normalized["ecosystem"] = _choice(
            source["ecosystem"], _GITHUB_ECOSYSTEMS, field="ecosystem"
        )
    if "severity" in source:
        normalized["severity"] = _choice(
            source["severity"], _GITHUB_SEVERITIES, field="severity"
        )
    if "modified" in source:
        normalized["modified"] = _normalize_github_modified_range(source["modified"])

    normalized["direction"] = _choice(
        source.get("direction", "desc"), frozenset({"asc", "desc"}), field="direction"
    )
    normalized["per_page"] = _bounded_int(
        source.get("per_page", 100), field="per_page", minimum=1, maximum=100
    )
    normalized["sort"] = _choice(
        source.get("sort", "published"),
        frozenset({"updated", "published", "epss_percentage", "epss_percentile"}),
        field="sort",
    )
    if "after" in source:
        cursor = source["after"]
        if not isinstance(cursor, str) or not _GITHUB_CURSOR_RE.fullmatch(cursor):
            raise ValueError("after must be a bounded non-whitespace GitHub cursor")
        normalized["after"] = cursor
    return normalized


def github_collection_query(query: Mapping[str, Any]) -> dict[str, Any]:
    """Return GitHub filters and ordering without page-size or cursor state."""

    normalized = normalize_github_advisory_query(query)
    return {
        key: value for key, value in normalized.items() if key not in {"after", "per_page"}
    }


def build_github_advisory_url(query: Mapping[str, Any]) -> str:
    """Build a canonical GitHub advisory URL from a validated bounded query."""

    normalized = normalize_github_advisory_query(query)
    order = (
        "ghsa_id",
        "cve_id",
        "type",
        "ecosystem",
        "severity",
        "modified",
        "direction",
        "per_page",
        "sort",
        "after",
    )
    items = [(key, str(normalized[key])) for key in order if key in normalized]
    return f"{GITHUB_GLOBAL_ADVISORIES_URL}?{urlencode(items, safe=':')}"


def validate_registered_request_url(url: str, method: str) -> ProviderName:
    """Validate an exact provider origin/path/query/method policy."""

    normalized = require_https_url(url, field="request URL")
    if normalized != url:
        raise ValueError("request URL must be an exact registered intelligence endpoint")
    if url == OSV_QUERY_URL and method == "POST":
        return "osv"
    if url == CISA_KEV_CATALOG_URL and method == "GET":
        return "cisa_kev"

    parts = urlsplit(url)
    try:
        if method == "GET" and _exact_origin_path(
            parts, "services.nvd.nist.gov", "/rest/json/cves/2.0"
        ):
            query = _decode_nvd_query(parts.query)
            if build_nvd_cve_url(query) == url:
                return "nvd_cve"
        if method == "GET" and _exact_origin_path(parts, "api.github.com", "/advisories"):
            query = _decode_github_query(parts.query)
            if build_github_advisory_url(query) == url:
                return "github_advisory"
    except ValueError:
        pass
    raise ValueError("request URL must be an exact registered intelligence endpoint")


def validate_registered_response_url(url: str) -> ProviderName:
    """Validate a response URL against one registered provider policy."""

    if url == OSV_QUERY_URL:
        return "osv"
    if url == CISA_KEV_CATALOG_URL:
        return "cisa_kev"
    try:
        return validate_registered_request_url(url, "GET")
    except ValueError as exc:
        raise ValueError("response URL must be an exact registered intelligence endpoint") from exc


def query_from_nvd_url(url: str) -> dict[str, Any]:
    """Return the validated normalized query encoded in an NVD URL."""

    if validate_registered_request_url(url, "GET") != "nvd_cve":
        raise ValueError("URL is not a registered NVD request")
    return normalize_nvd_cve_query(_decode_nvd_query(urlsplit(url).query))


def query_from_github_url(url: str) -> dict[str, Any]:
    """Return the validated normalized query encoded in a GitHub URL."""

    if validate_registered_request_url(url, "GET") != "github_advisory":
        raise ValueError("URL is not a registered GitHub advisory request")
    return normalize_github_advisory_query(_decode_github_query(urlsplit(url).query))


def _query_mapping(query: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(query, Mapping):
        raise TypeError("provider query must be a mapping")
    result = dict(query)
    if not all(isinstance(key, str) for key in result):
        raise TypeError("provider query keys must be strings")
    return result


def _reject_unknown_keys(
    query: Mapping[str, Any], allowed: frozenset[str], *, provider: str
) -> None:
    unknown = sorted(set(query) - allowed)
    if unknown:
        raise ValueError(f"{provider} query contains unsupported parameters: {unknown}")


def _normalize_cve_ids(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        candidates: Sequence[Any] = value.split(",")
    elif isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        candidates = value
    else:
        raise TypeError("cveIds must be a string or sequence of CVE identifiers")
    if not 1 <= len(candidates) <= 100:
        raise ValueError("cveIds must contain between 1 and 100 identifiers")
    result: list[str] = []
    for candidate in candidates:
        identifier = _matching_string(candidate, _CVE_ID_RE, field="cveIds entry")
        if identifier in result:
            raise ValueError("cveIds must not contain duplicates")
        result.append(identifier)
    return tuple(result)


def _normalize_offset_timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 timestamp with a UTC offset")
    text = value.strip()
    parsed_text = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
    try:
        parsed = datetime.fromisoformat(parsed_text)
    except ValueError as exc:
        raise ValueError(f"{field} must be an ISO-8601 timestamp with a UTC offset") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _normalize_github_modified_range(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("modified must be a closed YYYY-MM-DD..YYYY-MM-DD range")
    match = _GITHUB_MODIFIED_RANGE_RE.fullmatch(value)
    if match is None:
        raise ValueError("modified must be a closed YYYY-MM-DD..YYYY-MM-DD range")
    try:
        start = datetime.fromisoformat(match.group("start"))
        end = datetime.fromisoformat(match.group("end"))
    except ValueError as exc:
        raise ValueError("modified contains an invalid calendar date") from exc
    if end < start:
        raise ValueError("modified range end must not precede its start")
    if end - start > timedelta(days=31):
        raise ValueError("GitHub modified ranges must not exceed 31 days")
    return value


def _matching_string(value: Any, pattern: re.Pattern[str], *, field: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{field} has an invalid format")
    return value


def _choice(value: Any, choices: frozenset[str], *, field: str) -> str:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"{field} must be one of {sorted(choices)}")
    return value


def _bounded_int(value: Any, *, field: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise TypeError(f"{field} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{field} must be within [{minimum}, {maximum}]")
    return value


def _exact_origin_path(parts: Any, hostname: str, path: str) -> bool:
    return (
        parts.scheme == "https"
        and parts.netloc == hostname
        and parts.hostname == hostname
        and parts.port is None
        and parts.username is None
        and parts.password is None
        and parts.path == path
        and not parts.fragment
        and bool(parts.query)
    )


def _parse_unique_query(query: str, *, maximum_fields: int) -> dict[str, str]:
    if not query or _INVALID_PERCENT_ESCAPE_RE.search(query):
        raise ValueError("provider query is missing or has invalid percent encoding")
    try:
        pairs = parse_qsl(
            query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=maximum_fields,
        )
    except ValueError as exc:
        raise ValueError("provider query is malformed") from exc
    result: dict[str, str] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"provider query parameter is duplicated: {key}")
        result[key] = value
    return result


def _decode_nvd_query(query: str) -> dict[str, Any]:
    decoded: dict[str, Any] = _parse_unique_query(query, maximum_fields=5)
    for key in ("resultsPerPage", "startIndex"):
        if key in decoded:
            try:
                decoded[key] = int(decoded[key])
            except ValueError as exc:
                raise ValueError(f"{key} must be an integer") from exc
    return decoded


def _decode_github_query(query: str) -> dict[str, Any]:
    decoded: dict[str, Any] = _parse_unique_query(query, maximum_fields=10)
    if "per_page" in decoded:
        try:
            decoded["per_page"] = int(decoded["per_page"])
        except ValueError as exc:
            raise ValueError("per_page must be an integer") from exc
    return decoded


__all__ = [
    "CISA_KEV_CATALOG_URL",
    "GITHUB_API_VERSION",
    "GITHUB_GLOBAL_ADVISORIES_URL",
    "NVD_CVE_API_URL",
    "OSV_QUERY_URL",
    "ProviderName",
    "build_github_advisory_url",
    "build_nvd_cve_url",
    "github_collection_query",
    "normalize_github_advisory_query",
    "normalize_nvd_cve_query",
    "nvd_collection_query",
    "query_from_github_url",
    "query_from_nvd_url",
    "validate_registered_request_url",
    "validate_registered_response_url",
]
