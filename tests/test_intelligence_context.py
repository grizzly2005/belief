from __future__ import annotations

import hashlib
import copy
import inspect
import json
from dataclasses import FrozenInstanceError
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from belief.intelligence import (
    GITHUB_API_VERSION,
    GITHUB_GLOBAL_ADVISORIES_URL,
    HTTPStatusTransportError,
    HTTPFetchRequest,
    HTTPFetchResponse,
    IntelligenceSchemaError,
    InvalidTransportResponseError,
    LicenseMetadata,
    MalformedIntelligenceJSONError,
    NVD_CVE_API_URL,
    NetworkTransportError,
    PaginationMetadata,
    ResponseTooLargeError,
    TransportTimeoutError,
    build_cisa_kev_request,
    build_github_advisory_request,
    build_nvd_cve_request,
    build_osv_query_request,
    canonical_json_sha256,
    concatenate_context_records,
    fetch_http_response,
    parse_cisa_kev_catalog,
    parse_github_advisory_response,
    parse_nvd_cve_response,
    parse_osv_query_response,
)


RETRIEVED_AT = "2026-08-23T12:00:00Z"
OSV_URL = "https://api.osv.dev/v1/query"
CISA_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = NVD_CVE_API_URL
GITHUB_URL = GITHUB_GLOBAL_ADVISORIES_URL


def test_pagination_metadata_preserves_legacy_projection_and_unknown_is_fail_closed():
    legacy = PaginationMetadata(
        mode="cursor",
        request_position=None,
        next_position=None,
        page_size=1,
        provider_total=None,
        page_complete=True,
        collection_complete=True,
    )
    assert legacy.collection_status == "complete"
    assert legacy.requested_page_size == 1

    unknown = PaginationMetadata(
        mode="cursor",
        request_position=None,
        next_position=None,
        page_size=1,
        provider_total=None,
        page_complete=True,
        collection_complete=False,
        collection_status="unknown",
        requested_page_size=100,
    )
    assert unknown.collection_complete is False
    with pytest.raises(ValueError, match="unknown collection status"):
        PaginationMetadata(
            mode="cursor",
            request_position=None,
            next_position="cursor_2",
            page_size=1,
            provider_total=None,
            page_complete=True,
            collection_complete=False,
            collection_status="unknown",
            requested_page_size=100,
        )


@pytest.fixture
def osv_query() -> dict:
    return {
        "version": "1.0.0",
        "package": {"name": "example", "ecosystem": "PyPI"},
    }


@pytest.fixture
def osv_response_bytes() -> bytes:
    return json.dumps(
        {
            "vulns": [
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2026-0001"],
                    "published": "2026-08-19T00:00:00Z",
                    "modified": "2026-08-22T00:00:00Z",
                    "summary": "First provider statement",
                    "affected": [],
                    "references": [
                        {"type": "ADVISORY", "url": "https://osv.dev/vulnerability/test"}
                    ],
                },
                {
                    "id": "GHSA-aaaa-bbbb-cccc",
                    "aliases": ["CVE-2026-0001"],
                    "published": "2026-08-20T00:00:00Z",
                    "modified": "2026-08-22T01:00:00Z",
                    "summary": "Conflicting duplicate provider statement",
                    "affected": [],
                },
            ]
        },
        separators=(",", ":"),
    ).encode("utf-8")


@pytest.fixture
def cisa_query() -> dict:
    return {"catalog": "known_exploited_vulnerabilities", "format": "json"}


@pytest.fixture
def cisa_response_bytes() -> bytes:
    vulnerability = {
        "cveID": "CVE-2026-0001",
        "vendorProject": "Example Vendor",
        "product": "Example Product",
        "vulnerabilityName": "CISA catalog statement",
        "dateAdded": "2026-08-21",
        "shortDescription": "Observed catalog text only.",
        "requiredAction": "Apply vendor mitigations.",
        "dueDate": "2026-09-01",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "",
        "cwes": ["CWE-79"],
    }
    conflicting_duplicate = dict(vulnerability)
    conflicting_duplicate["requiredAction"] = "Remove the affected component."
    return json.dumps(
        {
            "title": "CISA Known Exploited Vulnerabilities Catalog",
            "catalogVersion": "2026.08.22",
            "dateReleased": "2026.08.22",
            "count": 2,
            "vulnerabilities": [vulnerability, conflicting_duplicate],
        },
        separators=(",", ":"),
    ).encode("utf-8")


@pytest.fixture
def nvd_query() -> dict:
    return {
        "cveIds": ["CVE-2026-0001"],
        "resultsPerPage": 1,
        "startIndex": 0,
    }


@pytest.fixture
def nvd_response_bytes() -> bytes:
    return json.dumps(
        {
            "resultsPerPage": 1,
            "startIndex": 0,
            "totalResults": 1,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-08-23T11:59:58.125",
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-0001",
                        "sourceIdentifier": "security@example.test",
                        "published": "2026-08-19T00:00:00.000",
                        "lastModified": "2026-08-22T00:00:00.500",
                        "vulnStatus": "Analyzed",
                        "descriptions": [
                            {"lang": "fr", "value": "Description fournisseur."},
                            {"lang": "en", "value": "NVD provider statement"},
                        ],
                        "metrics": {},
                        "weaknesses": [],
                        "configurations": [],
                        "references": [],
                    }
                }
            ],
        },
        separators=(",", ":"),
    ).encode("utf-8")


@pytest.fixture
def github_query() -> dict:
    return {
        "cve_id": "CVE-2026-0001",
        "type": "reviewed",
        "per_page": 1,
    }


@pytest.fixture
def github_response_bytes() -> bytes:
    return _github_response_bytes()


def _github_response_bytes() -> bytes:
    return json.dumps(
        [
            {
                "ghsa_id": "GHSA-2345-cfgh-jmpq",
                "cve_id": "CVE-2026-0001",
                "summary": "GitHub provider statement",
                "description": "Context only.",
                "type": "reviewed",
                "severity": "high",
                "identifiers": [
                    {"type": "GHSA", "value": "GHSA-2345-cfgh-jmpq"},
                    {"type": "CVE", "value": "CVE-2026-0001"},
                ],
                "references": ["https://example.test/advisory"],
                "published_at": "2026-08-19T00:00:00Z",
                "updated_at": "2026-08-22T00:00:00Z",
                "withdrawn_at": None,
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "pip", "name": "example"},
                        "vulnerable_version_range": "< 2.0",
                        "first_patched_version": "2.0",
                    }
                ],
                "cvss_severities": {},
                "cwes": [{"cwe_id": "CWE-79", "name": "XSS"}],
                "credits": [],
            }
        ],
        separators=(",", ":"),
    ).encode("utf-8")


def _github_headers(*, link: str | None = None) -> tuple[tuple[str, str], ...]:
    headers = [
        ("Content-Type", "application/json; charset=utf-8"),
        ("X-GitHub-Api-Version-Selected", GITHUB_API_VERSION),
        ("X-RateLimit-Limit", "60"),
        ("X-RateLimit-Remaining", "59"),
        ("X-RateLimit-Used", "1"),
        ("X-RateLimit-Reset", "1787529079"),
        ("X-RateLimit-Resource", "core"),
    ]
    if link is not None:
        headers.append(("Link", link))
    return tuple(headers)


def test_osv_happy_path_is_immutable_context_only_with_full_provenance(
    osv_query,
    osv_response_bytes,
):
    license_metadata = LicenseMetadata(
        identifier="source-policy-license",
        status="declared",
        terms_url="https://example.test/license",
        attribution="Example attribution",
    )

    batch = parse_osv_query_response(
        osv_response_bytes,
        query=osv_query,
        source_url=OSV_URL,
        retrieved_at_utc=RETRIEVED_AT,
        license_metadata=license_metadata,
        freshness_max_age_seconds=2 * 24 * 60 * 60,
    )

    assert batch.classification == "context_only"
    assert batch.proof_eligible is False
    assert batch.parser_status == "parsed"
    assert len(batch.records) == 2
    first = batch.records[0]
    assert first.provider == "osv"
    assert first.source_url == OSV_URL
    assert first.record_id == "GHSA-aaaa-bbbb-cccc"
    assert first.identifiers == ("GHSA-aaaa-bbbb-cccc", "CVE-2026-0001")
    assert first.normalized_query_sha256 == canonical_json_sha256(osv_query)
    assert first.retrieved_at_utc == RETRIEVED_AT
    assert first.source_revision == "2026-08-22T00:00:00Z"
    assert first.raw_response_sha256 == hashlib.sha256(osv_response_bytes).hexdigest()
    assert first.freshness.state == "fresh"
    assert first.license == license_metadata
    assert first.parser_status == "parsed"
    assert first.classification == "context_only"
    assert first.proof_eligible is False
    assert not hasattr(first, "to_finding")
    assert not hasattr(first, "to_audit_case")

    with pytest.raises(FrozenInstanceError):
        first.summary = "mutated"
    detached = first.payload()
    detached["summary"] = "mutated detached value"
    assert first.payload()["summary"] == "First provider statement"


def test_cisa_happy_path_retains_catalog_revision_and_unknown_license(
    cisa_query,
    cisa_response_bytes,
):
    batch = parse_cisa_kev_catalog(
        cisa_response_bytes,
        query=cisa_query,
        source_url=CISA_URL,
        retrieved_at_utc=RETRIEVED_AT,
        freshness_max_age_seconds=2 * 24 * 60 * 60,
    )

    assert batch.source_revision == "2026.08.22"
    assert batch.license.identifier == "unknown"
    assert batch.license.status == "unknown"
    assert [record.record_id for record in batch.records] == [
        "CVE-2026-0001",
        "CVE-2026-0001",
    ]
    assert [record.occurrence_index for record in batch.records] == [0, 1]
    assert batch.records[0].freshness.basis == "source_modified_at"
    assert (
        batch.records[0].payload()["requiredAction"]
        != (batch.records[1].payload()["requiredAction"])
    )


def test_duplicate_and_mirrored_cve_occurrences_never_merge_or_become_proof(
    osv_query,
    osv_response_bytes,
    cisa_query,
    cisa_response_bytes,
):
    osv = parse_osv_query_response(
        osv_response_bytes,
        query=osv_query,
        source_url=OSV_URL,
        retrieved_at_utc=RETRIEVED_AT,
    )
    cisa = parse_cisa_kev_catalog(
        cisa_response_bytes,
        query=cisa_query,
        source_url=CISA_URL,
        retrieved_at_utc=RETRIEVED_AT,
    )

    combined = concatenate_context_records(osv, cisa)

    assert len(combined) == 4
    assert [record.provider for record in combined] == [
        "osv",
        "osv",
        "cisa_kev",
        "cisa_kev",
    ]
    assert all(record.classification == "context_only" for record in combined)
    assert all(record.proof_eligible is False for record in combined)


def test_canonical_query_hash_and_parse_result_are_idempotent(osv_response_bytes):
    first_query = {
        "version": "1.0.0",
        "package": {"name": "example", "ecosystem": "PyPI"},
    }
    reordered_query = {
        "package": {"ecosystem": "PyPI", "name": "example"},
        "version": "1.0.0",
    }

    first = parse_osv_query_response(
        osv_response_bytes,
        query=first_query,
        source_url=OSV_URL,
        retrieved_at_utc=RETRIEVED_AT,
    )
    second = parse_osv_query_response(
        osv_response_bytes,
        query=reordered_query,
        source_url=OSV_URL,
        retrieved_at_utc=RETRIEVED_AT,
    )

    assert canonical_json_sha256(first_query) == canonical_json_sha256(reordered_query)
    assert first == second
    assert first.to_dict() == second.to_dict()


@pytest.mark.parametrize(
    "parser,raw,query,url",
    [
        (parse_osv_query_response, b'{"vulns":[}', {"package": {}}, OSV_URL),
        (
            parse_cisa_kev_catalog,
            b'{"title":"one","title":"two"}',
            {"catalog": "kev"},
            CISA_URL,
        ),
    ],
)
def test_malformed_or_ambiguous_json_has_explicit_parser_status(parser, raw, query, url):
    with pytest.raises(MalformedIntelligenceJSONError) as raised:
        parser(raw, query=query, source_url=url, retrieved_at_utc=RETRIEVED_AT)

    assert raised.value.parser_status == "malformed_json"


@pytest.mark.parametrize(
    "parser,raw,query,url,expected_path",
    [
        (
            parse_osv_query_response,
            b'{"vulns":[{"summary":"missing id"}]}',
            {"package": {}},
            OSV_URL,
            "$.vulns[0].id",
        ),
        (
            parse_cisa_kev_catalog,
            b'{"title":"KEV","catalogVersion":"1","dateReleased":"2026.08.22",'
            b'"vulnerabilities":{}}',
            {"catalog": "kev"},
            CISA_URL,
            "$.vulnerabilities",
        ),
    ],
)
def test_schema_failures_are_typed_and_never_silently_empty(
    parser,
    raw,
    query,
    url,
    expected_path,
):
    with pytest.raises(IntelligenceSchemaError) as raised:
        parser(raw, query=query, source_url=url, retrieved_at_utc=RETRIEVED_AT)

    assert raised.value.parser_status == "invalid_schema"
    assert raised.value.path == expected_path


def test_valid_empty_osv_response_is_explicitly_parsed_empty(osv_query):
    batch = parse_osv_query_response(
        b'{"vulns":[]}',
        query=osv_query,
        source_url=OSV_URL,
        retrieved_at_utc=RETRIEVED_AT,
    )

    assert batch.parser_status == "parsed_empty"
    assert batch.records == ()


def test_osv_response_with_pagination_token_is_rejected_as_incomplete(osv_query):
    with pytest.raises(IntelligenceSchemaError) as raised:
        parse_osv_query_response(
            b'{"vulns":[],"next_page_token":"more-results"}',
            query=osv_query,
            source_url=OSV_URL,
            retrieved_at_utc=RETRIEVED_AT,
        )

    assert raised.value.path == "$.next_page_token"


def test_cisa_declared_count_must_match_catalog_rows(cisa_query):
    raw = (
        b'{"title":"KEV","catalogVersion":"1","dateReleased":"2026-08-22",'
        b'"count":1,"vulnerabilities":[]}'
    )

    with pytest.raises(IntelligenceSchemaError) as raised:
        parse_cisa_kev_catalog(
            raw,
            query=cisa_query,
            source_url=CISA_URL,
            retrieved_at_utc=RETRIEVED_AT,
        )

    assert raised.value.path == "$.count"


def test_cisa_catalog_without_count_is_rejected_as_incomplete(cisa_query):
    raw = b'{"title":"KEV","catalogVersion":"1","dateReleased":"2026-08-22","vulnerabilities":[]}'

    with pytest.raises(IntelligenceSchemaError) as raised:
        parse_cisa_kev_catalog(
            raw,
            query=cisa_query,
            source_url=CISA_URL,
            retrieved_at_utc=RETRIEVED_AT,
        )

    assert raised.value.path == "$.count"


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        content_length: int | None = None,
        final_url: str | None = None,
    ):
        self._body = body
        self.status = status
        self.closed = False
        self.final_url = final_url
        self.headers = Message()
        self.headers["Content-Type"] = "application/json"
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def read(self, size: int) -> bytes:
        return self._body[:size]

    def close(self) -> None:
        self.closed = True

    def geturl(self) -> str:
        return self.final_url or OSV_URL


def test_live_transport_is_injectable_bounded_and_sets_user_agent(osv_query):
    request = build_osv_query_request(
        osv_query,
        timeout_seconds=3,
        max_response_bytes=1024,
        user_agent="BELIEF-tests/1",
    )
    response = _FakeResponse(b'{"vulns":[]}', content_length=12)
    response.headers["Set-Cookie"] = "transport-secret"
    observed = {}

    def opener(wire_request, timeout):
        observed["method"] = wire_request.get_method()
        observed["user_agent"] = wire_request.get_header("User-agent")
        observed["timeout"] = timeout
        observed["body"] = wire_request.data
        return response

    fetched = fetch_http_response(
        request,
        opener=opener,
        clock=lambda: RETRIEVED_AT,
    )

    assert fetched.body == b'{"vulns":[]}'
    assert fetched.retrieved_at_utc == RETRIEVED_AT
    assert fetched.headers == (("content-type", "application/json"),)
    assert "transport-secret" not in repr(fetched)
    assert observed == {
        "method": "POST",
        "user_agent": "BELIEF-tests/1",
        "timeout": 3.0,
        "body": b'{"package":{"ecosystem":"PyPI","name":"example"},"version":"1.0.0"}',
    }
    assert response.closed is True


def test_live_transport_raises_typed_oversize_without_returning_bytes():
    request = build_cisa_kev_request(
        timeout_seconds=3,
        max_response_bytes=4,
        user_agent="BELIEF-tests/1",
    )
    response = _FakeResponse(b"12345", final_url=CISA_URL)

    with pytest.raises(ResponseTooLargeError) as raised:
        fetch_http_response(request, opener=lambda _request, _timeout: response)

    assert raised.value.error_code == "response_too_large"
    assert raised.value.max_response_bytes == 4
    assert response.closed is True


def test_live_transport_raises_typed_http_network_and_timeout_failures():
    request = build_cisa_kev_request(
        timeout_seconds=3,
        max_response_bytes=1024,
        user_agent="BELIEF-tests/1",
    )

    def http_failure(_request, _timeout):
        raise HTTPError(request.url, 503, "unavailable", {}, None)

    def network_failure(_request, _timeout):
        raise URLError("offline")

    def timeout_failure(_request, _timeout):
        raise TimeoutError("timed out")

    with pytest.raises(HTTPStatusTransportError) as http_raised:
        fetch_http_response(request, opener=http_failure)
    with pytest.raises(NetworkTransportError) as network_raised:
        fetch_http_response(request, opener=network_failure)
    with pytest.raises(TransportTimeoutError) as timeout_raised:
        fetch_http_response(request, opener=timeout_failure)

    assert http_raised.value.status_code == 503
    assert network_raised.value.error_code == "network_error"
    assert timeout_raised.value.error_code == "timeout"


def test_live_transport_rejects_unregistered_urls_and_redirected_responses():
    with pytest.raises(ValueError, match="registered intelligence endpoint"):
        HTTPFetchRequest(
            url="https://example.test/feed.json",
            method="GET",
            timeout_seconds=3,
            max_response_bytes=1024,
            user_agent="BELIEF-tests/1",
        )

    request = build_cisa_kev_request(
        timeout_seconds=3,
        max_response_bytes=1024,
        user_agent="BELIEF-tests/1",
    )
    response = _FakeResponse(
        b"{}",
        final_url="https://example.test/redirected.json",
    )
    with pytest.raises(InvalidTransportResponseError) as raised:
        fetch_http_response(request, opener=lambda _request, _timeout: response)

    assert raised.value.error_code == "invalid_response"
    assert response.closed is True


def test_request_bounds_and_user_agent_are_mandatory(osv_query):
    with pytest.raises(TypeError):
        build_osv_query_request(osv_query)
    with pytest.raises(ValueError, match="timeout_seconds"):
        build_osv_query_request(
            osv_query,
            timeout_seconds=31,
            max_response_bytes=1024,
            user_agent="BELIEF-tests/1",
        )
    with pytest.raises(ValueError, match="user_agent"):
        build_osv_query_request(
            osv_query,
            timeout_seconds=3,
            max_response_bytes=1024,
            user_agent="",
        )


def test_nvd_adapter_is_context_only_complete_and_normalizes_documented_utc(
    nvd_query,
    nvd_response_bytes,
):
    request = build_nvd_cve_request(
        nvd_query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
        api_key="nvd-secret-value",
    )
    assert request.url.startswith(f"{NVD_URL}?cveIds=CVE-2026-0001")
    assert "nvd-secret-value" not in repr(request)
    assert "nvd-secret-value" not in request.url
    assert all(name.lower() != "apikey" for name, _value in request.headers)

    response = HTTPFetchResponse(
        source_url=request.url,
        status_code=200,
        retrieved_at_utc=RETRIEVED_AT,
        body=nvd_response_bytes,
        headers=(("Content-Type", "application/json"),),
    )
    page = parse_nvd_cve_response(
        response,
        query=nvd_query,
        freshness_max_age_seconds=2 * 24 * 60 * 60,
    )

    assert page.classification == "context_only"
    assert page.proof_eligible is False
    assert page.schema_version == "belief.external_intelligence_page.v2"
    assert page.api_contract_version == "NVD_CVE/2.0"
    assert page.pagination.to_dict() == {
        "mode": "offset",
        "request_position": 0,
        "next_position": None,
        "page_size": 1,
        "provider_total": 1,
        "page_complete": True,
        "collection_complete": True,
        "collection_status": "complete",
        "requested_page_size": 1,
    }
    assert page.raw_response_bytes == len(nvd_response_bytes)
    assert page.rate_limit.policy_limit is None
    assert page.rate_limit.policy_window_seconds is None
    assert page.response_generated_at_utc == "2026-08-23T11:59:58.125000Z"
    record = page.batch.records[0]
    assert record.provider == "nvd_cve"
    assert record.record_id == "CVE-2026-0001"
    assert record.summary == "NVD provider statement"
    assert record.source_revision == "2026-08-22T00:00:00.500000Z"
    assert record.freshness.state == "fresh"
    assert record.license.identifier == "NIST-PUBLIC-DOMAIN-US"
    assert record.payload()["lastModified"] == "2026-08-22T00:00:00.500"
    assert not hasattr(record, "to_finding")
    serialized = json.dumps(page.to_dict(), sort_keys=True)
    assert "nvd-secret-value" not in serialized
    assert "reportability" not in serialized


def test_nvd_adapter_retains_incomplete_collection_offset(nvd_response_bytes):
    query = {
        "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
        "resultsPerPage": 1,
        "startIndex": 0,
    }
    payload = json.loads(nvd_response_bytes)
    payload["totalResults"] = 2
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    request = build_nvd_cve_request(
        query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
    )
    page = parse_nvd_cve_response(
        HTTPFetchResponse(
            source_url=request.url,
            status_code=200,
            retrieved_at_utc=RETRIEVED_AT,
            body=body,
            headers=(("Content-Type", "application/json"),),
        ),
        query=query,
    )

    assert page.pagination.collection_complete is False
    assert page.pagination.collection_status == "incomplete"
    assert page.pagination.next_position == 1
    assert page.pagination.provider_total == 2


def test_github_adapter_retains_cursor_rate_limit_license_and_version(
    github_query,
    github_response_bytes,
):
    request = build_github_advisory_request(
        github_query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
        token="github-secret-value",
    )
    assert request.url.startswith(f"{GITHUB_URL}?cve_id=CVE-2026-0001")
    assert "github-secret-value" not in repr(request)
    assert "github-secret-value" not in request.url
    assert all(name.lower() != "authorization" for name, _value in request.headers)

    page = parse_github_advisory_response(
        HTTPFetchResponse(
            source_url=request.url,
            status_code=200,
            retrieved_at_utc=RETRIEVED_AT,
            body=github_response_bytes,
            headers=(*_github_headers(), ("Set-Cookie", "provider-secret")),
        ),
        query=github_query,
    )

    assert page.classification == "context_only"
    assert page.proof_eligible is False
    assert page.api_contract_version == GITHUB_API_VERSION
    assert page.pagination.mode == "cursor"
    assert page.pagination.collection_complete is False
    assert page.pagination.collection_status == "unknown"
    assert page.pagination.next_position is None
    assert page.rate_limit.observed_limit == 60
    assert page.rate_limit.policy_limit is None
    assert page.rate_limit.policy_window_seconds is None
    assert page.rate_limit.remaining == 59
    assert page.rate_limit.used == 1
    assert page.rate_limit.resource == "core"
    record = page.batch.records[0]
    assert record.record_id == "GHSA-2345-cfgh-jmpq"
    assert record.identifiers == ("GHSA-2345-cfgh-jmpq", "CVE-2026-0001")
    assert record.license.identifier == "CC-BY-4.0"
    assert record.classification == "context_only"
    assert record.proof_eligible is False
    serialized = json.dumps(page.to_dict(), sort_keys=True)
    assert "github-secret-value" not in serialized
    assert "provider-secret" not in serialized
    assert "reportability" not in serialized


def test_provider_quota_policy_cannot_be_reclassified_by_auth_boolean():
    assert "authenticated" not in inspect.signature(parse_nvd_cve_response).parameters
    assert "authenticated" not in inspect.signature(parse_github_advisory_response).parameters


def test_github_modified_filter_matches_published_or_updated_semantics():
    query = {
        "modified": "2026-08-18..2026-08-20",
        "type": "reviewed",
        "per_page": 1,
    }
    request = build_github_advisory_request(
        query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
    )
    payload = json.loads(_github_response_bytes())

    published_match = copy.deepcopy(payload)
    published_match[0]["published_at"] = "2026-08-19T00:00:00Z"
    published_match[0]["updated_at"] = "2026-08-22T00:00:00Z"
    updated_match = copy.deepcopy(payload)
    updated_match[0]["published_at"] = "2026-08-01T00:00:00Z"
    updated_match[0]["updated_at"] = "2026-08-19T00:00:00Z"

    for matching_payload in (published_match, updated_match):
        page = parse_github_advisory_response(
            HTTPFetchResponse(
                source_url=request.url,
                status_code=200,
                retrieved_at_utc=RETRIEVED_AT,
                body=json.dumps(
                    matching_payload,
                    separators=(",", ":"),
                ).encode("utf-8"),
                headers=_github_headers(),
            ),
            query=query,
        )
        assert page.batch.records[0].record_id == "GHSA-2345-cfgh-jmpq"


def test_github_adapter_validates_and_retains_only_the_next_cursor(github_response_bytes):
    query = {
        "modified": "2026-08-01..2026-08-23",
        "type": "reviewed",
        "direction": "asc",
        "sort": "updated",
        "per_page": 1,
    }
    next_query = dict(query, after="cursor_2")
    request = build_github_advisory_request(
        query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
    )
    next_request = build_github_advisory_request(
        next_query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
    )
    link = f'<{next_request.url}>; rel="next"'
    page = parse_github_advisory_response(
        HTTPFetchResponse(
            source_url=request.url,
            status_code=200,
            retrieved_at_utc=RETRIEVED_AT,
            body=github_response_bytes,
            headers=_github_headers(link=link),
        ),
        query=query,
    )

    assert page.pagination.collection_complete is False
    assert page.pagination.collection_status == "incomplete"
    assert page.pagination.request_position is None
    assert page.pagination.next_position == "cursor_2"
    assert page.selected_response_headers_sha256 == canonical_json_sha256(
        [list(item) for item in page.selected_response_headers]
    )


def test_github_adapter_rejects_cross_host_or_non_advancing_next_link(
    github_query,
    github_response_bytes,
):
    request = build_github_advisory_request(
        github_query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
    )
    for link in (
        '<https://api.github.com.evil.example/advisories?after=x>; rel="next"',
        f'<{request.url}>; rel="next"',
    ):
        response = HTTPFetchResponse(
            source_url=request.url,
            status_code=200,
            retrieved_at_utc=RETRIEVED_AT,
            body=github_response_bytes,
            headers=_github_headers(link=link),
        )
        with pytest.raises(IntelligenceSchemaError) as raised:
            parse_github_advisory_response(response, query=github_query)
        assert raised.value.path == "$.headers.link"


def test_provider_query_policies_reject_unbounded_deprecated_or_ambiguous_inputs():
    common = {
        "timeout_seconds": 3,
        "max_response_bytes": 4096,
        "user_agent": "BELIEF-tests/1",
    }
    with pytest.raises(ValueError, match="cveIds or"):
        build_nvd_cve_request({}, **common)
    with pytest.raises(ValueError, match="unsupported parameters"):
        build_nvd_cve_request({"cveId": "CVE-2026-0001"}, **common)
    with pytest.raises(ValueError, match="duplicates"):
        build_nvd_cve_request({"cveIds": ["CVE-2026-0001", "CVE-2026-0001"]}, **common)
    with pytest.raises(ValueError, match="require"):
        build_github_advisory_request({"type": "reviewed"}, **common)
    with pytest.raises(ValueError, match="unsupported parameters"):
        build_github_advisory_request(
            {"cve_id": "CVE-2026-0001", "redirect": "https://example.test"},
            **common,
        )
    with pytest.raises(ValueError, match="registered intelligence endpoint"):
        HTTPFetchRequest(
            url=(
                "https://api.github.com.evil.example/advisories"
                "?cve_id=CVE-2026-0001&type=reviewed&direction=desc&per_page=1&sort=published"
            ),
            method="GET",
            timeout_seconds=3,
            max_response_bytes=4096,
            user_agent="BELIEF-tests/1",
        )
    valid_nvd = build_nvd_cve_request({"cveIds": ["CVE-2026-0001"]}, **common)
    with pytest.raises(ValueError, match="unsupported public request header"):
        HTTPFetchRequest(
            url=valid_nvd.url,
            method="GET",
            timeout_seconds=3,
            max_response_bytes=4096,
            user_agent="BELIEF-tests/1",
            headers=(("Accept", "application/json"), ("Host", "example.test")),
        )


def test_provider_parsers_enforce_page_cardinality_bounds(
    nvd_query,
    nvd_response_bytes,
    github_query,
    github_response_bytes,
):
    nvd_payload = json.loads(nvd_response_bytes)
    nvd_payload["resultsPerPage"] = 2001
    nvd_request = build_nvd_cve_request(
        nvd_query,
        timeout_seconds=3,
        max_response_bytes=1024 * 1024,
        user_agent="BELIEF-tests/1",
    )
    with pytest.raises(IntelligenceSchemaError) as nvd_raised:
        parse_nvd_cve_response(
            HTTPFetchResponse(
                source_url=nvd_request.url,
                status_code=200,
                retrieved_at_utc=RETRIEVED_AT,
                body=json.dumps(nvd_payload).encode("utf-8"),
                headers=(("Content-Type", "application/json"),),
            ),
            query=nvd_query,
        )
    assert nvd_raised.value.path == "$.resultsPerPage"

    github_payload = json.loads(github_response_bytes)
    github_payload *= 101
    bounded_query = dict(github_query, per_page=100)
    github_request = build_github_advisory_request(
        bounded_query,
        timeout_seconds=3,
        max_response_bytes=1024 * 1024,
        user_agent="BELIEF-tests/1",
    )
    with pytest.raises(IntelligenceSchemaError) as github_raised:
        parse_github_advisory_response(
            HTTPFetchResponse(
                source_url=github_request.url,
                status_code=200,
                retrieved_at_utc=RETRIEVED_AT,
                body=json.dumps(github_payload).encode("utf-8"),
                headers=_github_headers(),
            ),
            query=bounded_query,
        )
    assert github_raised.value.path == "$"


def test_github_adapter_rejects_wrong_contract_version_and_partial_rate_state(
    github_query,
    github_response_bytes,
):
    request = build_github_advisory_request(
        github_query,
        timeout_seconds=3,
        max_response_bytes=4096,
        user_agent="BELIEF-tests/1",
    )
    wrong_version = tuple(
        (name, "2022-11-28") if name == "X-GitHub-Api-Version-Selected" else (name, value)
        for name, value in _github_headers()
    )
    with pytest.raises(IntelligenceSchemaError) as version_raised:
        parse_github_advisory_response(
            HTTPFetchResponse(
                source_url=request.url,
                status_code=200,
                retrieved_at_utc=RETRIEVED_AT,
                body=github_response_bytes,
                headers=wrong_version,
            ),
            query=github_query,
        )
    assert version_raised.value.path == "$.headers.x-github-api-version-selected"

    partial_rate = (
        ("Content-Type", "application/json"),
        ("X-GitHub-Api-Version-Selected", GITHUB_API_VERSION),
        ("X-RateLimit-Limit", "60"),
    )
    with pytest.raises(IntelligenceSchemaError) as rate_raised:
        parse_github_advisory_response(
            HTTPFetchResponse(
                source_url=request.url,
                status_code=200,
                retrieved_at_utc=RETRIEVED_AT,
                body=github_response_bytes,
                headers=partial_rate,
            ),
            query=github_query,
        )
    assert rate_raised.value.path == "$.headers"


def test_secret_headers_reach_wire_only_and_redirects_still_fail_closed(nvd_query):
    request = build_nvd_cve_request(
        nvd_query,
        timeout_seconds=3,
        max_response_bytes=1024,
        user_agent="BELIEF-tests/1",
        api_key="wire-only-secret",
    )
    observed = {}

    def opener(wire_request, _timeout):
        observed["api_key"] = wire_request.get_header("Apikey")
        return _FakeResponse(b"{}", final_url=request.url)

    fetched = fetch_http_response(request, opener=opener, clock=lambda: RETRIEVED_AT)
    assert fetched.body == b"{}"
    assert observed == {"api_key": "wire-only-secret"}

    redirected = _FakeResponse(
        b"{}",
        final_url=(
            "https://services.nvd.nist.gov.evil.example/rest/json/cves/2.0"
            "?cveIds=CVE-2026-0001&resultsPerPage=1&startIndex=0"
        ),
    )
    with pytest.raises(InvalidTransportResponseError):
        fetch_http_response(request, opener=lambda _request, _timeout: redirected)
