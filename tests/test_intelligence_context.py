from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from email.message import Message
from urllib.error import HTTPError, URLError

import pytest

from belief.intelligence import (
    HTTPStatusTransportError,
    HTTPFetchRequest,
    IntelligenceSchemaError,
    InvalidTransportResponseError,
    LicenseMetadata,
    MalformedIntelligenceJSONError,
    NetworkTransportError,
    ResponseTooLargeError,
    TransportTimeoutError,
    build_cisa_kev_request,
    build_osv_query_request,
    canonical_json_sha256,
    concatenate_context_records,
    fetch_http_response,
    parse_cisa_kev_catalog,
    parse_osv_query_response,
)


RETRIEVED_AT = "2026-08-23T12:00:00Z"
OSV_URL = "https://api.osv.dev/v1/query"
CISA_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
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
    assert batch.records[0].payload()["requiredAction"] != (
        batch.records[1].payload()["requiredAction"]
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
    raw = (
        b'{"title":"KEV","catalogVersion":"1","dateReleased":"2026-08-22",'
        b'"vulnerabilities":[]}'
    )

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
