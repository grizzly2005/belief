from __future__ import annotations

import json
from dataclasses import replace
from urllib.parse import parse_qs, urlsplit

import pytest

from belief.intelligence import (
    GITHUB_API_VERSION,
    CollectionIncompleteError,
    CollectionIntegrityError,
    CollectionLimits,
    HTTPFetchRequest,
    HTTPFetchResponse,
    assemble_context_collection,
    build_github_advisory_request,
    collect_github_advisories,
    collect_nvd_cves,
)
from belief.intelligence.canonical import canonical_json_sha256


RETRIEVED_AT = "2026-08-23T12:00:00Z"
USER_AGENT = "BELIEF-collection-tests/1"


def _limits(
    *,
    pages: int = 5,
    records: int = 10,
    total_bytes: int = 32_768,
    response_bytes: int = 8_192,
) -> CollectionLimits:
    return CollectionLimits(
        max_pages=pages,
        max_records=records,
        max_total_response_bytes=total_bytes,
        max_response_bytes=response_bytes,
    )


def _nvd_body(
    *,
    start: int,
    total: int,
    identifiers: list[str],
    generated_at: str = "2026-08-23T11:59:58.125",
) -> bytes:
    vulnerabilities = []
    for identifier in identifiers:
        vulnerabilities.append(
            {
                "cve": {
                    "id": identifier,
                    "sourceIdentifier": "security@example.test",
                    "published": "2026-08-19T00:00:00.000",
                    "lastModified": "2026-08-22T00:00:00.500",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": f"Provider statement {identifier}"}],
                    "metrics": {},
                    "weaknesses": [],
                    "configurations": [],
                    "references": [],
                }
            }
        )
    return json.dumps(
        {
            "resultsPerPage": len(vulnerabilities),
            "startIndex": start,
            "totalResults": total,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": generated_at,
            "vulnerabilities": vulnerabilities,
        },
        separators=(",", ":"),
    ).encode("utf-8")


def _nvd_response(request: HTTPFetchRequest, body: bytes) -> HTTPFetchResponse:
    return HTTPFetchResponse(
        source_url=request.url,
        status_code=200,
        retrieved_at_utc=RETRIEVED_AT,
        body=body,
        headers=(("Content-Type", "application/json"),),
    )


def _nvd_two_page_fetcher(
    calls: list[HTTPFetchRequest],
    *,
    second_total: int = 2,
    duplicate_second: bool = False,
):
    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        calls.append(request)
        offset = int(parse_qs(urlsplit(request.url).query)["startIndex"][0])
        if offset == 0:
            body = _nvd_body(start=0, total=2, identifiers=["CVE-2026-0001"])
        else:
            identifier = "CVE-2026-0001" if duplicate_second else "CVE-2026-0002"
            body = _nvd_body(start=1, total=second_total, identifiers=[identifier])
        return _nvd_response(request, body)

    return fetch


def _github_body(identifier: str) -> bytes:
    return json.dumps(
        [
            {
                "ghsa_id": identifier,
                "cve_id": None,
                "summary": f"Provider statement {identifier}",
                "description": "Context only.",
                "type": "reviewed",
                "severity": "high",
                "identifiers": [{"type": "GHSA", "value": identifier}],
                "references": ["https://example.test/advisory"],
                "published_at": "2026-08-19T00:00:00Z",
                "updated_at": "2026-08-22T00:00:00Z",
                "withdrawn_at": None,
                "vulnerabilities": [],
                "cvss_severities": {},
                "cwes": [],
                "credits": [],
            }
        ],
        separators=(",", ":"),
    ).encode("utf-8")


def _github_headers(
    *,
    link: str | None = None,
    remaining: int = 59,
) -> tuple[tuple[str, str], ...]:
    headers = [
        ("Content-Type", "application/json"),
        ("X-GitHub-Api-Version-Selected", GITHUB_API_VERSION),
        ("X-RateLimit-Limit", "60"),
        ("X-RateLimit-Remaining", str(remaining)),
        ("X-RateLimit-Used", str(60 - remaining)),
        ("X-RateLimit-Reset", "1787529079"),
        ("X-RateLimit-Resource", "core"),
    ]
    if link is not None:
        headers.append(("Link", link))
    return tuple(headers)


def _github_response(
    request: HTTPFetchRequest,
    *,
    identifier: str,
    next_cursor: str | None,
    remaining: int = 59,
) -> HTTPFetchResponse:
    query = {
        "modified": "2026-08-01..2026-08-23",
        "type": "reviewed",
        "direction": "asc",
        "sort": "updated",
        "per_page": 1,
    }
    link = None
    if next_cursor is not None:
        next_request = build_github_advisory_request(
            dict(query, after=next_cursor),
            timeout_seconds=3,
            max_response_bytes=8192,
            user_agent=USER_AGENT,
        )
        link = f'<{next_request.url}>; rel="next"'
    return HTTPFetchResponse(
        source_url=request.url,
        status_code=200,
        retrieved_at_utc=RETRIEVED_AT,
        body=_github_body(identifier),
        headers=_github_headers(link=link, remaining=remaining),
    )


def _github_query() -> dict[str, object]:
    return {
        "modified": "2026-08-01..2026-08-23",
        "type": "reviewed",
        "direction": "asc",
        "sort": "updated",
        "per_page": 1,
    }


def test_collection_limits_are_mandatory_positive_and_hard_capped():
    with pytest.raises(ValueError, match="max_pages"):
        _limits(pages=0)
    with pytest.raises(ValueError, match="max_records"):
        _limits(records=10_001)
    with pytest.raises(ValueError, match="must not exceed"):
        _limits(total_bytes=1024, response_bytes=2048)


def test_nvd_collector_validates_two_page_continuity_and_terminal_total():
    calls: list[HTTPFetchRequest] = []
    collection = collect_nvd_cves(
        {
            "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
            "resultsPerPage": 1,
            "startIndex": 0,
        },
        limits=_limits(),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=_nvd_two_page_fetcher(calls),
    )

    assert len(calls) == 2
    assert collection.collection_status == "complete"
    assert collection.collection_complete is True
    assert collection.snapshot_consistency == "unverified"
    assert collection.provider_total == 2
    assert [record.record_id for record in collection.records] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]
    assert collection.total_response_bytes == sum(
        page.raw_response_bytes for page in collection.pages
    )
    assert collection.proof_eligible is False

    forged = replace(collection.pages[0], collection_query_sha256="0" * 64)
    with pytest.raises(CollectionIntegrityError, match="collection digest"):
        assemble_context_collection(forged, limits=_limits())

    forged_pagination = replace(
        collection.pages[0].pagination,
        requested_page_size=2,
    )
    forged_page_size = replace(collection.pages[0], pagination=forged_pagination)
    with pytest.raises(CollectionIntegrityError, match="request page size"):
        assemble_context_collection(forged_page_size, limits=_limits())

    forged_contract = replace(
        collection.pages[0],
        api_contract_version="forged-contract",
    )
    with pytest.raises(CollectionIntegrityError, match="contract version"):
        assemble_context_collection(forged_contract, limits=_limits())


def test_falsy_callable_fetcher_is_never_replaced_by_live_transport():
    body = _nvd_body(start=0, total=1, identifiers=["CVE-2026-0001"])

    class FalseyFetcher:
        def __init__(self) -> None:
            self.calls = 0

        def __bool__(self) -> bool:
            return False

        def __call__(self, request: HTTPFetchRequest) -> HTTPFetchResponse:
            self.calls += 1
            return _nvd_response(request, body)

    fetcher = FalseyFetcher()
    collection = collect_nvd_cves(
        {"cveIds": ["CVE-2026-0001"], "resultsPerPage": 1, "startIndex": 0},
        limits=_limits(),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetcher,
    )
    assert fetcher.calls == 1
    assert collection.collection_complete is True


def test_nvd_collector_shrinks_only_the_terminal_request_to_remaining_budget():
    calls: list[HTTPFetchRequest] = []

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        calls.append(request)
        query = parse_qs(urlsplit(request.url).query)
        offset = int(query["startIndex"][0])
        requested = int(query["resultsPerPage"][0])
        if offset == 0:
            assert requested == 2
            body = _nvd_body(
                start=0,
                total=3,
                identifiers=["CVE-2026-0001", "CVE-2026-0002"],
            )
        else:
            assert requested == 1
            body = _nvd_body(start=2, total=3, identifiers=["CVE-2026-0003"])
        return _nvd_response(request, body)

    collection = collect_nvd_cves(
        {
            "cveIds": ["CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003"],
            "resultsPerPage": 2,
            "startIndex": 0,
        },
        limits=_limits(records=3),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )
    assert len(calls) == 2
    assert [page.pagination.requested_page_size for page in collection.pages] == [2, 1]
    assert collection.provider_total == 3
    assert len(collection.records) == 3


def test_nvd_collector_accepts_short_nonterminal_pages_under_provider_maximum():
    calls: list[tuple[int, int]] = []
    rows = {
        0: ["CVE-2026-0001", "CVE-2026-0002"],
        2: ["CVE-2026-0003"],
        3: ["CVE-2026-0004"],
    }

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        query = parse_qs(urlsplit(request.url).query)
        offset = int(query["startIndex"][0])
        requested = int(query["resultsPerPage"][0])
        calls.append((offset, requested))
        return _nvd_response(
            request,
            _nvd_body(start=offset, total=4, identifiers=rows[offset]),
        )

    collection = collect_nvd_cves(
        {
            "cveIds": [
                "CVE-2026-0001",
                "CVE-2026-0002",
                "CVE-2026-0003",
                "CVE-2026-0004",
            ],
            "resultsPerPage": 3,
            "startIndex": 0,
        },
        limits=_limits(records=4),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )
    assert calls == [(0, 3), (2, 2), (3, 1)]
    assert collection.collection_complete is True
    assert len(collection.records) == 4


def test_nvd_collector_stops_at_page_and_record_limits_without_extra_fetch():
    page_calls: list[HTTPFetchRequest] = []
    with pytest.raises(CollectionIncompleteError) as page_error:
        collect_nvd_cves(
            {
                "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            limits=_limits(pages=1),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=_nvd_two_page_fetcher(page_calls),
        )
    assert page_error.value.reason == "max_pages"
    assert len(page_calls) == 1

    record_calls: list[HTTPFetchRequest] = []
    with pytest.raises(CollectionIncompleteError) as record_error:
        collect_nvd_cves(
            {
                "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            limits=_limits(records=1),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=_nvd_two_page_fetcher(record_calls),
        )
    assert record_error.value.reason == "max_records"
    assert len(record_calls) == 1


def test_nvd_collector_rejects_total_drift_and_duplicate_record_ids():
    drift_calls: list[HTTPFetchRequest] = []
    with pytest.raises(CollectionIntegrityError, match="provider total changed"):
        collect_nvd_cves(
            {
                "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=_nvd_two_page_fetcher(drift_calls, second_total=3),
        )
    assert len(drift_calls) == 2

    duplicate_calls: list[HTTPFetchRequest] = []
    with pytest.raises(CollectionIntegrityError, match="record_id repeated"):
        collect_nvd_cves(
            {
                "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=_nvd_two_page_fetcher(
                duplicate_calls,
                duplicate_second=True,
            ),
        )
    assert len(duplicate_calls) == 2


def test_response_byte_limit_accepts_exact_boundary_and_rejects_one_less():
    body = _nvd_body(start=0, total=1, identifiers=["CVE-2026-0001"])
    calls: list[HTTPFetchRequest] = []

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        calls.append(request)
        return _nvd_response(request, body)

    collection = collect_nvd_cves(
        {"cveIds": ["CVE-2026-0001"], "resultsPerPage": 1, "startIndex": 0},
        limits=_limits(total_bytes=len(body), response_bytes=len(body)),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )
    assert collection.total_response_bytes == len(body)

    with pytest.raises(CollectionIncompleteError) as raised:
        collect_nvd_cves(
            {"cveIds": ["CVE-2026-0001"], "resultsPerPage": 1, "startIndex": 0},
            limits=_limits(total_bytes=len(body) - 1, response_bytes=len(body) - 1),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=fetch,
        )
    assert raised.value.reason == "response_too_large"

    with pytest.raises(CollectionIncompleteError) as assembled_error:
        assemble_context_collection(
            *collection.pages,
            limits=_limits(
                total_bytes=len(body),
                response_bytes=1,
            ),
        )
    assert assembled_error.value.reason == "max_response_bytes"


def test_parse_failure_uses_stable_reason_and_counts_attempted_response_bytes():
    malformed = b'{"resultsPerPage":'

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        return _nvd_response(request, malformed)

    with pytest.raises(CollectionIncompleteError) as raised:
        collect_nvd_cves(
            {"cveIds": ["CVE-2026-0001"], "resultsPerPage": 1, "startIndex": 0},
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=fetch,
        )
    assert raised.value.reason == "malformed_json"
    assert raised.value.total_response_bytes == len(malformed)
    assert raised.value.page_count == 0


def test_nvd_collector_rejects_provider_generation_timestamp_regression():
    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        offset = int(parse_qs(urlsplit(request.url).query)["startIndex"][0])
        if offset == 0:
            body = _nvd_body(
                start=0,
                total=2,
                identifiers=["CVE-2026-0001"],
                generated_at="2026-08-23T12:00:00.000",
            )
        else:
            body = _nvd_body(
                start=1,
                total=2,
                identifiers=["CVE-2026-0002"],
                generated_at="2026-08-23T11:00:00.000",
            )
        return _nvd_response(request, body)

    with pytest.raises(CollectionIntegrityError, match="generation timestamp"):
        collect_nvd_cves(
            {
                "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=fetch,
        )


def test_nvd_collector_never_waits_or_refetches_after_retry_after():
    calls = 0

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        nonlocal calls
        calls += 1
        response = _nvd_response(
            request,
            _nvd_body(start=0, total=2, identifiers=["CVE-2026-0001"]),
        )
        return replace(
            response,
            headers=(
                ("Content-Type", "application/json"),
                ("Retry-After", "5"),
            ),
        )

    with pytest.raises(CollectionIncompleteError) as raised:
        collect_nvd_cves(
            {
                "cveIds": ["CVE-2026-0001", "CVE-2026-0002"],
                "resultsPerPage": 1,
                "startIndex": 0,
            },
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=fetch,
        )
    assert raised.value.reason == "retry_after_observed"
    assert raised.value.next_position == 1
    assert calls == 1


def test_github_absent_link_is_unknown_never_positive_completeness():
    calls: list[HTTPFetchRequest] = []

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        calls.append(request)
        return _github_response(
            request,
            identifier="GHSA-2345-cfgh-jmpq",
            next_cursor=None,
        )

    collection = collect_github_advisories(
        _github_query(),
        limits=_limits(),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )

    assert len(calls) == 1
    assert collection.collection_status == "unknown"
    assert collection.collection_complete is False
    assert collection.pages[0].pagination.collection_status == "unknown"
    assert collection.to_dict()["snapshot_consistency"] == "unverified"

    forged_rate = replace(collection.pages[0].rate_limit, remaining=1)
    forged_page = replace(collection.pages[0], rate_limit=forged_rate)
    with pytest.raises(CollectionIntegrityError, match="retained headers"):
        assemble_context_collection(forged_page, limits=_limits())


def test_github_link_without_next_remains_unknown_not_authenticated_finality():
    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        response = _github_response(
            request,
            identifier="GHSA-2345-cfgh-jmpq",
            next_cursor=None,
        )
        return replace(
            response,
            headers=(
                *_github_headers(),
                ("Link", f'<{request.url}>; rel="prev"'),
            ),
        )

    collection = collect_github_advisories(
        _github_query(),
        limits=_limits(),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )
    assert collection.collection_status == "unknown"
    assert collection.collection_complete is False


def test_github_next_position_is_bound_to_retained_link_header():
    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        cursor = parse_qs(urlsplit(request.url).query).get("after", [None])[0]
        return _github_response(
            request,
            identifier=("GHSA-2345-cfgh-jmpq" if cursor is None else "GHSA-3456-ghjm-pqrv"),
            next_cursor="cursor_a" if cursor is None else None,
        )

    collection = collect_github_advisories(
        _github_query(),
        limits=_limits(),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )
    forged_pagination = replace(
        collection.pages[0].pagination,
        next_position="cursor_b",
    )
    forged_first = replace(collection.pages[0], pagination=forged_pagination)
    with pytest.raises(CollectionIntegrityError, match="retained Link header"):
        assemble_context_collection(
            forged_first,
            collection.pages[1],
            limits=_limits(),
        )


def test_github_malformed_retained_link_has_precise_integrity_error():
    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        return _github_response(
            request,
            identifier="GHSA-2345-cfgh-jmpq",
            next_cursor=None,
        )

    collection = collect_github_advisories(
        _github_query(),
        limits=_limits(),
        timeout_seconds=3,
        user_agent=USER_AGENT,
        fetcher=fetch,
    )
    selected_headers = tuple(
        sorted((*collection.pages[0].selected_response_headers, ("link", "not-a-link")))
    )
    forged_page = replace(
        collection.pages[0],
        selected_response_headers=selected_headers,
        selected_response_headers_sha256=canonical_json_sha256(
            [[name, value] for name, value in selected_headers]
        ),
    )

    with pytest.raises(CollectionIntegrityError, match="retained Link header"):
        assemble_context_collection(forged_page, limits=_limits())


def test_github_collector_rejects_cursor_cycle_before_refetching_position():
    calls: list[HTTPFetchRequest] = []
    transitions = {None: "cursor_a", "cursor_a": "cursor_b", "cursor_b": "cursor_a"}
    identifiers = {
        None: "GHSA-2345-cfgh-jmpq",
        "cursor_a": "GHSA-3456-ghjm-pqrv",
        "cursor_b": "GHSA-4567-hjmp-qrvc",
    }

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        calls.append(request)
        cursor = parse_qs(urlsplit(request.url).query).get("after", [None])[0]
        return _github_response(
            request,
            identifier=identifiers[cursor],
            next_cursor=transitions[cursor],
        )

    with pytest.raises(CollectionIntegrityError, match="repeats or cycles"):
        collect_github_advisories(
            _github_query(),
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=fetch,
        )
    assert len(calls) == 3


def test_github_collector_stops_on_observed_zero_quota_with_next_cursor():
    calls: list[HTTPFetchRequest] = []

    def fetch(request: HTTPFetchRequest) -> HTTPFetchResponse:
        calls.append(request)
        return _github_response(
            request,
            identifier="GHSA-2345-cfgh-jmpq",
            next_cursor="cursor_a",
            remaining=0,
        )

    with pytest.raises(CollectionIncompleteError) as raised:
        collect_github_advisories(
            _github_query(),
            limits=_limits(),
            timeout_seconds=3,
            user_agent=USER_AGENT,
            fetcher=fetch,
        )
    assert raised.value.reason == "quota_exhausted"
    assert raised.value.quota_state == "exhausted"
    assert raised.value.next_position == "cursor_a"
    assert len(calls) == 1
