"""Fail-closed, globally bounded collection of paginated intelligence pages."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

from .adapters import (
    _github_next_cursor,
    _github_rate_limit,
    _optional_header_int,
    parse_github_advisory_response,
    parse_nvd_cve_response,
)
from .canonical import canonical_json_sha256
from .errors import (
    CollectionIncompleteError,
    CollectionIntegrityError,
    ExternalIntelligenceError,
)
from .models import (
    CONTEXT_ONLY_CLASSIFICATION,
    CollectionStatus,
    ExternalIntelligencePage,
    ExternalIntelligenceRecord,
    RateLimitMetadata,
)
from .providers import (
    github_collection_query,
    normalize_github_advisory_query,
    normalize_nvd_cve_query,
    nvd_collection_query,
    query_from_github_url,
    query_from_nvd_url,
)
from .transport import (
    GITHUB_API_VERSION,
    GITHUB_GLOBAL_ADVISORIES_URL,
    MAX_HTTP_RESPONSE_BYTES,
    NVD_CVE_API_URL,
    HTTPFetchRequest,
    HTTPFetchResponse,
    build_github_advisory_request,
    build_nvd_cve_request,
    fetch_http_response,
)


INTELLIGENCE_COLLECTION_SCHEMA_VERSION = "belief.external_intelligence_collection.v1"
MAX_COLLECTION_PAGES = 100
MAX_COLLECTION_RECORDS = 10_000
MAX_COLLECTION_RESPONSE_BYTES = 64 * 1024 * 1024

FetchIntelligenceResponse = Callable[[HTTPFetchRequest], HTTPFetchResponse]


@dataclass(frozen=True, slots=True)
class CollectionLimits:
    """Mandatory caller limits, themselves capped by BELIEF safety maxima."""

    max_pages: int
    max_records: int
    max_total_response_bytes: int
    max_response_bytes: int

    def __post_init__(self) -> None:
        _bounded_positive_int(self.max_pages, "max_pages", MAX_COLLECTION_PAGES)
        _bounded_positive_int(self.max_records, "max_records", MAX_COLLECTION_RECORDS)
        _bounded_positive_int(
            self.max_total_response_bytes,
            "max_total_response_bytes",
            MAX_COLLECTION_RESPONSE_BYTES,
        )
        _bounded_positive_int(
            self.max_response_bytes,
            "max_response_bytes",
            MAX_HTTP_RESPONSE_BYTES,
        )
        if self.max_response_bytes > self.max_total_response_bytes:
            raise ValueError("max_response_bytes must not exceed max_total_response_bytes")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_pages": self.max_pages,
            "max_records": self.max_records,
            "max_total_response_bytes": self.max_total_response_bytes,
            "max_response_bytes": self.max_response_bytes,
        }


@dataclass(frozen=True, slots=True)
class _SequenceState:
    provider: str
    endpoint_url: str
    api_contract_version: str
    collection_query_sha256: str
    collection_status: CollectionStatus
    provider_total: int | None
    records: tuple[ExternalIntelligenceRecord, ...]
    total_response_bytes: int
    next_position: int | str | None
    quota_state: str


@dataclass(frozen=True, slots=True)
class ExternalIntelligenceCollection:
    """One validated terminal page chain with no proof-authority semantics."""

    pages: tuple[ExternalIntelligencePage, ...]
    limits: CollectionLimits
    provider: str = field(init=False)
    endpoint_url: str = field(init=False)
    api_contract_version: str = field(init=False)
    collection_query_sha256: str = field(init=False)
    collection_status: CollectionStatus = field(init=False)
    collection_complete: bool = field(init=False)
    provider_total: int | None = field(init=False)
    records: tuple[ExternalIntelligenceRecord, ...] = field(init=False, repr=False)
    total_response_bytes: int = field(init=False)
    snapshot_consistency: str = field(default="unverified", init=False)
    schema_version: str = field(
        default=INTELLIGENCE_COLLECTION_SCHEMA_VERSION,
        init=False,
    )
    classification: str = field(default=CONTEXT_ONLY_CLASSIFICATION, init=False)
    proof_eligible: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.pages, tuple):
            raise TypeError("pages must be an immutable tuple")
        if not isinstance(self.limits, CollectionLimits):
            raise TypeError("limits must be CollectionLimits")
        state = _validate_page_sequence(self.pages, self.limits, require_terminal=True)
        object.__setattr__(self, "provider", state.provider)
        object.__setattr__(self, "endpoint_url", state.endpoint_url)
        object.__setattr__(self, "api_contract_version", state.api_contract_version)
        object.__setattr__(
            self,
            "collection_query_sha256",
            state.collection_query_sha256,
        )
        object.__setattr__(self, "collection_status", state.collection_status)
        object.__setattr__(
            self,
            "collection_complete",
            state.collection_status == "complete",
        )
        object.__setattr__(self, "provider_total", state.provider_total)
        object.__setattr__(self, "records", state.records)
        object.__setattr__(self, "total_response_bytes", state.total_response_bytes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "proof_eligible": self.proof_eligible,
            "provider": self.provider,
            "endpoint_url": self.endpoint_url,
            "api_contract_version": self.api_contract_version,
            "collection_query_sha256": self.collection_query_sha256,
            "collection_status": self.collection_status,
            "collection_complete": self.collection_complete,
            "snapshot_consistency": self.snapshot_consistency,
            "provider_total": self.provider_total,
            "page_count": len(self.pages),
            "record_count": len(self.records),
            "total_response_bytes": self.total_response_bytes,
            "limits": self.limits.to_dict(),
            "pages": [page.to_dict() for page in self.pages],
        }


def assemble_context_collection(
    *pages: ExternalIntelligencePage,
    limits: CollectionLimits,
) -> ExternalIntelligenceCollection:
    """Validate a terminal page chain and retain every unique provider occurrence."""

    return ExternalIntelligenceCollection(pages=tuple(pages), limits=limits)


def collect_nvd_cves(
    query: Mapping[str, Any],
    *,
    limits: CollectionLimits,
    timeout_seconds: float,
    user_agent: str,
    api_key: str | None = None,
    freshness_max_age_seconds: int | None = None,
    fetcher: FetchIntelligenceResponse | None = None,
) -> ExternalIntelligenceCollection:
    """Fetch NVD pages from offset zero under mandatory cumulative limits."""

    normalized = normalize_nvd_cve_query(query)
    if normalized["startIndex"] != 0:
        raise ValueError("NVD collection must start at offset zero")
    normalized["resultsPerPage"] = min(
        normalized["resultsPerPage"],
        limits.max_records,
    )
    pages: list[ExternalIntelligencePage] = []
    current_query = normalized
    while True:
        _guard_before_fetch(pages, limits)
        request = build_nvd_cve_request(
            current_query,
            timeout_seconds=timeout_seconds,
            max_response_bytes=_next_response_byte_limit(pages, limits),
            user_agent=user_agent,
            api_key=api_key,
        )
        page = _fetch_and_parse(
            request,
            pages=pages,
            limits=limits,
            fetcher=fetcher,
            parser=lambda response: parse_nvd_cve_response(
                response,
                query=current_query,
                freshness_max_age_seconds=freshness_max_age_seconds,
            ),
        )
        pages.append(page)
        state = _validate_page_sequence(tuple(pages), limits, require_terminal=False)
        if state.provider_total is not None and state.provider_total > limits.max_records:
            _raise_incomplete("max_records", pages, state.next_position)
        if state.collection_status != "incomplete":
            return assemble_context_collection(*pages, limits=limits)
        _guard_quota(page, pages)
        remaining_records = limits.max_records - len(state.records)
        remaining_provider_records = state.provider_total - len(state.records)
        next_page_size = min(
            normalized["resultsPerPage"],
            remaining_records,
            remaining_provider_records,
        )
        if next_page_size <= 0:
            _raise_incomplete("max_records", pages, state.next_position)
        current_query = dict(
            current_query,
            startIndex=state.next_position,
            resultsPerPage=next_page_size,
        )


def collect_github_advisories(
    query: Mapping[str, Any],
    *,
    limits: CollectionLimits,
    timeout_seconds: float,
    user_agent: str,
    token: str | None = None,
    freshness_max_age_seconds: int | None = None,
    fetcher: FetchIntelligenceResponse | None = None,
) -> ExternalIntelligenceCollection:
    """Fetch GitHub cursor pages; absent Link remains completeness-unknown."""

    normalized = normalize_github_advisory_query(query)
    if "after" in normalized:
        raise ValueError("GitHub collection must start without a cursor")
    normalized["per_page"] = min(normalized["per_page"], limits.max_records)
    pages: list[ExternalIntelligencePage] = []
    current_query = normalized
    while True:
        _guard_before_fetch(pages, limits)
        request = build_github_advisory_request(
            current_query,
            timeout_seconds=timeout_seconds,
            max_response_bytes=_next_response_byte_limit(pages, limits),
            user_agent=user_agent,
            token=token,
        )
        page = _fetch_and_parse(
            request,
            pages=pages,
            limits=limits,
            fetcher=fetcher,
            parser=lambda response: parse_github_advisory_response(
                response,
                query=current_query,
                freshness_max_age_seconds=freshness_max_age_seconds,
            ),
        )
        pages.append(page)
        state = _validate_page_sequence(tuple(pages), limits, require_terminal=False)
        if state.collection_status != "incomplete":
            return assemble_context_collection(*pages, limits=limits)
        _guard_quota(page, pages)
        current_query = dict(current_query, after=state.next_position)


def _fetch_and_parse(
    request: HTTPFetchRequest,
    *,
    pages: list[ExternalIntelligencePage],
    limits: CollectionLimits,
    fetcher: FetchIntelligenceResponse | None,
    parser: Callable[[HTTPFetchResponse], ExternalIntelligencePage],
) -> ExternalIntelligencePage:
    response: HTTPFetchResponse | None = None
    try:
        active_fetcher = fetch_http_response if fetcher is None else fetcher
        response = active_fetcher(request)
        if not isinstance(response, HTTPFetchResponse):
            raise TypeError("fetcher must return HTTPFetchResponse")
        if len(response.body) > request.max_response_bytes:
            _raise_incomplete(
                "response_too_large",
                pages,
                _last_next_position(pages),
                extra_response_bytes=len(response.body),
            )
        remaining_records = limits.max_records - sum(len(page.batch.records) for page in pages)
        page = parser(response)
        if len(page.batch.records) > remaining_records:
            _raise_incomplete(
                "max_records",
                pages,
                _last_next_position(pages),
                extra_response_bytes=len(response.body),
            )
        return page
    except CollectionIncompleteError:
        raise
    except ExternalIntelligenceError as exc:
        _raise_incomplete(
            (
                getattr(exc, "error_code", None)
                or getattr(exc, "parser_status", None)
                or exc.__class__.__name__
            ),
            pages,
            _last_next_position(pages),
            cause=exc,
            extra_response_bytes=(
                len(response.body) if isinstance(response, HTTPFetchResponse) else 0
            ),
        )
    except (TypeError, ValueError) as exc:
        _raise_incomplete(
            "invalid_fetch_or_page",
            pages,
            _last_next_position(pages),
            cause=exc,
            extra_response_bytes=(
                len(response.body) if isinstance(response, HTTPFetchResponse) else 0
            ),
        )
    raise AssertionError("unreachable")


def _validate_page_sequence(
    pages: tuple[ExternalIntelligencePage, ...],
    limits: CollectionLimits,
    *,
    require_terminal: bool,
) -> _SequenceState:
    if not pages:
        raise CollectionIntegrityError("a collection requires at least one page")

    first = pages[0]
    if not isinstance(first, ExternalIntelligencePage):
        raise TypeError("pages must contain ExternalIntelligencePage values")
    mode = first.pagination.mode
    if mode == "offset" and first.pagination.request_position != 0:
        raise CollectionIntegrityError("offset collections must start at zero")
    if mode == "cursor" and first.pagination.request_position is not None:
        raise CollectionIntegrityError("cursor collections must start without a cursor")
    if mode == "none" and len(pages) != 1:
        raise CollectionIntegrityError("non-paginated collections contain exactly one page")

    seen_positions: set[tuple[type[object], object]] = set()
    seen_request_digests: set[str] = set()
    seen_record_ids: set[str] = set()
    records: list[ExternalIntelligenceRecord] = []
    total_response_bytes = 0
    provider_total = first.pagination.provider_total
    requested_page_size = first.pagination.requested_page_size
    previous: ExternalIntelligencePage | None = None

    for page in pages:
        if not isinstance(page, ExternalIntelligencePage):
            raise TypeError("pages must contain ExternalIntelligencePage values")
        if (
            page.provider != first.provider
            or page.endpoint_url != first.endpoint_url
            or page.api_contract_version != first.api_contract_version
            or page.collection_query_sha256 != first.collection_query_sha256
        ):
            raise CollectionIntegrityError("page identity changed within the collection")
        if page.pagination.mode != mode:
            raise CollectionIntegrityError("pagination mode changed within the collection")
        _validate_page_query_bindings(page)
        if page.pagination.requested_page_size != requested_page_size:
            if not _is_bounded_offset_resize(
                page,
                initial_requested_page_size=requested_page_size,
                provider_total=provider_total,
            ):
                raise CollectionIntegrityError("requested page size changed within the collection")
        if page.pagination.provider_total != provider_total:
            raise CollectionIntegrityError("provider total changed within the collection")
        if len(page.batch.records) != page.pagination.page_size:
            raise CollectionIntegrityError("page record count does not match page metadata")
        if previous is not None:
            if previous.pagination.collection_status != "incomplete":
                raise CollectionIntegrityError("a page follows a terminal page")
            if previous.rate_limit.remaining == 0:
                raise CollectionIntegrityError("a page follows an exhausted observed quota")
            if page.pagination.request_position != previous.pagination.next_position:
                raise CollectionIntegrityError("page position does not continue the prior page")
            if _retrieval_time(page) < _retrieval_time(previous):
                raise CollectionIntegrityError(
                    "page retrieval timestamp moved backwards within the collection"
                )
            current_generation = _provider_generation_time(page)
            previous_generation = _provider_generation_time(previous)
            if (
                current_generation is not None
                and previous_generation is not None
                and current_generation < previous_generation
            ):
                raise CollectionIntegrityError(
                    "provider response generation timestamp moved backwards"
                )

        if mode == "offset" and page.pagination.collection_status == "incomplete":
            expected_next = page.pagination.request_position + page.pagination.page_size
            if page.pagination.next_position != expected_next:
                raise CollectionIntegrityError("offset page does not advance by its page size")

        position_key = (type(page.pagination.request_position), page.pagination.request_position)
        if position_key in seen_positions:
            raise CollectionIntegrityError("pagination position repeated or cycled")
        seen_positions.add(position_key)
        next_position = page.pagination.next_position
        if next_position is not None:
            next_key = (type(next_position), next_position)
            if next_key in seen_positions:
                raise CollectionIntegrityError("pagination next position repeats or cycles")
        if page.request_query_sha256 in seen_request_digests:
            raise CollectionIntegrityError("page request repeated within the collection")
        seen_request_digests.add(page.request_query_sha256)

        for record in page.batch.records:
            if record.record_id in seen_record_ids:
                raise CollectionIntegrityError(
                    f"provider record_id repeated within the collection: {record.record_id}"
                )
            seen_record_ids.add(record.record_id)
            records.append(record)
        total_response_bytes += page.raw_response_bytes
        if page.raw_response_bytes > limits.max_response_bytes:
            _raise_incomplete(
                "max_response_bytes",
                list(pages),
                page.pagination.next_position,
            )
        if len(records) > limits.max_records:
            _raise_incomplete("max_records", list(pages), page.pagination.next_position)
        if total_response_bytes > limits.max_total_response_bytes:
            _raise_incomplete(
                "max_total_response_bytes",
                list(pages),
                page.pagination.next_position,
            )
        previous = page

    if len(pages) > limits.max_pages:
        _raise_incomplete("max_pages", list(pages), pages[-1].pagination.next_position)
    final = pages[-1]
    if mode == "offset" and final.pagination.collection_status == "complete":
        if provider_total != len(records):
            raise CollectionIntegrityError(
                "terminal offset collection count does not match provider total"
            )
    if require_terminal and final.pagination.collection_status == "incomplete":
        _raise_incomplete("non_terminal", list(pages), final.pagination.next_position)

    return _SequenceState(
        provider=first.provider,
        endpoint_url=first.endpoint_url,
        api_contract_version=first.api_contract_version,
        collection_query_sha256=first.collection_query_sha256,
        collection_status=final.pagination.collection_status,
        provider_total=provider_total,
        records=tuple(records),
        total_response_bytes=total_response_bytes,
        next_position=final.pagination.next_position,
        quota_state=_quota_state(final),
    )


def _guard_before_fetch(
    pages: list[ExternalIntelligencePage],
    limits: CollectionLimits,
) -> None:
    next_position = _last_next_position(pages)
    if len(pages) >= limits.max_pages:
        _raise_incomplete("max_pages", pages, next_position)
    record_count = sum(len(page.batch.records) for page in pages)
    if record_count >= limits.max_records:
        _raise_incomplete("max_records", pages, next_position)
    if pages and pages[0].pagination.mode == "cursor":
        requested_page_size = pages[0].pagination.requested_page_size
        if requested_page_size is not None:
            if limits.max_records - record_count < requested_page_size:
                _raise_incomplete("max_records", pages, next_position)
    if sum(page.raw_response_bytes for page in pages) >= limits.max_total_response_bytes:
        _raise_incomplete("max_total_response_bytes", pages, next_position)


def _guard_quota(
    page: ExternalIntelligencePage,
    pages: list[ExternalIntelligencePage],
) -> None:
    if page.rate_limit.remaining == 0:
        _raise_incomplete("quota_exhausted", pages, page.pagination.next_position)
    if page.rate_limit.retry_after_seconds is not None:
        _raise_incomplete("retry_after_observed", pages, page.pagination.next_position)


def _next_response_byte_limit(
    pages: list[ExternalIntelligencePage],
    limits: CollectionLimits,
) -> int:
    remaining = limits.max_total_response_bytes - sum(page.raw_response_bytes for page in pages)
    if remaining <= 0:
        _raise_incomplete(
            "max_total_response_bytes",
            pages,
            _last_next_position(pages),
        )
    return min(limits.max_response_bytes, remaining)


def _validate_page_query_bindings(page: ExternalIntelligencePage) -> None:
    try:
        if page.provider == "nvd_cve":
            request_query = query_from_nvd_url(page.request_url)
            collection_query = nvd_collection_query(request_query)
            if page.endpoint_url != NVD_CVE_API_URL:
                raise CollectionIntegrityError("NVD page endpoint is not canonical")
            if page.api_contract_version != "NVD_CVE/2.0":
                raise CollectionIntegrityError("NVD API contract version is not canonical")
            if page.pagination.mode != "offset":
                raise CollectionIntegrityError("NVD pages require offset pagination")
            if page.pagination.collection_status == "unknown":
                raise CollectionIntegrityError(
                    "NVD body totals cannot produce unknown completeness"
                )
            if request_query["startIndex"] != page.pagination.request_position:
                raise CollectionIntegrityError("NVD request offset does not match page metadata")
            if request_query["resultsPerPage"] != page.pagination.requested_page_size:
                raise CollectionIntegrityError("NVD request page size does not match page metadata")
            selected_headers = dict(page.selected_response_headers)
            try:
                retry_after_seconds = _optional_header_int(
                    selected_headers,
                    "retry-after",
                )
            except ValueError as exc:
                raise CollectionIntegrityError(
                    "NVD retained response headers violate provider policy"
                ) from exc
            expected_rate_limit = RateLimitMetadata(
                policy_limit=None,
                policy_window_seconds=None,
                observed_limit=None,
                remaining=None,
                used=None,
                reset_epoch_seconds=None,
                retry_after_seconds=retry_after_seconds,
                resource=None,
            )
            if page.rate_limit != expected_rate_limit:
                raise CollectionIntegrityError(
                    "NVD rate-limit metadata does not match retained headers"
                )
        elif page.provider == "github_advisory":
            request_query = query_from_github_url(page.request_url)
            collection_query = github_collection_query(request_query)
            if page.endpoint_url != GITHUB_GLOBAL_ADVISORIES_URL:
                raise CollectionIntegrityError("GitHub page endpoint is not canonical")
            if page.api_contract_version != GITHUB_API_VERSION:
                raise CollectionIntegrityError("GitHub API contract version is not canonical")
            if page.pagination.mode != "cursor":
                raise CollectionIntegrityError("GitHub pages require cursor pagination")
            if page.pagination.collection_status == "complete":
                raise CollectionIntegrityError(
                    "GitHub Link pagination cannot prove collection completeness"
                )
            if request_query.get("after") != page.pagination.request_position:
                raise CollectionIntegrityError("GitHub request cursor does not match page metadata")
            if request_query["per_page"] != page.pagination.requested_page_size:
                raise CollectionIntegrityError(
                    "GitHub request page size does not match page metadata"
                )
            selected_headers = dict(page.selected_response_headers)
            if selected_headers.get("x-github-api-version-selected") != GITHUB_API_VERSION:
                raise CollectionIntegrityError(
                    "GitHub selected API version does not match the pinned contract"
                )
            try:
                expected_rate_limit = _github_rate_limit(selected_headers)
            except ValueError as exc:
                raise CollectionIntegrityError(
                    "GitHub retained rate-limit headers violate provider policy"
                ) from exc
            if page.rate_limit != expected_rate_limit:
                raise CollectionIntegrityError(
                    "GitHub rate-limit metadata does not match retained headers"
                )
            try:
                header_next_cursor = _github_next_cursor(
                    selected_headers.get("link"),
                    collection_query=collection_query,
                    per_page=request_query["per_page"],
                    current_cursor=request_query.get("after"),
                )
            except ValueError as exc:
                raise CollectionIntegrityError(
                    "GitHub retained Link header violates provider policy"
                ) from exc
            if header_next_cursor != page.pagination.next_position:
                raise CollectionIntegrityError(
                    "GitHub next cursor does not match the retained Link header"
                )
        else:
            raise CollectionIntegrityError(
                f"unsupported paginated collection provider: {page.provider}"
            )
    except CollectionIntegrityError:
        raise
    except ValueError as exc:
        raise CollectionIntegrityError("page request URL violates provider policy") from exc
    if canonical_json_sha256(request_query) != page.request_query_sha256:
        raise CollectionIntegrityError("page request digest does not match its request URL")
    if canonical_json_sha256(collection_query) != page.collection_query_sha256:
        raise CollectionIntegrityError("page collection digest does not match its request URL")


def _is_bounded_offset_resize(
    page: ExternalIntelligencePage,
    *,
    initial_requested_page_size: int | None,
    provider_total: int | None,
) -> bool:
    if (
        page.pagination.mode != "offset"
        or initial_requested_page_size is None
        or provider_total is None
    ):
        return False
    requested = page.pagination.requested_page_size
    position = page.pagination.request_position
    if not isinstance(requested, int) or not isinstance(position, int):
        return False
    remaining_at_request = provider_total - position
    expected = min(initial_requested_page_size, remaining_at_request)
    return requested == expected and 0 < requested < initial_requested_page_size


def _retrieval_time(page: ExternalIntelligencePage) -> datetime:
    return datetime.fromisoformat(page.batch.retrieved_at_utc.replace("Z", "+00:00"))


def _provider_generation_time(page: ExternalIntelligencePage) -> datetime | None:
    if page.response_generated_at_utc is None:
        return None
    return datetime.fromisoformat(page.response_generated_at_utc.replace("Z", "+00:00"))


def _last_next_position(
    pages: list[ExternalIntelligencePage],
) -> int | str | None:
    return pages[-1].pagination.next_position if pages else None


def _quota_state(page: ExternalIntelligencePage | None) -> str:
    if page is None or page.rate_limit.remaining is None:
        return "unknown"
    return "exhausted" if page.rate_limit.remaining == 0 else "available"


def _raise_incomplete(
    reason: str,
    pages: list[ExternalIntelligencePage],
    next_position: int | str | None,
    *,
    cause: BaseException | None = None,
    extra_response_bytes: int = 0,
) -> None:
    error = CollectionIncompleteError(
        reason,
        next_position=next_position,
        page_count=len(pages),
        record_count=sum(len(page.batch.records) for page in pages),
        total_response_bytes=(
            sum(page.raw_response_bytes for page in pages) + extra_response_bytes
        ),
        quota_state=_quota_state(pages[-1] if pages else None),
    )
    if cause is None:
        raise error
    raise error from cause


def _bounded_positive_int(value: object, field_name: str, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{field_name} must be an integer")
    if not 1 <= value <= maximum:
        raise ValueError(f"{field_name} must be within [1, {maximum}]")


__all__ = [
    "CollectionLimits",
    "ExternalIntelligenceCollection",
    "FetchIntelligenceResponse",
    "INTELLIGENCE_COLLECTION_SCHEMA_VERSION",
    "MAX_COLLECTION_PAGES",
    "MAX_COLLECTION_RECORDS",
    "MAX_COLLECTION_RESPONSE_BYTES",
    "assemble_context_collection",
    "collect_github_advisories",
    "collect_nvd_cves",
]
