"""Explicit, bounded stdlib HTTP transport for live intelligence retrieval."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .canonical import canonical_json, normalize_retrieval_timestamp, require_https_url
from .errors import (
    HTTPStatusTransportError,
    InvalidTransportResponseError,
    NetworkTransportError,
    ResponseTooLargeError,
    TransportTimeoutError,
)


OSV_QUERY_URL = "https://api.osv.dev/v1/query"
CISA_KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
MAX_HTTP_TIMEOUT_SECONDS = 30.0
MAX_HTTP_RESPONSE_BYTES = 16 * 1024 * 1024
ALLOWED_INTELLIGENCE_URLS = frozenset({OSV_QUERY_URL, CISA_KEV_CATALOG_URL})


class _RefuseRedirects(HTTPRedirectHandler):
    """Keep the registered provider endpoint as the actual network boundary."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


@dataclass(frozen=True, slots=True)
class HTTPFetchRequest:
    """Caller-explicit network request with hard global upper bounds."""

    url: str
    method: str
    timeout_seconds: float
    max_response_bytes: int
    user_agent: str
    body: bytes | None = None
    headers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        normalized_url = require_https_url(self.url, field="request URL")
        if normalized_url != self.url or normalized_url not in ALLOWED_INTELLIGENCE_URLS:
            raise ValueError("request URL must be an exact registered intelligence endpoint")
        if self.method not in {"GET", "POST"}:
            raise ValueError("HTTP method must be GET or POST")
        if isinstance(self.timeout_seconds, bool) or not isinstance(
            self.timeout_seconds,
            (int, float),
        ):
            raise TypeError("timeout_seconds must be numeric")
        if not 0 < float(self.timeout_seconds) <= MAX_HTTP_TIMEOUT_SECONDS:
            raise ValueError(
                f"timeout_seconds must be within (0, {MAX_HTTP_TIMEOUT_SECONDS}]"
            )
        if isinstance(self.max_response_bytes, bool) or not isinstance(
            self.max_response_bytes,
            int,
        ):
            raise TypeError("max_response_bytes must be an integer")
        if not 0 < self.max_response_bytes <= MAX_HTTP_RESPONSE_BYTES:
            raise ValueError(
                f"max_response_bytes must be within [1, {MAX_HTTP_RESPONSE_BYTES}]"
            )
        _header_value(self.user_agent, "user_agent")
        if self.body is not None and not isinstance(self.body, bytes):
            raise TypeError("body must be immutable bytes when present")
        if not isinstance(self.headers, tuple):
            raise TypeError("headers must be an immutable tuple")
        for name, value in self.headers:
            _header_value(name, "header name")
            _header_value(value, f"header {name}")


@dataclass(frozen=True, slots=True)
class HTTPFetchResponse:
    """Exact bounded bytes plus HTTP retrieval metadata."""

    source_url: str
    status_code: int
    retrieved_at_utc: str
    body: bytes
    headers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        require_https_url(self.source_url)
        if not 200 <= self.status_code <= 299:
            raise ValueError("HTTPFetchResponse requires a successful status")
        if normalize_retrieval_timestamp(self.retrieved_at_utc) != self.retrieved_at_utc:
            raise ValueError("retrieved_at_utc must use canonical UTC form")
        if not isinstance(self.body, bytes):
            raise TypeError("response body must be immutable bytes")
        if not isinstance(self.headers, tuple):
            raise TypeError("response headers must be an immutable tuple")


def build_osv_query_request(
    query: Mapping[str, Any],
    *,
    timeout_seconds: float,
    max_response_bytes: int,
    user_agent: str,
    source_url: str = OSV_QUERY_URL,
) -> HTTPFetchRequest:
    """Build, but do not execute, a deterministic OSV POST request."""

    body = canonical_json(dict(query)).encode("utf-8")
    return HTTPFetchRequest(
        url=source_url,
        method="POST",
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        user_agent=user_agent,
        body=body,
        headers=(("Accept", "application/json"), ("Content-Type", "application/json")),
    )


def build_cisa_kev_request(
    *,
    timeout_seconds: float,
    max_response_bytes: int,
    user_agent: str,
    source_url: str = CISA_KEV_CATALOG_URL,
) -> HTTPFetchRequest:
    """Build, but do not execute, a bounded CISA KEV GET request."""

    return HTTPFetchRequest(
        url=source_url,
        method="GET",
        timeout_seconds=timeout_seconds,
        max_response_bytes=max_response_bytes,
        user_agent=user_agent,
        headers=(("Accept", "application/json"),),
    )


def fetch_http_response(
    request: HTTPFetchRequest,
    *,
    opener: Callable[[Request, float], Any] | None = None,
    clock: Callable[[], str | datetime] | None = None,
) -> HTTPFetchResponse:
    """Execute one explicit request and raise typed failures on every error.

    The injected ``opener`` receives the stdlib ``Request`` and timeout. This
    keeps all network tests offline while production callers opt in explicitly.
    """

    open_request = opener or _stdlib_open
    now = clock or (lambda: datetime.now(timezone.utc))
    headers = {name: value for name, value in request.headers}
    headers["User-Agent"] = request.user_agent
    wire_request = Request(
        request.url,
        data=request.body,
        headers=headers,
        method=request.method,
    )

    try:
        response = open_request(wire_request, float(request.timeout_seconds))
    except HTTPError as exc:
        raise HTTPStatusTransportError(
            f"provider returned HTTP {exc.code}",
            url=request.url,
            status_code=int(exc.code),
        ) from exc
    except (TimeoutError, socket.timeout) as exc:
        raise TransportTimeoutError("provider request timed out", url=request.url) from exc
    except URLError as exc:
        if isinstance(exc.reason, (TimeoutError, socket.timeout)):
            raise TransportTimeoutError("provider request timed out", url=request.url) from exc
        raise NetworkTransportError("provider network request failed", url=request.url) from exc
    except OSError as exc:
        raise NetworkTransportError("provider network request failed", url=request.url) from exc
    except Exception as exc:
        raise NetworkTransportError("provider request failed", url=request.url) from exc

    try:
        _validate_final_response_url(response, request.url)
        status_code = _status_code(response, request.url)
        if not 200 <= status_code <= 299:
            raise HTTPStatusTransportError(
                f"provider returned HTTP {status_code}",
                url=request.url,
                status_code=status_code,
            )
        content_length = _content_length(response, request.url)
        if content_length is not None and content_length > request.max_response_bytes:
            raise ResponseTooLargeError(
                "provider response exceeds caller byte limit",
                url=request.url,
                max_response_bytes=request.max_response_bytes,
            )
        try:
            body = response.read(request.max_response_bytes + 1)
        except (TimeoutError, socket.timeout) as exc:
            raise TransportTimeoutError(
                "provider response read timed out",
                url=request.url,
            ) from exc
        except OSError as exc:
            raise NetworkTransportError(
                "provider response read failed",
                url=request.url,
            ) from exc
        except Exception as exc:
            raise NetworkTransportError(
                "provider response read failed",
                url=request.url,
            ) from exc
        if not isinstance(body, bytes):
            raise InvalidTransportResponseError(
                "provider response body is not bytes",
                url=request.url,
            )
        if len(body) > request.max_response_bytes:
            raise ResponseTooLargeError(
                "provider response exceeds caller byte limit",
                url=request.url,
                max_response_bytes=request.max_response_bytes,
            )
        response_headers = _response_headers(response)
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()

    return HTTPFetchResponse(
        source_url=request.url,
        status_code=status_code,
        retrieved_at_utc=normalize_retrieval_timestamp(now()),
        body=body,
        headers=response_headers,
    )


def _stdlib_open(request: Request, timeout_seconds: float) -> Any:
    opener = build_opener(_RefuseRedirects())
    return opener.open(request, timeout=timeout_seconds)


def _validate_final_response_url(response: Any, expected_url: str) -> None:
    geturl = getattr(response, "geturl", None)
    if not callable(geturl):
        return
    candidate = geturl()
    try:
        normalized = require_https_url(candidate, field="response URL")
    except (TypeError, ValueError) as exc:
        raise InvalidTransportResponseError(
            "provider response URL is invalid",
            url=expected_url,
        ) from exc
    if normalized != expected_url:
        raise InvalidTransportResponseError(
            "provider response URL differs from the registered endpoint",
            url=expected_url,
        )


def _status_code(response: Any, url: str) -> int:
    candidate = getattr(response, "status", None)
    if candidate is None:
        getcode = getattr(response, "getcode", None)
        candidate = getcode() if callable(getcode) else None
    if not isinstance(candidate, int) or isinstance(candidate, bool):
        raise InvalidTransportResponseError(
            "provider response has no integer HTTP status",
            url=url,
        )
    return candidate


def _content_length(response: Any, url: str) -> int | None:
    headers = getattr(response, "headers", None)
    if headers is None or not hasattr(headers, "get"):
        return None
    candidate = headers.get("Content-Length")
    if candidate is None:
        return None
    try:
        result = int(candidate)
    except (TypeError, ValueError) as exc:
        raise InvalidTransportResponseError(
            "provider Content-Length is not an integer",
            url=url,
        ) from exc
    if result < 0:
        raise InvalidTransportResponseError(
            "provider Content-Length is negative",
            url=url,
        )
    return result


def _response_headers(response: Any) -> tuple[tuple[str, str], ...]:
    headers = getattr(response, "headers", None)
    if headers is None or not hasattr(headers, "items"):
        return ()
    return tuple(sorted((str(name), str(value)) for name, value in headers.items()))


def _header_value(value: object, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if "\r" in value or "\n" in value:
        raise ValueError(f"{field_name} must not contain line breaks")


__all__ = [
    "ALLOWED_INTELLIGENCE_URLS",
    "CISA_KEV_CATALOG_URL",
    "MAX_HTTP_RESPONSE_BYTES",
    "MAX_HTTP_TIMEOUT_SECONDS",
    "OSV_QUERY_URL",
    "HTTPFetchRequest",
    "HTTPFetchResponse",
    "build_cisa_kev_request",
    "build_osv_query_request",
    "fetch_http_response",
]
