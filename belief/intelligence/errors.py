"""Typed failures for bounded external-intelligence ingestion."""

from __future__ import annotations


class ExternalIntelligenceError(Exception):
    """Base class for failures at the external-intelligence boundary."""


class QueryNormalizationError(ExternalIntelligenceError, ValueError):
    """A provider query cannot be represented as canonical JSON."""


class CollectionIntegrityError(ExternalIntelligenceError, ValueError):
    """A page sequence cannot form one continuous provider collection."""


class CollectionIncompleteError(ExternalIntelligenceError, RuntimeError):
    """A bounded live collection stopped before a trusted terminal state."""

    def __init__(
        self,
        reason: str,
        *,
        next_position: int | str | None,
        page_count: int,
        record_count: int,
        total_response_bytes: int,
        quota_state: str,
    ) -> None:
        super().__init__(f"external-intelligence collection incomplete: {reason}")
        self.reason = reason
        self.next_position = next_position
        self.page_count = page_count
        self.record_count = record_count
        self.total_response_bytes = total_response_bytes
        self.quota_state = quota_state


class IntelligenceParseError(ExternalIntelligenceError, ValueError):
    """A provider response could not be parsed under its strict contract."""

    parser_status = "parse_error"

    def __init__(self, message: str, *, path: str = "$") -> None:
        super().__init__(f"{path}: {message}")
        self.path = path


class MalformedIntelligenceJSONError(IntelligenceParseError):
    """Raw response bytes are not one unambiguous strict JSON document."""

    parser_status = "malformed_json"


class IntelligenceSchemaError(IntelligenceParseError):
    """Decoded JSON does not match the provider contract used by BELIEF."""

    parser_status = "invalid_schema"


class IntelligenceTransportError(ExternalIntelligenceError, RuntimeError):
    """A live HTTP request failed without producing trusted response bytes."""

    error_code = "transport_error"

    def __init__(self, message: str, *, url: str) -> None:
        super().__init__(message)
        self.url = url


class TransportTimeoutError(IntelligenceTransportError):
    """The bounded HTTP request timed out."""

    error_code = "timeout"


class NetworkTransportError(IntelligenceTransportError):
    """The HTTP request failed below the HTTP status layer."""

    error_code = "network_error"


class HTTPStatusTransportError(IntelligenceTransportError):
    """The provider returned a non-success HTTP status."""

    error_code = "http_status"

    def __init__(
        self,
        message: str,
        *,
        url: str,
        status_code: int,
        response_headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        super().__init__(message, url=url)
        self.status_code = status_code
        self.response_headers = response_headers


class ResponseTooLargeError(IntelligenceTransportError):
    """The response exceeded the caller-selected bounded byte limit."""

    error_code = "response_too_large"

    def __init__(self, message: str, *, url: str, max_response_bytes: int) -> None:
        super().__init__(message, url=url)
        self.max_response_bytes = max_response_bytes


class InvalidTransportResponseError(IntelligenceTransportError):
    """The HTTP response metadata or body contract was invalid."""

    error_code = "invalid_response"


__all__ = [
    "CollectionIncompleteError",
    "CollectionIntegrityError",
    "ExternalIntelligenceError",
    "HTTPStatusTransportError",
    "IntelligenceParseError",
    "IntelligenceSchemaError",
    "IntelligenceTransportError",
    "InvalidTransportResponseError",
    "MalformedIntelligenceJSONError",
    "NetworkTransportError",
    "QueryNormalizationError",
    "ResponseTooLargeError",
    "TransportTimeoutError",
]
