import io

import pytest

from belief.api_server import APIServer, BeliefAPIHandler, MAX_LIST_LIMIT, MAX_REQUEST_BYTES, is_loopback_host


def _handler():
    handler = object.__new__(BeliefAPIHandler)
    handler.reports = {}
    return handler


def test_api_list_limit_is_bounded_and_invalid_values_do_not_raise():
    handler = _handler()

    assert handler._list_beliefs({"limit": ["not-a-number"]})["beliefs"] == []
    assert handler._list_beliefs({"limit": [str(MAX_LIST_LIMIT + 100)]})["total"] == 0


def test_api_rejects_oversized_analyze_body_without_reading_it():
    handler = _handler()
    responses = []
    handler.headers = {"Content-Length": str(MAX_REQUEST_BYTES + 1)}
    handler.rfile = io.BytesIO(b"should not be read")
    handler._json_response = lambda data, status=200: responses.append((data, status))

    handler._handle_analyze()

    assert responses == [({"error": "Request body is too large"}, 413)]


def test_api_rejects_invalid_content_length():
    handler = _handler()
    responses = []
    handler.headers = {"Content-Length": "invalid"}
    handler.rfile = io.BytesIO()
    handler._json_response = lambda data, status=200: responses.append((data, status))

    handler._handle_analyze()

    assert responses == [({"error": "Invalid Content-Length"}, 400)]


def test_api_public_bind_requires_explicit_opt_in():
    assert is_loopback_host("127.0.0.1") is True
    assert is_loopback_host("localhost") is True
    assert is_loopback_host("0.0.0.0") is False

    with pytest.raises(ValueError, match="non-loopback"):
        APIServer(host="0.0.0.0").start()
