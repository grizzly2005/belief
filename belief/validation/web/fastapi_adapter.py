"""Bounded synchronous ASGI micro-harness for FastAPI fixture applications.

This is deliberately not a general ASGI transport.  It supports one local
HTTP request, immediate in-process awaits, bounded headers and bodies, and no
lifespan, streaming, background task, socket, or external event-loop behavior.
It contains no oracle expectations.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Coroutine
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .fixtures.apps.contracts import (
    ClientResponse,
    PathApplication,
    ResourceApplication,
)
from .fixtures.apps.support import (
    initial_resources,
    path_policy_alpha,
    path_policy_beta,
    path_state,
    prepare_path_layout,
    resource_policy_alpha,
    resource_policy_beta,
    resource_state,
)

_MAX_ASGI_MESSAGES = 64
_MAX_REQUEST_BODY_BYTES = 64 * 1024
_MAX_RESPONSE_BODY_BYTES = 256 * 1024
_MAX_HEADER_COUNT = 64
_MAX_HEADER_BYTES = 32 * 1024
_MAX_QUERY_BYTES = 8 * 1024
_MAX_PATH_BYTES = 4 * 1024


def prepare_fastapi_path_app(
    temporary_root: Path,
    parameters: Mapping[str, Any],
    *,
    application_id: str,
    policy_name: str,
) -> PathApplication:
    policy = {
        "alpha": path_policy_alpha,
        "beta": path_policy_beta,
    }.get(policy_name)
    if policy is None:
        raise ValueError("unknown closed path application policy")
    include_symlink = parameters.get("include_symlink", True)
    layout = prepare_path_layout(
        temporary_root / "fixture",
        include_symlink=include_symlink,
    )
    app = FastAPI(title=f"belief_{application_id}")

    @app.get("/files")
    async def read_file(path: str):
        status, body = policy(
            layout,
            path,
        )
        return JSONResponse(status_code=status, content=body)

    def requester(value: str) -> ClientResponse:
        return _asgi_request(
            app,
            method="GET",
            path="/files",
            query={"path": value},
        )

    return PathApplication(
        request=requester,
        state=lambda: path_state(layout),
        absolute_outside_stimulus=str(layout.sentinel),
        symlink_supported=layout.symlink_supported,
    )


def prepare_fastapi_idor_app(
    *,
    application_id: str,
    policy_name: str,
) -> ResourceApplication:
    policy = {
        "alpha": resource_policy_alpha,
        "beta": resource_policy_beta,
    }.get(policy_name)
    if policy is None:
        raise ValueError("unknown closed resource application policy")
    resources = initial_resources()
    app = FastAPI(title=f"belief_{application_id}")

    @app.get("/resources/{resource_id}")
    async def read_resource(resource_id: str, request: Request):
        status, body = policy(
            resources,
            method="GET",
            resource_id=resource_id,
            user_id=request.headers.get("X-User-ID", ""),
            tenant_id=request.headers.get("X-Tenant-ID", ""),
            value="",
        )
        return JSONResponse(status_code=status, content=body)

    @app.patch("/resources/{resource_id}")
    async def update_resource(resource_id: str, request: Request):
        payload = await request.json()
        value = (
            str(payload.get("value") or "")
            if isinstance(payload, dict)
            else ""
        )
        status, body = policy(
            resources,
            method="PATCH",
            resource_id=resource_id,
            user_id=request.headers.get("X-User-ID", ""),
            tenant_id=request.headers.get("X-Tenant-ID", ""),
            value=value,
        )
        return JSONResponse(status_code=status, content=body)

    def requester(
        method: str,
        resource_id: str,
        user_id: str,
        tenant_id: str,
        value: str,
    ) -> ClientResponse:
        return _asgi_request(
            app,
            method=method,
            path=f"/resources/{resource_id}",
            headers={
                "X-User-ID": user_id,
                "X-Tenant-ID": tenant_id,
            },
            json_body=(
                {"value": value} if method == "PATCH" else None
            ),
        )

    return ResourceApplication(
        request=requester,
        state=lambda: resource_state(resources),
    )


def _asgi_request(
    app: Any,
    *,
    method: str,
    path: str,
    query: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Mapping[str, Any] | None = None,
) -> ClientResponse:
    """Call one simple ASGI app under fail-closed in-memory limits."""

    encoded_body = (
        json.dumps(
            dict(json_body),
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        if json_body is not None
        else b""
    )
    if len(encoded_body) > _MAX_REQUEST_BODY_BYTES:
        raise RuntimeError("local ASGI request body exceeds its byte bound")
    raw_path = path.encode("ascii")
    if len(raw_path) > _MAX_PATH_BYTES:
        raise RuntimeError("local ASGI path exceeds its byte bound")
    query_string = urlencode(query or {}).encode("ascii")
    if len(query_string) > _MAX_QUERY_BYTES:
        raise RuntimeError("local ASGI query exceeds its byte bound")
    encoded_headers = [
        (name.lower().encode("ascii"), value.encode("utf-8"))
        for name, value in (headers or {}).items()
    ]
    if json_body is not None:
        encoded_headers.append((b"content-type", b"application/json"))
    encoded_headers.append(
        (b"content-length", str(len(encoded_body)).encode("ascii"))
    )
    _validate_headers(encoded_headers)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": raw_path,
        "query_string": query_string,
        "root_path": "",
        "headers": encoded_headers,
        "client": None,
        "server": None,
    }
    incoming = [{
        "type": "http.request",
        "body": encoded_body,
        "more_body": False,
    }]
    response_status: int | None = None
    response_body = bytearray()
    response_complete = False
    message_count = 0

    async def receive() -> dict[str, Any]:
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        nonlocal message_count
        nonlocal response_complete
        nonlocal response_status

        message_count += 1
        if message_count > _MAX_ASGI_MESSAGES:
            raise RuntimeError("local ASGI response exceeded its message bound")
        message_type = message.get("type")
        if message_type == "http.response.start":
            if response_status is not None or response_complete:
                raise RuntimeError("local ASGI response start was repeated")
            status = message.get("status")
            if not isinstance(status, int) or not 100 <= status <= 599:
                raise RuntimeError("local ASGI response status is invalid")
            raw_headers = message.get("headers", [])
            if not isinstance(raw_headers, (list, tuple)):
                raise RuntimeError("local ASGI response headers are invalid")
            _validate_headers(raw_headers)
            response_status = status
            return
        if message_type != "http.response.body":
            raise RuntimeError("local ASGI emitted an unsupported message type")
        if response_status is None or response_complete:
            raise RuntimeError("local ASGI response body ordering is invalid")
        body_chunk = message.get("body", b"")
        if not isinstance(body_chunk, bytes):
            raise RuntimeError("local ASGI response body is not bytes")
        if len(response_body) + len(body_chunk) > _MAX_RESPONSE_BODY_BYTES:
            raise RuntimeError("local ASGI response body exceeds its byte bound")
        response_body.extend(body_chunk)
        more_body = message.get("more_body", False)
        if not isinstance(more_body, bool):
            raise RuntimeError("local ASGI response continuation is invalid")
        response_complete = not more_body

    _drive_local_coroutine(app(scope, receive, send))
    if response_status is None or not response_complete:
        raise RuntimeError("local ASGI response did not complete")
    decoded = (
        json.loads(
            response_body.decode("utf-8"),
            parse_constant=_reject_json_constant,
        )
        if response_body
        else {}
    )
    return ClientResponse(
        status_code=response_status,
        body=decoded if isinstance(decoded, dict) else {},
    )


def _validate_headers(headers: Any) -> None:
    if len(headers) > _MAX_HEADER_COUNT:
        raise RuntimeError("local ASGI headers exceed their count bound")
    total_bytes = 0
    for item in headers:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise RuntimeError("local ASGI header entry is invalid")
        name, value = item
        if not isinstance(name, bytes) or not isinstance(value, bytes):
            raise RuntimeError("local ASGI header values are not bytes")
        total_bytes += len(name) + len(value)
        if total_bytes > _MAX_HEADER_BYTES:
            raise RuntimeError("local ASGI headers exceed their byte bound")


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _drive_local_coroutine(coroutine: Coroutine[Any, Any, Any]) -> None:
    """Drive an ASGI call that may only await immediately local operations."""

    iterator = coroutine.__await__()
    value: Any = None
    for _step in range(1_000):
        try:
            pending = iterator.send(value)
        except StopIteration:
            return
        value = None
        if pending is None:
            continue
        done = getattr(pending, "done", None)
        result = getattr(pending, "result", None)
        if callable(done) and done() and callable(result):
            value = result()
            continue
        raise RuntimeError(
            "local ASGI fixture attempted a non-local async operation"
        )
    raise RuntimeError("local ASGI fixture exceeded its operation bound")


__all__ = [
    "_asgi_request",
    "prepare_fastapi_idor_app",
    "prepare_fastapi_path_app",
]
