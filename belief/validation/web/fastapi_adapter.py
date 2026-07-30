"""Transparent FastAPI fixtures exercised through a local ASGI transport."""

import copy
import json
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any, Coroutine
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from ..worker.registry import RegisteredFixtureResult
from ._shared import (
    ClientResponse,
    PathPolicy,
    ResourcePolicy,
    idor_observations,
    initial_resources,
    path_observations,
    prepare_path_layout,
)


def prepare_fastapi_path_app(
    temporary_root: Path,
    parameters: Mapping[str, Any],
    *,
    application_id: str,
    policy: PathPolicy,
) -> Callable[[], RegisteredFixtureResult]:
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

    def execute() -> RegisteredFixtureResult:
        def requester(value: str) -> ClientResponse:
            return _asgi_request(
                app,
                method="GET",
                path="/files",
                query={"path": value},
            )
        observations, limitations = path_observations(
            requester,
            layout,
            include_symlink=include_symlink,
        )
        return RegisteredFixtureResult(
            observations=observations,
            limitations=limitations,
            capability_used="fastapi_local_asgi_transport",
        )

    return execute


def prepare_fastapi_idor_app(
    *,
    application_id: str,
    policy: ResourcePolicy,
) -> Callable[[], RegisteredFixtureResult]:
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

    def execute() -> RegisteredFixtureResult:
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

        def snapshot() -> dict[str, dict[str, str]]:
            return copy.deepcopy(resources)

        observations, limitations = idor_observations(
            requester,
            snapshot,
        )
        return RegisteredFixtureResult(
            observations=observations,
            limitations=limitations,
            capability_used="fastapi_local_asgi_transport",
        )

    return execute


def _asgi_request(
    app: Any,
    *,
    method: str,
    path: str,
    query: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    json_body: Mapping[str, Any] | None = None,
) -> ClientResponse:
    """Call a simple ASGI app directly without an event loop or socket."""

    encoded_body = (
        json.dumps(
            dict(json_body),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if json_body is not None
        else b""
    )
    encoded_headers = [
        (name.lower().encode("ascii"), value.encode("utf-8"))
        for name, value in (headers or {}).items()
    ]
    if json_body is not None:
        encoded_headers.append((b"content-type", b"application/json"))
    encoded_headers.append(
        (b"content-length", str(len(encoded_body)).encode("ascii"))
    )
    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("ascii"),
        "query_string": urlencode(query or {}).encode("ascii"),
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
    outgoing: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if incoming:
            return incoming.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        outgoing.append(dict(message))

    _drive_local_coroutine(app(scope, receive, send))
    start = next(
        (
            message
            for message in outgoing
            if message.get("type") == "http.response.start"
        ),
        {},
    )
    body = b"".join(
        message.get("body", b"")
        for message in outgoing
        if message.get("type") == "http.response.body"
    )
    decoded = json.loads(body.decode("utf-8")) if body else {}
    return ClientResponse(
        status_code=int(start.get("status", 500)),
        body=decoded if isinstance(decoded, dict) else {},
    )


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
    "prepare_fastapi_idor_app",
    "prepare_fastapi_path_app",
]
