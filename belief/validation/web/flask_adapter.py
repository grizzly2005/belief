"""Transparent Flask fixtures exercised only through ``test_client()``."""

from __future__ import annotations

import copy
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

from ..worker.registry import (
    FixtureSpec,
    RegisteredFixtureResult,
)
from ._shared import (
    ClientResponse,
    idor_observations,
    initial_resources,
    path_observations,
    prepare_path_layout,
    serve_path,
    serve_resource,
)


def run_flask_fixture(
    spec: FixtureSpec,
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> RegisteredFixtureResult:
    return prepare_flask_fixture(spec, temporary_root, parameters)()


def prepare_flask_fixture(
    spec: FixtureSpec,
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> Callable[[], RegisteredFixtureResult]:
    if spec.case_type == "path_traversal_possible":
        return _prepare_path_fixture(spec, temporary_root, parameters)
    if spec.case_type == "idor_bola_possible":
        return _prepare_idor_fixture(spec)
    raise ValueError("unsupported Flask fixture case type")


def _prepare_path_fixture(
    spec: FixtureSpec,
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> Callable[[], RegisteredFixtureResult]:
    include_symlink = parameters.get("include_symlink", True)
    layout = prepare_path_layout(
        temporary_root / "fixture",
        include_symlink=include_symlink,
    )
    app = Flask(f"belief_{spec.fixture_id}")
    app.config.update(TESTING=True)

    @app.get("/files")
    def read_file():
        status, body = serve_path(
            layout,
            request.args.get("path", ""),
            protected=spec.security_enforced,
        )
        return jsonify(body), status

    client = app.test_client()

    def execute() -> RegisteredFixtureResult:
        with client:
            def requester(value: str) -> ClientResponse:
                response = client.get(
                    "/files",
                    query_string={"path": value},
                )
                body = response.get_json(silent=True)
                return ClientResponse(
                    status_code=response.status_code,
                    body=body if isinstance(body, dict) else {},
                )

            observations, limitations = path_observations(
                requester,
                layout,
                include_symlink=include_symlink,
            )
        return RegisteredFixtureResult(
            observations=observations,
            limitations=limitations,
            capability_used="flask_test_client",
        )

    return execute


def _prepare_idor_fixture(
    spec: FixtureSpec,
) -> Callable[[], RegisteredFixtureResult]:
    resources = initial_resources()
    app = Flask(f"belief_{spec.fixture_id}")
    app.config.update(TESTING=True)

    @app.route("/resources/<resource_id>", methods=["GET", "PATCH"])
    def resource(resource_id: str):
        payload = request.get_json(silent=True)
        value = (
            str(payload.get("value") or "")
            if isinstance(payload, dict)
            else ""
        )
        status, body = serve_resource(
            resources,
            method=request.method,
            resource_id=resource_id,
            user_id=request.headers.get("X-User-ID", ""),
            tenant_id=request.headers.get("X-Tenant-ID", ""),
            value=value,
            protected=spec.security_enforced,
        )
        return jsonify(body), status

    client = app.test_client()

    def execute() -> RegisteredFixtureResult:
        with client:
            def requester(
                method: str,
                resource_id: str,
                user_id: str,
                tenant_id: str,
                value: str,
            ) -> ClientResponse:
                headers = {
                    "X-User-ID": user_id,
                    "X-Tenant-ID": tenant_id,
                }
                if method == "GET":
                    response = client.get(
                        f"/resources/{resource_id}",
                        headers=headers,
                    )
                else:
                    response = client.patch(
                        f"/resources/{resource_id}",
                        headers=headers,
                        json={"value": value},
                    )
                body = response.get_json(silent=True)
                return ClientResponse(
                    status_code=response.status_code,
                    body=body if isinstance(body, dict) else {},
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
            capability_used="flask_test_client",
        )

    return execute


__all__ = ["prepare_flask_fixture", "run_flask_fixture"]
