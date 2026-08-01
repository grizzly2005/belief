"""Flask system-under-test adapter; it contains no oracle expectations."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, request

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


def prepare_flask_path_app(
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
    app = Flask(
        f"belief_{application_id}",
        root_path=str(temporary_root),
        instance_path=str(temporary_root / "instance"),
    )
    app.config.update(TESTING=True)

    @app.get("/files")
    def read_file():
        status, body = policy(
            layout,
            request.args.get("path", ""),
        )
        return jsonify(body), status

    client = app.test_client()

    def requester(value: str) -> ClientResponse:
        with client:
            response = client.get(
                "/files",
                query_string={"path": value},
            )
            body = response.get_json(silent=True)
            return ClientResponse(
                status_code=response.status_code,
                body=body if isinstance(body, dict) else {},
            )

    return PathApplication(
        request=requester,
        state=lambda: path_state(layout),
        absolute_outside_stimulus=str(layout.sentinel),
        symlink_supported=layout.symlink_supported,
    )


def prepare_flask_idor_app(
    temporary_root: Path,
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
    app = Flask(
        f"belief_{application_id}",
        root_path=str(temporary_root),
        instance_path=str(temporary_root / "instance"),
    )
    app.config.update(TESTING=True)

    @app.route("/resources/<resource_id>", methods=["GET", "PATCH"])
    def resource(resource_id: str):
        payload = request.get_json(silent=True)
        value = (
            str(payload.get("value") or "")
            if isinstance(payload, dict)
            else ""
        )
        status, body = policy(
            resources,
            method=request.method,
            resource_id=resource_id,
            user_id=request.headers.get("X-User-ID", ""),
            tenant_id=request.headers.get("X-Tenant-ID", ""),
            value=value,
        )
        return jsonify(body), status

    client = app.test_client()

    def requester(
        method: str,
        resource_id: str,
        user_id: str,
        tenant_id: str,
        value: str,
    ) -> ClientResponse:
        with client:
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

    return ResourceApplication(
        request=requester,
        state=lambda: resource_state(resources),
    )


__all__ = [
    "prepare_flask_idor_app",
    "prepare_flask_path_app",
]
