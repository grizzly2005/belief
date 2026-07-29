from __future__ import annotations

from dataclasses import dataclass
from functools import wraps

from application_policy import authorize_resource as external_authorize_resource

from flask import Flask, abort, request

app = Flask(__name__)

RESOURCES = {
    "resource_a": {
        "resource_id": "resource_a",
        "owner_id": "user_a",
        "tenant_id": "tenant_a",
        "value": "alpha",
        "last_viewed_by": "",
    },
    "resource_b": {
        "resource_id": "resource_b",
        "owner_id": "user_b",
        "tenant_id": "tenant_a",
        "value": "bravo",
        "last_viewed_by": "",
    },
    "resource_c": {
        "resource_id": "resource_c",
        "owner_id": "user_a",
        "tenant_id": "tenant_b",
        "value": "charlie",
        "last_viewed_by": "",
    },
}


def _field(resource: dict[str, str], name: str) -> str:
    return str(resource[name])


def _touch(resource: dict[str, str], user_id: str) -> None:
    resource["last_viewed_by"] = user_id


def _serialize(resource: dict[str, str]) -> dict[str, str]:
    return {
        "resource_id": resource["resource_id"],
        "value": resource["value"],
    }

def resource_boundary(handler):
    @wraps(handler)
    def wrapped(resource_id: str):
        user_id = request.headers.get("X-User-ID", "")
        tenant_id = request.headers.get("X-Tenant-ID", "")
        resource = RESOURCES.get(resource_id)
        if resource is None:
            abort(404)
        if not external_authorize_resource(user_id, tenant_id, resource):
            abort(403)
        selected = resource
        payload = _serialize(selected)
        return handler(resource_id, payload)
    return wrapped


@app.get("/resources/<resource_id>")
@resource_boundary
def resource_route(
    resource_id: str,
    payload: dict[str, str],
):
    return payload
