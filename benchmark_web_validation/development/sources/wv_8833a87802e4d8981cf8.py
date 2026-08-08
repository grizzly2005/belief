from __future__ import annotations

from dataclasses import dataclass
from functools import wraps

from fastapi import Depends, FastAPI, HTTPException, Request

app = FastAPI()

@dataclass
class Resource:
    resource_id: str
    owner_id: str
    tenant_id: str
    value: str
    last_viewed_by: str = ""


RESOURCES = {
    "resource_a": Resource(
        "resource_a", "user_a", "tenant_a", "alpha"
    ),
    "resource_b": Resource(
        "resource_b", "user_b", "tenant_a", "bravo"
    ),
    "resource_c": Resource(
        "resource_c", "user_a", "tenant_b", "charlie"
    ),
}


def _field(resource: Resource, name: str) -> str:
    return str(getattr(resource, name))


def _touch(resource: Resource, user_id: str) -> None:
    resource.last_viewed_by = user_id


def _serialize(resource: Resource) -> dict[str, str]:
    return {
        "resource_id": resource.resource_id,
        "value": resource.value,
    }

@app.get("/resources/{resource_id}")
async def resource_route(resource_id: str, request: Request):
    user_id = request.headers.get("X-User-ID", "")
    tenant_id = request.headers.get("X-Tenant-ID", "")
    resource = RESOURCES.get(resource_id)
    if resource is None:
        raise HTTPException(status_code=404)
    if (_field(resource, "owner_id") != user_id or _field(resource, "tenant_id") != tenant_id):
        raise HTTPException(status_code=403)
    selected = resource
    payload = _serialize(selected)
    return payload
