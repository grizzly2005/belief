from __future__ import annotations

from functools import wraps
from pathlib import Path

from application_policy import resolve_asset as external_resolve_asset

from flask import Flask, abort, request

app = Flask(__name__)

ASSET_ROOT = Path("/srv/belief/assets").resolve()

def _read_asset(candidate: Path) -> str:
    return candidate.read_text(encoding="utf-8")


def asset_boundary(handler):
    @wraps(handler)
    def wrapped():
        raw_path = request.args.get("path", "")
        candidate = external_resolve_asset(raw_path, ASSET_ROOT)
        content = _read_asset(candidate)
        return handler(content)
    return wrapped


@app.get("/assets")
@asset_boundary
def asset_route(content: str):
    return {"content": content}
