from __future__ import annotations

from functools import wraps
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)

ASSET_ROOT = Path("/srv/belief/assets").resolve()

def _read_asset(candidate: Path) -> str:
    return candidate.read_text(encoding="utf-8")


def asset_boundary(handler):
    @wraps(handler)
    def wrapped():
        raw_path = request.args.get("path", "")
        candidate = (ASSET_ROOT / raw_path).resolve()
        content = _read_asset(candidate)
        if not candidate.is_relative_to(ASSET_ROOT):
            abort(404)
        return handler(content)
    return wrapped


@app.get("/assets")
@asset_boundary
def asset_route(content: str):
    return {"content": content}
