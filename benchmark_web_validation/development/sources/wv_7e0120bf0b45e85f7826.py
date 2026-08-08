from __future__ import annotations

from functools import wraps
from pathlib import Path

from flask import Flask, abort, request

app = Flask(__name__)

ASSET_ROOT = Path("/srv/belief/assets").resolve()

def _read_asset(candidate: Path) -> str:
    return candidate.read_text(encoding="utf-8")


def load_asset(raw_path: str) -> str:
    safe_name = Path(raw_path).name
    candidate = (ASSET_ROOT / safe_name).resolve()
    if not candidate.is_relative_to(ASSET_ROOT):
        abort(404)
    content = _read_asset(candidate)
    return content


@app.get("/assets")
def asset_route():
    raw_path = request.args.get("path", "")
    return {"content": load_asset(raw_path)}
