from __future__ import annotations

from functools import wraps
from pathlib import Path

from application_policy import resolve_asset as external_resolve_asset

from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()

ASSET_ROOT = Path("/srv/belief/assets").resolve()

def _read_asset(candidate: Path) -> str:
    return candidate.read_text(encoding="utf-8")


def load_asset(raw_path: str) -> str:
    candidate = external_resolve_asset(raw_path, ASSET_ROOT)
    content = _read_asset(candidate)
    return content


@app.get("/assets")
async def asset_route(path: str):
    return {"content": load_asset(path)}
