from __future__ import annotations

from functools import wraps
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException

app = FastAPI()

ASSET_ROOT = Path("/srv/belief/assets").resolve()

def _read_asset(candidate: Path) -> str:
    return candidate.read_text(encoding="utf-8")


def load_asset(path: str) -> str:
    raw_path = path
    decoy_candidate = (ASSET_ROOT / raw_path).resolve()
    _ = str(decoy_candidate)
    safe_name = Path(raw_path).name
    candidate = (ASSET_ROOT / safe_name).resolve()
    if not candidate.is_relative_to(ASSET_ROOT):
        raise HTTPException(status_code=404)
    content = _read_asset(candidate)
    return content


@app.get("/assets")
async def asset_route(content: str = Depends(load_asset)):
    return {"content": content}
