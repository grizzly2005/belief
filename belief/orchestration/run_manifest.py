"""Run manifest writer for BELIEF orchestration v1."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_run_manifest(output_dir: str | Path, payload: dict[str, Any]) -> dict[str, Any]:
    manifest = {
        "schema_version": "belief.run_manifest.v1",
        **payload,
    }
    output = Path(output_dir) / "metadata" / "run-manifest.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


__all__ = ["write_run_manifest"]
