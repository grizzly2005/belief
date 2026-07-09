"""Artifact detection for API, traffic, PDX, and IaC files."""

from __future__ import annotations

import json
from pathlib import Path


def detect_artifacts(files: list[Path]) -> dict[str, list[str]]:
    api_files: list[str] = []
    traffic_files: list[str] = []
    pdx_files: list[str] = []
    iac_files: list[str] = []

    for path in files:
        rel = path.as_posix()
        suffix = path.suffix.lower()
        name = path.name.lower()
        if suffix == ".tf":
            iac_files.append(rel)
        if suffix in {".yaml", ".yml"}:
            text = _read_small(path).lower()
            if "apiversion:" in text and "kind:" in text:
                iac_files.append(rel)
            if "openapi:" in text or "swagger:" in text:
                api_files.append(rel)
        if suffix == ".har" or name.endswith(".har"):
            traffic_files.append(rel)
        if suffix == ".xml":
            text = _read_small(path).lower()
            if "<items" in text and "<request" in text and "<response" in text:
                traffic_files.append(rel)
        if suffix == ".json":
            payload = _read_json(path)
            if isinstance(payload, dict):
                if "openapi" in payload or "swagger" in payload:
                    api_files.append(rel)
                if isinstance(payload.get("log"), dict) and isinstance(payload["log"].get("entries"), list):
                    traffic_files.append(rel)
                if payload.get("schema_version") == "belief.pdx.v1" or {"meta", "deltas", "verdicts"} <= set(payload):
                    pdx_files.append(rel)
    return {
        "api_files": sorted(set(api_files)),
        "traffic_files": sorted(set(traffic_files)),
        "pdx_files": sorted(set(pdx_files)),
        "iac_files": sorted(set(iac_files)),
    }


def _read_small(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:20000]
    except OSError:
        return ""


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


__all__ = ["detect_artifacts"]
