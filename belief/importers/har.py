"""Passive HAR importer with header redaction."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from belief.tool_results.io import sanitize_for_json
from belief.tools.schemas import AccessObservation, NormalizedToolResult


def import_har(path: str | Path) -> NormalizedToolResult:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = payload.get("log", {}).get("entries", []) if isinstance(payload, dict) else []
    observations = []
    for entry in entries if isinstance(entries, list) else []:
        request = entry.get("request") if isinstance(entry, dict) and isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry, dict) and isinstance(entry.get("response"), dict) else {}
        url_path = _path(_str(request.get("url")))
        observations.append(AccessObservation(
            source_tool="har",
            actor=None,
            role=None,
            method=_str(request.get("method")) or None,
            path=url_path,
            object_type=None,
            object_id_source=None,
            action="observed_http_request",
            expected_guard=None,
            mutation=_str(request.get("method")).upper() in {"POST", "PUT", "PATCH", "DELETE"},
            response_exposes_object=int(response.get("status") or 0) < 400 if response else False,
            confidence="imported",
            evidence=[f"status={response.get('status')}"] if response.get("status") else [],
        ))
    return NormalizedToolResult(
        tool_id="har",
        access_observations=observations,
        raw=sanitize_for_json({"entry_count": len(observations)}),
    )


def _path(url: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(url)
    return parsed.path or "/"


def _str(value: Any) -> str:
    return str(value or "").strip()


__all__ = ["import_har"]
