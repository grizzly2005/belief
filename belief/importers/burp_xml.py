"""Passive Burp XML importer with request/response redaction."""

from __future__ import annotations

import base64
import xml.etree.ElementTree as ET
from pathlib import Path

from belief.tool_results.io import sanitize_for_json
from belief.tools.schemas import AccessObservation, NormalizedToolResult


def import_burp_xml(path: str | Path) -> NormalizedToolResult:
    root = ET.fromstring(Path(path).read_text(encoding="utf-8"))
    observations = []
    raw_items = []
    for item in root.findall(".//item"):
        method = _text(item.find("method")) or "REQUEST"
        url = _text(item.find("url"))
        request_text = _maybe_b64(_text(item.find("request")), item.find("request"))
        response_text = _maybe_b64(_text(item.find("response")), item.find("response"))
        observations.append(AccessObservation(
            source_tool="burp",
            actor=None,
            role=None,
            method=method.upper(),
            path=_path(url),
            object_type=None,
            object_id_source=None,
            action="observed_http_request",
            expected_guard=None,
            mutation=method.upper() in {"POST", "PUT", "PATCH", "DELETE"},
            response_exposes_object=bool(response_text),
            confidence="imported",
            evidence=["burp item import"],
        ))
        raw_items.append(sanitize_for_json({"url": url, "request": request_text, "response": response_text}))
    return NormalizedToolResult(tool_id="burp", access_observations=observations, raw={"items": raw_items})


def _text(node) -> str:
    return (node.text or "").strip() if node is not None else ""


def _maybe_b64(text: str, node) -> str:
    if node is not None and (node.attrib.get("base64") or "").lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def _path(url: str) -> str:
    from urllib.parse import urlparse

    return urlparse(url).path or "/"


__all__ = ["import_burp_xml"]
