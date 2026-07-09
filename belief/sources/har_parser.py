"""
har_parser — replay an HTTP Archive (HAR) file as BELIEF BehaviorObservations.

HAR is a JSON format exported by every major browser DevTools (Chrome,
Firefox, Safari) and by proxies (mitmproxy, Burp, ZAP). Schema:
https://www.w3.org/TR/HAR/ (draft but stable de facto).

Why this matters for BELIEF:
- A pentester records a session in Burp/DevTools, saves as .har
- BELIEF replays it offline, no network needed, 100% reproducible
- Each request/response pair becomes a BehaviorObservation
- Offline source adapters can then generate BELIEF-compatible observations

The HAR parser here is STANDALONE — pure Python stdlib, no deps.
Output is a list of dicts compatible with BELIEF's offline observation shape.

Supported input formats:
- .har (Chrome / Firefox / mitmproxy / Burp "Save All in HAR")
- .har.zip (zipped single HAR — common from ZAP)

Not supported here (use burp_parser for those):
- .saz (Fiddler)
- .burp (Burp project file — binary)
- .nessus
"""
from __future__ import annotations

import gzip
import json
import logging
import urllib.parse
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger("belief.sources.har")


@dataclass
class HarEntry:
    """A single request/response pair extracted from a HAR file.

    Field names intentionally match BELIEF's offline HTTP observation shape.
    """
    url: str
    method: str
    status_code: int
    request_headers: Dict[str, str] = field(default_factory=dict)
    response_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None
    response_body: Optional[str] = None
    response_size: int = 0
    response_time_ms: int = 0
    path: str = ""
    query: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[str] = None
    mime_type: str = ""

    @property
    def host(self) -> str:
        return urllib.parse.urlparse(self.url).netloc


def _read_har_file(path: str) -> Dict[str, Any]:
    """Read a HAR file, handling .har, .har.zip, and gzip-compressed variants."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    if p.suffix.lower() == ".zip":
        with zipfile.ZipFile(p) as zf:
            # Take first .har inside
            har_names = [n for n in zf.namelist() if n.lower().endswith(".har")]
            if not har_names:
                raise ValueError(f"no .har inside {path}")
            with zf.open(har_names[0]) as f:
                return json.loads(f.read().decode("utf-8"))
    raw = p.read_bytes()
    if raw[:2] == b"\x1f\x8b":  # gzip magic
        raw = gzip.decompress(raw)
    return json.loads(raw.decode("utf-8"))


def _headers_list_to_dict(hdrs: Iterable[Dict[str, str]]) -> Dict[str, str]:
    """Collapse HAR's {'name': ..., 'value': ...} list to a flat dict.
    Duplicate headers: last one wins (HAR is explicit about preserving order,
    but for belief extraction we only need presence/value)."""
    out: Dict[str, str] = {}
    for h in hdrs or []:
        name = (h.get("name") or "").strip()
        value = h.get("value") or ""
        if name:
            out[name] = value
    return out


def _query_list_to_dict(q: Iterable[Dict[str, str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for item in q or []:
        name = item.get("name") or ""
        if name:
            out[name] = item.get("value", "")
    return out


def parse_har(path: str) -> List[HarEntry]:
    """Parse a HAR file, return every request/response as a HarEntry.

    Entries are returned in the order they appear in the HAR (i.e. chronological).
    """
    data = _read_har_file(path)
    log = data.get("log") or {}
    raw_entries = log.get("entries") or []
    out: List[HarEntry] = []
    for idx, e in enumerate(raw_entries):
        try:
            req = e.get("request", {}) or {}
            resp = e.get("response", {}) or {}
            url = req.get("url", "")
            if not url:
                continue
            parsed = urllib.parse.urlparse(url)

            # Request body: HAR puts it under request.postData.text
            req_body = None
            pd = req.get("postData") or {}
            if pd.get("text"):
                req_body = pd["text"]
            elif pd.get("params"):
                # form-encoded params
                req_body = "&".join(
                    f"{p.get('name','')}={p.get('value','')}" for p in pd["params"]
                )

            # Response body: HAR puts it under response.content.text
            resp_body = None
            cnt = resp.get("content") or {}
            if cnt.get("text") is not None:
                text = cnt["text"]
                if cnt.get("encoding") == "base64":
                    import base64
                    try:
                        resp_body = base64.b64decode(text).decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        resp_body = None
                else:
                    resp_body = text

            entry = HarEntry(
                url=url,
                method=(req.get("method") or "GET").upper(),
                status_code=int(resp.get("status") or 0),
                request_headers=_headers_list_to_dict(req.get("headers", [])),
                response_headers=_headers_list_to_dict(resp.get("headers", [])),
                request_body=req_body,
                response_body=resp_body,
                response_size=int(cnt.get("size") or 0),
                response_time_ms=int(e.get("time") or 0),
                path=parsed.path or "/",
                query=_query_list_to_dict(req.get("queryString", [])),
                timestamp=e.get("startedDateTime"),
                mime_type=(cnt.get("mimeType") or ""),
            )
            out.append(entry)
        except Exception as ex:
            logger.debug(f"skip HAR entry {idx}: {ex}")
            continue
    logger.info(f"parsed {len(out)} entries from {path}")
    return out


def filter_entries(
    entries: List[HarEntry],
    *,
    methods: Optional[List[str]] = None,
    hosts: Optional[List[str]] = None,
    status_min: int = 0,
    status_max: int = 999,
    path_contains: Optional[str] = None,
    exclude_static: bool = True,
) -> List[HarEntry]:
    """Filter a HAR entry list. Default excludes static assets (images, fonts, css)."""
    STATIC_EXTS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                   ".woff", ".woff2", ".ttf", ".otf", ".eot",
                   ".css", ".map")
    out: List[HarEntry] = []
    for e in entries:
        if methods and e.method not in methods:
            continue
        if hosts and e.host not in hosts:
            continue
        if not (status_min <= e.status_code <= status_max):
            continue
        if path_contains and path_contains not in e.path:
            continue
        if exclude_static and any(e.path.lower().endswith(ext) for ext in STATIC_EXTS):
            continue
        out.append(e)
    return out


def to_observations(entries: List[HarEntry]) -> List[Dict[str, Any]]:
    """Convert HarEntry list to flat offline HTTP observation dictionaries."""
    obs = []
    for e in entries:
        obs.append({
            "url": e.url,
            "method": e.method,
            "path": e.path,
            "request_headers": e.request_headers,
            "request_body": e.request_body,
            "status_code": e.status_code,
            "response_headers": e.response_headers,
            "response_body": e.response_body,
            "response_size": e.response_size,
            "response_time_ms": e.response_time_ms,
            "timestamp": e.timestamp,
            "mime_type": e.mime_type,
        })
    return obs


def har_summary(path: str) -> Dict[str, Any]:
    """Quick stats on a HAR, useful before running full extraction."""
    entries = parse_har(path)
    hosts: Dict[str, int] = {}
    methods: Dict[str, int] = {}
    statuses: Dict[int, int] = {}
    for e in entries:
        hosts[e.host] = hosts.get(e.host, 0) + 1
        methods[e.method] = methods.get(e.method, 0) + 1
        statuses[e.status_code] = statuses.get(e.status_code, 0) + 1
    return {
        "total_entries": len(entries),
        "hosts": hosts,
        "methods": methods,
        "statuses": statuses,
    }


__all__ = [
    "HarEntry", "parse_har", "filter_entries",
    "to_observations", "har_summary",
]
