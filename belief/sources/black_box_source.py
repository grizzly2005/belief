"""
black_box_source — BeliefSource that derives beliefs from HTTP observations.

Two modes:
1. HAR replay: feed a .har file, no network needed
2. Live scan: wrap belief_http_engine.BeliefHttpEngine (existing)

Both produce the same Belief sextuplets so downstream (cross-verify,
drift, report) treats them identically to white-box beliefs.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import BeliefSource, SourceMetadata
from .har_parser import parse_har, filter_entries, to_observations, HarEntry

try:
    from belief.models import (
        Belief, Predicate, Scope,
        JustificationCategory, EpistemicStatus, LogicType, ArtifactKind,
    )
    _HAVE_MODELS = True
except ImportError:
    _HAVE_MODELS = False
    Belief = None  # type: ignore

logger = logging.getLogger("belief.sources.black_box")


# Patterns that commonly denote an implicit server-side belief.
# Each maps an observation feature to a Belief sextuplet template.
_RESPONSE_PATTERNS = [
    {   # 403 vs 404 → server believes the path is protected (vs absent)
        "match": lambda e: e.status_code == 403,
        "predicate": "server.path_exists_but_requires_auth",
        "justification": "C4",
        "scope_fn": lambda e: (e.path, 0, 0),
        "logic": "semantic",
        "reason": "403 reveals existence; 404 would hide it",
    },
    {   # 429 → rate limit is enforced and trusted
        "match": lambda e: e.status_code == 429,
        "predicate": "server.rate_limit_enforces_global_quota",
        "justification": "C4",
        "scope_fn": lambda e: (e.path, 0, 0),
        "logic": "semantic",
        "reason": "429 assumes client is rate-limited; may bypass via X-Forwarded-For",
    },
    {   # 500 on arbitrary input → server trusted input format
        "match": lambda e: e.status_code >= 500,
        "predicate": "server.input_parser_handles_malformed_input",
        "justification": "C5",
        "scope_fn": lambda e: (e.path, 0, 0),
        "logic": "semantic",
        "reason": "5xx implies unhandled exception path; input validation gap",
    },
    {   # Set-Cookie without HttpOnly → client-side code trusted
        "match": lambda e: (
            "set-cookie" in {k.lower() for k in e.response_headers}
            and "httponly" not in (
                next((v for k, v in e.response_headers.items()
                      if k.lower() == "set-cookie"), "").lower()
            )
        ),
        "predicate": "server.cookies_not_accessible_to_js",
        "justification": "C5",
        "scope_fn": lambda e: (e.path, 0, 0),
        "logic": "contract",
        "reason": "HttpOnly missing → XSS can steal session",
    },
    {   # No CSP header → trust in client-side XSS filter
        "match": lambda e: (
            e.status_code < 400
            and "content-security-policy" not in {k.lower() for k in e.response_headers}
            and "text/html" in (e.mime_type or "").lower()
        ),
        "predicate": "server.html_response_cannot_inject_scripts",
        "justification": "C5",
        "scope_fn": lambda e: (e.path, 0, 0),
        "logic": "semantic",
        "reason": "No CSP → any reflected XSS is directly exploitable",
    },
    {   # Reflected query parameter in response body → possible reflected XSS
        "match": lambda e: (
            e.response_body is not None
            and any(v for v in e.query.values() if len(v) > 3
                     and v in (e.response_body or ""))
        ),
        "predicate": "server.user_input_is_sanitized_before_reflection",
        "justification": "C4",
        "scope_fn": lambda e: (e.path, 0, 0),
        "logic": "contract",
        "reason": "Query param value appears verbatim in response → possible XSS/HTMLi",
    },
]


def _entry_to_beliefs(entry: HarEntry) -> List["Belief"]:
    """Apply every pattern; emit a Belief per match."""
    if not _HAVE_MODELS:
        return []
    out: List[Belief] = []
    for pat in _RESPONSE_PATTERNS:
        try:
            if not pat["match"](entry):
                continue
        except Exception:
            continue
        path, line_start, line_end = pat["scope_fn"](entry)
        pred = Predicate(
            expression=f"{pat['predicate']}[{entry.method} {path}]",
            variables=(),
            anchor_lines=(),
            natural_language=pat["reason"],
        )
        # Use URL as the "file" since there is no code
        scope = Scope(
            file_path=f"http://{entry.host}{path}",
            function_name=f"{entry.method} {path}",
            module=entry.host,
            line_start=line_start or None,
            line_end=line_end or None,
        )
        justif_map = {
            "C1": "C1_FORMAL_VERIFICATION",
            "C2": "C2_CALLER_VERIFICATION",
            "C3": "C3_DOCUMENTED_CONVENTION",
            "C4": "C4_IMPLICIT_CONVENTION",
            "C5": "C5_NO_JUSTIFICATION",
            "C6": "C6_OPAQUE_INFERENCE",
        }
        justif = getattr(JustificationCategory,
                         justif_map.get(pat["justification"], "C5_NO_JUSTIFICATION"))
        logic_map = {"fol": "FOL", "semantic": "SEMANTIC",
                     "contract": "CONTRACT", "temporal": "TEMPORAL"}
        logic = getattr(LogicType, logic_map.get(pat["logic"], "FOL"),
                        getattr(LogicType, "FOL", list(LogicType)[0]))
        out.append(Belief(
            predicate=pred,
            scope=scope,
            justification=justif,
            epistemic_status=EpistemicStatus.BELIEF,
            logic_type=logic,
            artifact_kind=ArtifactKind.SOURCE_CODE,  # closest enum value
            confidence_score=0.6,
        ))
    return out


class HarSource(BeliefSource):
    """BeliefSource built from a HAR file."""
    kind = "black_box"

    def __init__(
        self,
        har_path: str,
        *,
        hosts: Optional[List[str]] = None,
        methods: Optional[List[str]] = None,
        exclude_static: bool = True,
    ):
        self.har_path = har_path
        self.hosts = hosts
        self.methods = methods
        self.exclude_static = exclude_static
        self._entries_cache: Optional[List[HarEntry]] = None

    def entries(self) -> List[HarEntry]:
        if self._entries_cache is None:
            raw = parse_har(self.har_path)
            self._entries_cache = filter_entries(
                raw,
                methods=self.methods,
                hosts=self.hosts,
                exclude_static=self.exclude_static,
            )
        return self._entries_cache

    def collect_beliefs(self) -> List["Belief"]:
        if not _HAVE_MODELS:
            return []
        beliefs: List[Belief] = []
        for entry in self.entries():
            beliefs.extend(_entry_to_beliefs(entry))
        logger.info(
            f"HAR {self.har_path}: {len(self.entries())} entries → {len(beliefs)} beliefs"
        )
        return beliefs

    def metadata(self) -> SourceMetadata:
        entries = self.entries()
        return SourceMetadata(
            name=f"har:{Path(self.har_path).name}",
            kind=self.kind,
            project_path=self.har_path,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            extra={
                "entries": len(entries),
                "hosts_seen": sorted({e.host for e in entries})[:20],
            },
        )


__all__ = ["HarSource"]
