"""Bounded publication policy for MCP data derived from source code."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from pathlib import Path
from typing import Any

PUBLICATION_MODES = frozenset({"minimal", "redacted", "full-local-only"})

_RAW_CONTENT_KEYS = frozenset({
    "code",
    "context",
    "line_text",
    "prompt",
    "raw",
    "snippet",
    "source_code",
    "source_text",
    "stderr",
    "stdout",
})
_UNTRUSTED_TEXT_KEYS = frozenset({
    "description",
    "evidence",
    "human_next_steps",
    "message",
    "natural_language",
    "reason",
    "remediation",
    "title",
})
_TRUSTED_POLICY_TEXT_KEYS = frozenset({
    "interpretation_boundary",
    "limitations",
    "verdict_interpretation",
})
_PATH_KEYS = frozenset({
    "anchor_file",
    "file",
    "file_path",
    "files",
    "path",
    "paths",
    "source_file",
    "source_files",
    "target",
    "workspace",
    "workspace_root",
})
_SAFE_MINIMAL_TEXT = re.compile(r"^[A-Za-z0-9_./:@%+=,# ()\[\]-]{0,512}$")
_SAFE_CODE_LABEL = re.compile(r"^[a-z][a-z0-9_]{0,127}$")
_SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|password|passwd|secret|session|token|api[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_VALUE_PATTERNS = (
    re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{6,}"),
    re.compile(
        r"(?i)\b(api[_-]?key|password|passwd|secret|token)\s*[:=]\s*"
        r"[^\s,;]{3,}"
    ),
)
_OMITTED = "[OMITTED_UNTRUSTED_SOURCE_CONTENT]"
_REDACTED = "[REDACTED]"


class MCPPublicationError(ValueError):
    """Raised when publication policy configuration is unsafe."""


class MCPPublicationPolicy:
    """Sanitize source-derived data for local MCP publication."""

    def __init__(
        self,
        *,
        workspace_root: Path,
        mode: str = "minimal",
        allow_full_local_output: bool = False,
    ) -> None:
        normalized = str(mode or "minimal").strip().lower()
        if normalized not in PUBLICATION_MODES:
            raise MCPPublicationError(
                f"unsupported MCP publication mode: {normalized!r}"
            )
        if normalized == "full-local-only" and not allow_full_local_output:
            raise MCPPublicationError(
                "full-local-only publication requires explicit local opt-in"
            )
        self.workspace_root = workspace_root.resolve(strict=True)
        self.mode = normalized

    def metadata(
        self,
        *,
        contains_untrusted_source_content: bool,
    ) -> dict[str, Any]:
        disposition = {
            "minimal": "omitted",
            "redacted": "redacted_and_bounded",
            "full-local-only": "included_bounded_local_only",
        }[self.mode]
        return {
            "mode": self.mode,
            "contains_untrusted_source_content": (
                contains_untrusted_source_content
            ),
            "untrusted_source_content_disposition": disposition,
            "secrets_redacted": True,
            "absolute_paths_exposed": False,
            "transport_scope": "local_stdio_only",
        }

    def publish(self, value: dict[str, Any]) -> dict[str, Any]:
        published = self._visit(copy.deepcopy(value), key="", depth=0)
        if not isinstance(published, dict):
            raise MCPPublicationError("published MCP payload must remain an object")
        return published

    def _visit(self, value: Any, *, key: str, depth: int) -> Any:
        if depth > 16:
            return "[TRUNCATED_DEPTH]"
        if value is None or isinstance(value, (bool, int)):
            return value
        if isinstance(value, float):
            if not math.isfinite(value):
                raise MCPPublicationError(
                    "published MCP payload contains a non-finite number"
                )
            return value
        if isinstance(value, str):
            return self._string(value, key=key)
        if isinstance(value, list):
            return [
                self._visit(item, key=key, depth=depth + 1)
                for item in value[:256]
            ]
        if isinstance(value, tuple):
            return self._visit(list(value), key=key, depth=depth)
        if isinstance(value, dict):
            clean: dict[str, Any] = {}
            for raw_key, child in list(value.items())[:256]:
                if not isinstance(raw_key, str):
                    raise MCPPublicationError(
                        "published MCP payload contains a non-string key"
                    )
                text_key = raw_key
                lowered = text_key.casefold()
                if (
                    _SENSITIVE_KEY.search(text_key)
                    and not isinstance(child, (bool, int, float))
                    and child is not None
                ):
                    clean[text_key] = _REDACTED
                    continue
                if (
                    self.mode == "minimal"
                    and lowered == "code"
                    and isinstance(child, str)
                    and _SAFE_CODE_LABEL.fullmatch(child)
                ):
                    clean[text_key] = child
                    continue
                if self.mode == "minimal" and lowered in _RAW_CONTENT_KEYS:
                    clean[text_key] = {} if isinstance(child, dict) else _OMITTED
                    continue
                clean[text_key] = self._visit(
                    child,
                    key=lowered,
                    depth=depth + 1,
                )
            return clean
        return self._string(str(value), key=key)

    def _string(self, value: str, *, key: str) -> str:
        text = _redact_secrets(_strip_controls(value))
        if key in _PATH_KEYS or _looks_like_absolute_path(text):
            return self._relative_path(text)
        if key == "uri" or key.endswith("_uri"):
            if text.startswith("belief://") and len(text) <= 1_024:
                return text
            return "untrusted_sha256_" + hashlib.sha256(
                text.encode("utf-8", errors="strict")
            ).hexdigest()[:16]
        if self.mode == "minimal":
            if key in _RAW_CONTENT_KEYS or key in _UNTRUSTED_TEXT_KEYS:
                return _OMITTED
            if key in _TRUSTED_POLICY_TEXT_KEYS:
                return text[:2_048]
            if len(text) <= 512 and _SAFE_MINIMAL_TEXT.fullmatch(text):
                return text
            return "untrusted_sha256_" + hashlib.sha256(
                text.encode("utf-8", errors="strict")
            ).hexdigest()[:16]
        limit = 2_048 if self.mode == "redacted" else 8_192
        return text[:limit]

    def _relative_path(self, value: str) -> str:
        normalized = value.replace("\\", "/")
        if not normalized:
            return ""
        candidate = Path(value)
        try:
            if candidate.is_absolute():
                resolved = candidate.resolve(strict=False)
                try:
                    relative = resolved.relative_to(self.workspace_root)
                except ValueError:
                    return "[PATH_OUTSIDE_WORKSPACE]"
                return relative.as_posix() or "."
        except (OSError, RuntimeError):
            return "[PATH_REDACTED]"
        parts = Path(normalized).parts
        if ".." in parts:
            return "[PATH_REDACTED]"
        return normalized[:1_024]


def _strip_controls(value: str) -> str:
    return "".join(
        character
        for character in value
        if character in "\t\n\r" or ord(character) >= 32
    )


def _redact_secrets(value: str) -> str:
    redacted = value
    for pattern in _SENSITIVE_VALUE_PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    return redacted


def _looks_like_absolute_path(value: str) -> bool:
    if re.match(r"^[A-Za-z]:[\\/]", value):
        return True
    if value.startswith("\\\\"):
        return True
    return value.startswith(("/home/", "/Users/", "/tmp/", "/var/tmp/"))


__all__ = [
    "MCPPublicationError",
    "MCPPublicationPolicy",
    "PUBLICATION_MODES",
]
