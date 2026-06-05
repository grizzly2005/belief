"""Stable public schema helpers for BELIEF normalized tool results."""

from __future__ import annotations


TOOL_RESULT_SCHEMA_VERSION = "belief.tools.v1"


class ToolResultSchemaError(ValueError):
    """Raised when a normalized tool-result payload is malformed."""


__all__ = [
    "TOOL_RESULT_SCHEMA_VERSION",
    "ToolResultSchemaError",
]
