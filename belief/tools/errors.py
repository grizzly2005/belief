"""Controlled exceptions for BELIEF tool bridges."""

from __future__ import annotations


class ToolBridgeError(Exception):
    """Base class for tool bridge failures."""


class ToolManifestError(ToolBridgeError):
    """Raised when a bridge manifest is invalid or missing."""


class ToolSafetyError(ToolBridgeError):
    """Raised when a requested tool action violates the safety policy."""


class ToolExecutionError(ToolBridgeError):
    """Raised for controlled external execution failures."""


__all__ = [
    "ToolBridgeError",
    "ToolExecutionError",
    "ToolManifestError",
    "ToolSafetyError",
]
