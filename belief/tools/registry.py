"""Registry for built-in and user-provided BELIEF tool bridges."""

from __future__ import annotations

from .bridges import builtin_bridge_classes
from .bridges.base import ToolBridge


class ToolRegistry:
    def __init__(self) -> None:
        self._bridges: dict[str, ToolBridge] = {}

    def register(self, bridge: ToolBridge) -> None:
        self._bridges[bridge.tool_id] = bridge

    def get(self, tool_id: str) -> ToolBridge:
        key = str(tool_id).strip().lower().replace("-", "_")
        if key not in self._bridges:
            available = ", ".join(self.tool_ids())
            raise KeyError(f"unknown tool bridge {tool_id!r}; available: {available}")
        return self._bridges[key]

    def list_tools(self) -> list[ToolBridge]:
        return [self._bridges[key] for key in self.tool_ids()]

    def tool_ids(self) -> list[str]:
        return sorted(self._bridges)

    @classmethod
    def with_builtin_bridges(cls) -> "ToolRegistry":
        registry = cls()
        for bridge_cls in builtin_bridge_classes():
            registry.register(bridge_cls())
        return registry


__all__ = ["ToolRegistry"]
