from __future__ import annotations

import shutil
from abc import ABC, abstractmethod

from belief.tools.manifest import load_builtin_manifest
from belief.tools.schemas import NormalizedToolResult, ToolExecution, ToolInput, ToolManifest


class ToolBridge(ABC):
    tool_id: str

    @abstractmethod
    def manifest(self) -> ToolManifest:
        ...

    def is_available(self) -> bool:
        command = self.manifest().command
        return bool(command and shutil.which(command))

    def build_command(self, tool_input: ToolInput) -> list[str]:
        raise NotImplementedError

    def run(self, tool_input: ToolInput) -> ToolExecution:
        return ToolExecution(
            tool_id=self.tool_id,
            command=[],
            returncode=0,
            stdout="",
            stderr="",
            skipped=True,
            skip_reason="This bridge does not implement direct execution.",
        )

    def normalize(self, execution: ToolExecution) -> NormalizedToolResult:
        return NormalizedToolResult(tool_id=self.tool_id)


class ManifestBridge(ToolBridge):
    """Base class for bridges backed by a JSON manifest."""

    tool_id: str = ""

    def manifest(self) -> ToolManifest:
        return load_builtin_manifest(self.tool_id)


__all__ = ["ManifestBridge", "ToolBridge"]
