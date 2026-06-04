from __future__ import annotations

import shutil
from pathlib import Path

from belief.importers.codeql_sarif import import_codeql_sarif
from belief.tools.schemas import NormalizedToolResult, ToolExecution

from .base import ManifestBridge


class CodeQLBridge(ManifestBridge):
    tool_id = "codeql"

    def is_available(self) -> bool:
        return shutil.which("codeql") is not None

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        return NormalizedToolResult(
            tool_id=self.tool_id,
            findings=import_codeql_sarif(path),
            artifacts=[Path(path)],
            raw={"format": "sarif"},
        )

    def normalize(self, execution: ToolExecution) -> NormalizedToolResult:
        return NormalizedToolResult(
            tool_id=self.tool_id,
            warnings=["CodeQL MVP bridge supports passive SARIF import only."],
        )


__all__ = ["CodeQLBridge"]
