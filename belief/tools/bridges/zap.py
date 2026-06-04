from __future__ import annotations

import shutil
from pathlib import Path

from belief.importers.zap_json import import_zap_json
from belief.tools.schemas import NormalizedToolResult

from .base import ManifestBridge


class ZAPBridge(ManifestBridge):
    tool_id = "zap"

    def is_available(self) -> bool:
        return shutil.which("zap.sh") is not None or shutil.which("zap-baseline.py") is not None

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        return NormalizedToolResult(
            tool_id=self.tool_id,
            findings=import_zap_json(path),
            artifacts=[Path(path)],
            raw={"format": "zap-json"},
        )


__all__ = ["ZAPBridge"]
