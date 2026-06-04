from __future__ import annotations

import shutil
from pathlib import Path

from belief.importers.arjun_json import import_arjun_json
from belief.tools.schemas import NormalizedToolResult

from .base import ManifestBridge


class ArjunBridge(ManifestBridge):
    tool_id = "arjun"

    def is_available(self) -> bool:
        return shutil.which("arjun") is not None

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        return import_arjun_json(path)


__all__ = ["ArjunBridge"]
