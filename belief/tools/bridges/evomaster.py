from __future__ import annotations

import shutil

from .base import ManifestBridge


class EvoMasterBridge(ManifestBridge):
    tool_id = "evomaster"

    def is_available(self) -> bool:
        return shutil.which("evomaster") is not None


__all__ = ["EvoMasterBridge"]
