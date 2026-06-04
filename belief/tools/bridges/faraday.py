from __future__ import annotations

from belief.exporters.faraday_json import export_faraday_json
from belief.tools.schemas import ExternalFinding

from .base import ManifestBridge


class FaradayBridge(ManifestBridge):
    tool_id = "faraday"

    def is_available(self) -> bool:
        return False

    def export_json(self, findings: list[ExternalFinding]) -> dict:
        return export_faraday_json(findings)


__all__ = ["FaradayBridge"]
