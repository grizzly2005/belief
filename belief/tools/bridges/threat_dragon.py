from __future__ import annotations

from belief.exporters.threatdragon_json import export_threatdragon_json
from belief.tools.schemas import AccessObservation

from .base import ManifestBridge


class ThreatDragonBridge(ManifestBridge):
    tool_id = "threat_dragon"

    def is_available(self) -> bool:
        return False

    def export_json(self, observations: list[AccessObservation]) -> dict:
        return export_threatdragon_json(observations)


__all__ = ["ThreatDragonBridge"]
