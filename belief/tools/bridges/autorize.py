from __future__ import annotations

from belief.exporters.autorize_recipe import export_autorize_recipes
from belief.tools.schemas import AccessObservation

from .base import ManifestBridge


class AutorizeBridge(ManifestBridge):
    tool_id = "autorize"

    def is_available(self) -> bool:
        return False

    def export_recipe(self, observations: list[AccessObservation]) -> dict:
        return export_autorize_recipes(observations)


__all__ = ["AutorizeBridge"]
