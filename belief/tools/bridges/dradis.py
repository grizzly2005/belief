from __future__ import annotations

from belief.exporters.dradis_markdown import render_dradis_markdown
from belief.tools.schemas import ExternalFinding

from .base import ManifestBridge


class DradisBridge(ManifestBridge):
    tool_id = "dradis"

    def is_available(self) -> bool:
        return False

    def export_markdown(self, findings: list[ExternalFinding]) -> str:
        return render_dradis_markdown(findings)


__all__ = ["DradisBridge"]
