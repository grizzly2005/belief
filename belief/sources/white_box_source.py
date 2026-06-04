"""
white_box_source — adapts the existing belief.orchestrator as a BeliefSource.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional, Set

from . import BeliefSource, SourceMetadata

try:
    from belief.models import Belief
except ImportError:
    Belief = None  # type: ignore


class WhiteBoxSource(BeliefSource):
    """Wraps the LLM-based source-code orchestrator as a BeliefSource.

    Usage:
        from belief.config import BeliefConfig
        from belief.sources.white_box_source import WhiteBoxSource

        src = WhiteBoxSource(BeliefConfig(), project_path='/my/proj')
        beliefs = src.collect_beliefs()
    """
    kind = "white_box"

    def __init__(
        self,
        config,
        project_path: str,
        *,
        project_name: str = "",
        use_bridges: bool = True,
        enabled_bridges: Optional[Set[str]] = None,
    ):
        self.config = config
        self.project_path = project_path
        self.project_name = project_name or project_path.rstrip("/").split("/")[-1]
        self.use_bridges = use_bridges
        self.enabled_bridges = enabled_bridges
        self._last_report = None

    def collect_beliefs(self) -> List[Belief]:
        if self.use_bridges:
            from belief.enhanced_orchestrator import EnhancedOrchestrator
            orch = EnhancedOrchestrator(
                self.config,
                enabled_bridges=self.enabled_bridges,
            )
        else:
            from belief.orchestrator import Orchestrator
            orch = Orchestrator(self.config)
        report = orch.analyze_project(
            project_path=self.project_path,
            project_name=self.project_name,
        )
        self._last_report = report
        return list(getattr(report, "beliefs", []))

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            name=f"white_box:{self.project_name}",
            kind=self.kind,
            project_path=self.project_path,
            timestamp_utc=datetime.now(timezone.utc).isoformat(),
            extra={
                "use_bridges": self.use_bridges,
                "enabled_bridges": sorted(self.enabled_bridges) if self.enabled_bridges else None,
                "last_frontiers": len(getattr(self._last_report, "frontiers", []))
                                   if self._last_report else 0,
            },
        )

    def last_report(self):
        return self._last_report
