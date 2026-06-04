"""Backwards-compat shim (v4 merge).

EnhancedOrchestrator has been merged into Orchestrator via the
`enable_bridges=True` flag. This file keeps the import path alive
for any external code that still references it, but new code should
use Orchestrator directly.
"""
from __future__ import annotations

import warnings
from typing import Optional, Set

from .orchestrator import Orchestrator
from .config import BeliefConfig


class EnhancedOrchestrator(Orchestrator):
    """DEPRECATED: use Orchestrator(config, enable_bridges=True)."""

    _merge_beliefs = staticmethod(Orchestrator._merge_bridge_beliefs)

    def __init__(
        self,
        config: BeliefConfig,
        enabled_bridges: Optional[Set[str]] = None,
        dedupe_bridge_beliefs: bool = True,
    ):
        warnings.warn(
            "EnhancedOrchestrator is deprecated. Use "
            "Orchestrator(config, enable_bridges=True, enabled_bridges=...) instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        super().__init__(
            config,
            enable_bridges=True,
            enabled_bridges=enabled_bridges,
            dedupe_bridge_beliefs=dedupe_bridge_beliefs,
        )


def analyze_project_enhanced(
    config: BeliefConfig,
    project_path: str,
    enabled_bridges: Optional[Set[str]] = None,
    **kwargs,
):
    """DEPRECATED: use Orchestrator(config, enable_bridges=True).analyze_project()."""
    warnings.warn(
        "analyze_project_enhanced is deprecated. Use "
        "Orchestrator(config, enable_bridges=True) directly.",
        DeprecationWarning,
        stacklevel=2,
    )
    orch = Orchestrator(config, enable_bridges=True, enabled_bridges=enabled_bridges)
    return orch.analyze_project(project_path, **kwargs)


__all__ = ["EnhancedOrchestrator", "analyze_project_enhanced"]
