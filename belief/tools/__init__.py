"""Universal BELIEF tool bridge system.

The bridge layer normalizes external-tool outputs without vendoring upstream
tools. Bridges are passive/import-only by default unless a caller explicitly
opts into dynamic execution.
"""

from .schemas import (
    AccessObservation,
    AttackPath,
    ExternalFinding,
    NormalizedToolResult,
    RequestStep,
    ToolExecution,
    ToolInput,
    ToolManifest,
    ToolRiskProfile,
)


def __getattr__(name: str):
    if name == "ToolRegistry":
        from .registry import ToolRegistry

        return ToolRegistry
    if name == "ToolRunner":
        from .runner import ToolRunner

        return ToolRunner
    raise AttributeError(name)

__all__ = [
    "AccessObservation",
    "AttackPath",
    "ExternalFinding",
    "NormalizedToolResult",
    "RequestStep",
    "ToolExecution",
    "ToolInput",
    "ToolManifest",
    "ToolRegistry",
    "ToolRiskProfile",
    "ToolRunner",
]
