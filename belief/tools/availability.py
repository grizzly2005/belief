"""Optional external tool availability checks."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from typing import Any

from belief.scope import ScopePolicy, allow_tool

from .capabilities import ToolCapability, load_builtin_capabilities
from .profiles import load_tool_profile


@dataclass(frozen=True)
class ToolAvailability:
    tool_id: str
    status: str
    executable: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "status": self.status,
            "executable": self.executable,
            "reason": self.reason,
        }


def check_tool_availability(
    capability: ToolCapability,
    scope: ScopePolicy | None = None,
    target: str = "",
) -> ToolAvailability:
    decision = allow_tool(scope, capability, target)
    if not decision.allowed:
        return ToolAvailability(capability.tool_id, "disabled_by_scope", None, decision.reason)
    if capability.can_import_only and not capability.can_run_local:
        return ToolAvailability(capability.tool_id, "import_only", None, "passive import only in this pass")
    if "container" in capability.capabilities and not capability.can_run_local:
        return ToolAvailability(capability.tool_id, "container_required", None, "container integration is not enabled in CI")
    if not capability.can_run_local:
        return ToolAvailability(capability.tool_id, "not_supported_yet", None, "runner not implemented in v1")
    executable = _executable_name(capability)
    if capability.tool_id == "belief":
        return ToolAvailability(capability.tool_id, "installed", "python -m belief", "BELIEF local CLI")
    found = shutil.which(executable) if executable else None
    if found:
        return ToolAvailability(capability.tool_id, "installed", found, "detected on PATH")
    return ToolAvailability(capability.tool_id, "missing", None, f"{executable or capability.tool_id} not found on PATH")


def availability_for_profile(profile_id: str, scope: ScopePolicy | None = None, target: str = "") -> dict[str, Any]:
    profile = load_tool_profile(profile_id)
    capabilities = load_builtin_capabilities()
    rows = [
        check_tool_availability(capabilities[tool_id], scope, target).to_dict()
        for tool_id in profile.tools
        if tool_id in capabilities
    ]
    return {
        "schema_version": "belief.tool_availability.v1",
        "profile": profile.to_dict(),
        "target": target,
        "tools": rows,
    }


def _executable_name(capability: ToolCapability) -> str:
    if capability.run_command_template:
        return capability.run_command_template[0]
    return capability.tool_id.replace("_", "-")


__all__ = ["ToolAvailability", "availability_for_profile", "check_tool_availability"]
