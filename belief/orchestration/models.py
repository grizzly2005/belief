"""Models for BELIEF run plans and execution summaries."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


RUN_PLAN_SCHEMA_VERSION = "belief.run_plan.v1"
EXECUTION_SUMMARY_SCHEMA_VERSION = "belief.execution_summary.v1"


@dataclass(frozen=True)
class RunCommand:
    tool_id: str
    argv: tuple[str, ...]
    cwd: str
    raw_output: str
    normalized_output: str | None
    timeout_seconds: int
    requires_network: bool
    requires_dynamic: bool
    allowed_by_scope: bool
    tool_status: str
    skip_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "raw_output": self.raw_output,
            "normalized_output": self.normalized_output,
            "timeout_seconds": self.timeout_seconds,
            "requires_network": self.requires_network,
            "requires_dynamic": self.requires_dynamic,
            "allowed_by_scope": self.allowed_by_scope,
            "tool_status": self.tool_status,
            "skip_reason": self.skip_reason,
        }


@dataclass(frozen=True)
class RunPlan:
    target_profile: dict[str, Any]
    scope_summary: dict[str, Any]
    selected_tools: tuple[dict[str, Any], ...]
    skipped_tools: tuple[dict[str, Any], ...]
    commands: tuple[RunCommand, ...]
    import_steps: tuple[dict[str, Any], ...]
    merge_step: dict[str, Any]
    audit_step: dict[str, Any]
    report_steps: tuple[dict[str, Any], ...]
    output_layout: dict[str, str]
    safety_decisions: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = RUN_PLAN_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_profile": self.target_profile,
            "scope_summary": self.scope_summary,
            "selected_tools": list(self.selected_tools),
            "skipped_tools": list(self.skipped_tools),
            "commands": [command.to_dict() for command in self.commands],
            "import_steps": list(self.import_steps),
            "merge_step": self.merge_step,
            "audit_step": self.audit_step,
            "report_steps": list(self.report_steps),
            "output_layout": self.output_layout,
            "safety_decisions": list(self.safety_decisions),
            "limitations": list(self.limitations),
        }


__all__ = ["EXECUTION_SUMMARY_SCHEMA_VERSION", "RUN_PLAN_SCHEMA_VERSION", "RunCommand", "RunPlan"]
