"""Safe subprocess runner for BELIEF tool bridges."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .bridges.base import ToolBridge
from .schemas import ToolExecution, ToolInput
from .safety import validate_tool_input


class ToolRunner:
    """Run a bridge after manifest-level safety checks."""

    def run_bridge(self, bridge: ToolBridge, tool_input: ToolInput) -> ToolExecution:
        manifest = bridge.manifest()
        validate_tool_input(manifest, tool_input)
        if tool_input.output_dir:
            tool_input.output_dir.mkdir(parents=True, exist_ok=True)
        if not bridge.is_available() and manifest.execution_mode in {"external_cli", "docker", "python_module"}:
            return ToolExecution(
                tool_id=bridge.tool_id,
                command=[],
                returncode=0,
                stdout="",
                stderr="",
                skipped=True,
                skip_reason=f"{manifest.command or bridge.tool_id} is not installed.",
            )
        return bridge.run(tool_input)


def run_external_command(
    *,
    tool_id: str,
    command: list[str],
    timeout_seconds: int,
    artifacts: list[Path] | None = None,
) -> ToolExecution:
    completed = subprocess.run(
        command,
        shell=False,
        timeout=timeout_seconds,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    return ToolExecution(
        tool_id=tool_id,
        command=command,
        returncode=int(completed.returncode),
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
        artifacts=list(artifacts or []),
    )


__all__ = ["ToolRunner", "run_external_command"]
