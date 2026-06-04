from __future__ import annotations

from pathlib import Path

from belief.exporters.param_wordlist import write_param_wordlist
from belief.tools.schemas import NormalizedToolResult, ToolExecution, ToolInput

from .base import ManifestBridge


class ParamMinerBridge(ManifestBridge):
    tool_id = "param_miner"

    def is_available(self) -> bool:
        return True

    def run(self, tool_input: ToolInput) -> ToolExecution:
        output_dir = tool_input.output_dir or Path(".")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = write_param_wordlist(output_dir / "param_miner_wordlist.txt")
        return ToolExecution(
            tool_id=self.tool_id,
            command=[],
            returncode=0,
            stdout=str(output_file),
            stderr="",
            artifacts=[output_file],
        )

    def normalize(self, execution: ToolExecution) -> NormalizedToolResult:
        return NormalizedToolResult(tool_id=self.tool_id, artifacts=list(execution.artifacts))


__all__ = ["ParamMinerBridge"]
