from __future__ import annotations

import json
import shutil
from pathlib import Path

from belief.importers.semgrep_json import semgrep_payload_to_findings
from belief.tools.runner import run_external_command
from belief.tools.schemas import NormalizedToolResult, ToolExecution, ToolInput

from .base import ManifestBridge


class SemgrepBridge(ManifestBridge):
    tool_id = "semgrep"

    def is_available(self) -> bool:
        return shutil.which("semgrep") is not None

    def build_command(self, tool_input: ToolInput) -> list[str]:
        if tool_input.target is None:
            raise ValueError("SemgrepBridge requires ToolInput.target")
        return ["semgrep", "scan", "--json", "--config", "auto", str(tool_input.target)]

    def run(self, tool_input: ToolInput) -> ToolExecution:
        if not self.is_available():
            return ToolExecution(
                tool_id=self.tool_id,
                command=[],
                returncode=0,
                stdout="",
                stderr="",
                skipped=True,
                skip_reason="semgrep is not installed.",
            )
        command = self.build_command(tool_input)
        artifacts: list[Path] = []
        output_file = None
        if tool_input.output_dir:
            tool_input.output_dir.mkdir(parents=True, exist_ok=True)
            output_file = tool_input.output_dir / "semgrep.json"
            artifacts.append(output_file)
        execution = run_external_command(
            tool_id=self.tool_id,
            command=command,
            timeout_seconds=tool_input.timeout_seconds,
            artifacts=artifacts,
        )
        if output_file is not None:
            output_file.write_text(execution.stdout, encoding="utf-8")
        return execution

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return NormalizedToolResult(
            tool_id=self.tool_id,
            findings=semgrep_payload_to_findings(payload),
            artifacts=[Path(path)],
            raw={"format": "semgrep-json"},
        )

    def normalize(self, execution: ToolExecution) -> NormalizedToolResult:
        if execution.skipped:
            return NormalizedToolResult(tool_id=self.tool_id, warnings=[execution.skip_reason or "skipped"])
        warnings = []
        if execution.returncode != 0:
            warnings.append(f"semgrep exited with returncode {execution.returncode}")
        try:
            payload = json.loads(execution.stdout or "{}")
        except json.JSONDecodeError as exc:
            return NormalizedToolResult(
                tool_id=self.tool_id,
                warnings=[*warnings, f"invalid Semgrep JSON: {exc}"],
                artifacts=list(execution.artifacts),
                raw={
                    "returncode": execution.returncode,
                    "stderr_excerpt": execution.stderr[:1000],
                },
            )
        return NormalizedToolResult(
            tool_id=self.tool_id,
            findings=semgrep_payload_to_findings(payload),
            artifacts=list(execution.artifacts),
            warnings=warnings,
            raw={
                "returncode": execution.returncode,
                "stderr_excerpt": execution.stderr[:1000] if execution.returncode != 0 else "",
            },
        )


__all__ = ["SemgrepBridge"]
