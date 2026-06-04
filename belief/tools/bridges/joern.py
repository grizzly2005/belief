from __future__ import annotations

import json
import shutil
from pathlib import Path

from belief.tools.schemas import ExternalFinding, NormalizedToolResult

from .base import ManifestBridge


class JoernBridge(ManifestBridge):
    tool_id = "joern"

    def is_available(self) -> bool:
        return shutil.which("joern") is not None

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        source = Path(path)
        try:
            payload = json.loads(source.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            return NormalizedToolResult(tool_id=self.tool_id, warnings=[f"unsupported Joern JSON: {exc}"])
        findings = []
        rows = payload if isinstance(payload, list) else payload.get("findings", []) if isinstance(payload, dict) else []
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                findings.append(ExternalFinding(
                    tool_id=self.tool_id,
                    rule_id=str(row.get("rule_id") or row.get("query") or "") or None,
                    title=str(row.get("title") or row.get("query") or "Joern finding"),
                    message=str(row.get("message") or ""),
                    file=str(row.get("file") or "") or None,
                    line=_int(row.get("line")),
                    raw=row,
                ))
        warnings = [] if findings else ["No supported Joern findings detected."]
        return NormalizedToolResult(tool_id=self.tool_id, findings=findings, warnings=warnings, artifacts=[source])


def _int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


__all__ = ["JoernBridge"]
