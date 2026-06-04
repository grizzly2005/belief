from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from belief.tools.schemas import AttackPath, NormalizedToolResult, RequestStep

from .base import ManifestBridge


class RestlerBridge(ManifestBridge):
    tool_id = "restler"

    def is_available(self) -> bool:
        return shutil.which("restler") is not None

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        attack_paths = _restler_attack_paths(payload)
        warnings = [] if attack_paths else ["Unsupported or empty RESTler-style JSON format."]
        return NormalizedToolResult(
            tool_id=self.tool_id,
            attack_paths=attack_paths,
            warnings=warnings,
            artifacts=[source],
            raw={"format": "restler-json"},
        )


def _restler_attack_paths(payload: Any) -> list[AttackPath]:
    sequences = []
    if isinstance(payload, dict):
        raw = payload.get("sequences") or payload.get("requests") or []
        sequences = raw if isinstance(raw, list) else []
    paths: list[AttackPath] = []
    for index, sequence in enumerate(sequences):
        steps = []
        items = sequence if isinstance(sequence, list) else sequence.get("requests", []) if isinstance(sequence, dict) else []
        for item in items if isinstance(items, list) else []:
            if isinstance(item, dict):
                steps.append(RequestStep(
                    method=str(item.get("method") or "GET").upper(),
                    path=str(item.get("path") or item.get("url") or "/"),
                    consumes=[str(v) for v in item.get("consumes", [])] if isinstance(item.get("consumes"), list) else [],
                    produces=[str(v) for v in item.get("produces", [])] if isinstance(item.get("produces"), list) else [],
                ))
        if steps:
            paths.append(AttackPath(
                source_tool="restler",
                title=f"RESTler sequence {index + 1}",
                steps=steps,
                hypothesis="Replay sequence may validate a white-box API hypothesis.",
                evidence_needed=["Run only against authorized scoped environments."],
                risk="medium",
            ))
    return paths


__all__ = ["RestlerBridge"]
