from __future__ import annotations

import shutil
from pathlib import Path

from belief.importers.openapi_json import openapi_payload_to_access_observations
from belief.json_contracts import load_json_file
from belief.tools.schemas import NormalizedToolResult

from .base import ManifestBridge


class SchemathesisBridge(ManifestBridge):
    tool_id = "schemathesis"

    def is_available(self) -> bool:
        return shutil.which("schemathesis") is not None

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        source = Path(path)
        if source.suffix.lower() in {".yaml", ".yml"}:
            return NormalizedToolResult(
                tool_id=self.tool_id,
                warnings=["YAML OpenAPI import is unsupported without an optional YAML parser."],
                artifacts=[source],
            )
        payload = load_json_file(source)
        return NormalizedToolResult(
            tool_id=self.tool_id,
            access_observations=openapi_payload_to_access_observations(payload),
            artifacts=[source],
            raw={"format": "openapi-json"},
        )


__all__ = ["SchemathesisBridge"]
