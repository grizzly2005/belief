"""Provenance records for imported external tool signals."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .io import sanitize_for_json


@dataclass
class SignalProvenance:
    source_tool: str
    source_rule_id: str | None = None
    source_artifact: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    source_kind: str | None = None
    confidence: str | None = None
    raw_reference: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "source_tool": self.source_tool,
            "source_rule_id": self.source_rule_id,
            "source_artifact": self.source_artifact,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "source_kind": self.source_kind,
            "confidence": self.confidence,
            "raw_reference": sanitize_for_json(self.raw_reference),
        }
        return {key: value for key, value in data.items() if value not in (None, "", {})}


__all__ = ["SignalProvenance"]
