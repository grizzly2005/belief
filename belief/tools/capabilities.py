"""Tool capability registry for BELIEF orchestration v1."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolCapability:
    tool_id: str
    name: str
    category: str
    input_types: tuple[str, ...] = field(default_factory=tuple)
    output_formats: tuple[str, ...] = field(default_factory=tuple)
    languages: tuple[str, ...] = field(default_factory=tuple)
    capabilities: tuple[str, ...] = field(default_factory=tuple)
    requires_network: bool = False
    requires_dynamic: bool = False
    requires_scope: bool = False
    can_run_local: bool = False
    can_import_only: bool = False
    risk_level: str = "low"
    default_timeout_seconds: int = 180
    profiles: tuple[str, ...] = field(default_factory=tuple)
    run_command_template: tuple[str, ...] = field(default_factory=tuple)
    import_format: str | None = None
    normalized_output_name: str | None = None
    safety_notes: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ToolCapability":
        return cls(
            tool_id=str(raw["tool_id"]),
            name=str(raw.get("name") or raw["tool_id"]),
            category=str(raw.get("category") or "unknown"),
            input_types=tuple(_strings(raw.get("input_types"))),
            output_formats=tuple(_strings(raw.get("output_formats"))),
            languages=tuple(_strings(raw.get("languages"))),
            capabilities=tuple(_strings(raw.get("capabilities"))),
            requires_network=bool(raw.get("requires_network", False)),
            requires_dynamic=bool(raw.get("requires_dynamic", False)),
            requires_scope=bool(raw.get("requires_scope", False)),
            can_run_local=bool(raw.get("can_run_local", False)),
            can_import_only=bool(raw.get("can_import_only", False)),
            risk_level=str(raw.get("risk_level") or "low"),
            default_timeout_seconds=int(raw.get("default_timeout_seconds", 180) or 180),
            profiles=tuple(_strings(raw.get("profiles"))),
            run_command_template=tuple(_strings(raw.get("run_command_template"))),
            import_format=_optional(raw.get("import_format")),
            normalized_output_name=_optional(raw.get("normalized_output_name")),
            safety_notes=tuple(_strings(raw.get("safety_notes"))),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_id": self.tool_id,
            "name": self.name,
            "category": self.category,
            "input_types": list(self.input_types),
            "output_formats": list(self.output_formats),
            "languages": list(self.languages),
            "capabilities": list(self.capabilities),
            "requires_network": self.requires_network,
            "requires_dynamic": self.requires_dynamic,
            "requires_scope": self.requires_scope,
            "can_run_local": self.can_run_local,
            "can_import_only": self.can_import_only,
            "risk_level": self.risk_level,
            "default_timeout_seconds": self.default_timeout_seconds,
            "profiles": list(self.profiles),
            "run_command_template": list(self.run_command_template),
            "import_format": self.import_format,
            "normalized_output_name": self.normalized_output_name,
            "safety_notes": list(self.safety_notes),
        }


def builtin_capability_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools_bundled" / "capabilities"


def load_builtin_capabilities() -> dict[str, ToolCapability]:
    capabilities = {}
    for path in sorted(builtin_capability_dir().glob("*.json"), key=lambda item: item.name):
        raw = json.loads(path.read_text(encoding="utf-8"))
        capability = ToolCapability.from_dict(raw)
        capabilities[capability.tool_id] = capability
    return capabilities


def load_tool_capability(tool_id: str) -> ToolCapability:
    capabilities = load_builtin_capabilities()
    key = tool_id.strip().lower().replace("-", "_")
    if key not in capabilities:
        available = ", ".join(sorted(capabilities))
        raise KeyError(f"unknown tool capability {tool_id!r}; available: {available}")
    return capabilities[key]


def _strings(value: Any) -> list[str]:
    return [str(item) for item in value] if isinstance(value, list) else []


def _optional(value: Any) -> str | None:
    text = str(value or "").strip()
    return text or None


__all__ = [
    "ToolCapability",
    "builtin_capability_dir",
    "load_builtin_capabilities",
    "load_tool_capability",
]
