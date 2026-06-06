"""Tool profile loading for BELIEF orchestration v1."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolProfile:
    profile_id: str
    name: str
    description: str
    tools: tuple[str, ...] = field(default_factory=tuple)
    safety_notes: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ToolProfile":
        return cls(
            profile_id=str(raw["profile_id"]),
            name=str(raw.get("name") or raw["profile_id"]),
            description=str(raw.get("description") or ""),
            tools=tuple(str(item) for item in raw.get("tools", []) if str(item)),
            safety_notes=tuple(str(item) for item in raw.get("safety_notes", []) if str(item)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile_id,
            "name": self.name,
            "description": self.description,
            "tools": list(self.tools),
            "safety_notes": list(self.safety_notes),
        }


def builtin_profile_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools_bundled" / "profiles"


def load_tool_profiles() -> dict[str, ToolProfile]:
    profiles = {}
    for path in sorted(builtin_profile_dir().glob("*.json"), key=lambda item: item.name):
        raw = json.loads(path.read_text(encoding="utf-8"))
        profile = ToolProfile.from_dict(raw)
        profiles[profile.profile_id] = profile
    return profiles


def load_tool_profile(profile_id: str) -> ToolProfile:
    profiles = load_tool_profiles()
    key = profile_id.strip().lower()
    if key not in profiles:
        available = ", ".join(sorted(profiles))
        raise KeyError(f"unknown tool profile {profile_id!r}; available: {available}")
    return profiles[key]


__all__ = ["ToolProfile", "builtin_profile_dir", "load_tool_profile", "load_tool_profiles"]
