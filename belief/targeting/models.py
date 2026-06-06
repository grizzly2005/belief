"""Models for BELIEF target classification v1."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


TARGET_PROFILE_SCHEMA_VERSION = "belief.target_profile.v1"


@dataclass(frozen=True)
class TargetProfile:
    target: str
    target_type: str
    exists: bool
    languages: tuple[str, ...] = field(default_factory=tuple)
    frameworks: tuple[str, ...] = field(default_factory=tuple)
    package_files: tuple[str, ...] = field(default_factory=tuple)
    lockfiles: tuple[str, ...] = field(default_factory=tuple)
    iac_files: tuple[str, ...] = field(default_factory=tuple)
    api_files: tuple[str, ...] = field(default_factory=tuple)
    traffic_files: tuple[str, ...] = field(default_factory=tuple)
    pdx_files: tuple[str, ...] = field(default_factory=tuple)
    recommended_flags: tuple[str, ...] = field(default_factory=tuple)
    safety_notes: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = TARGET_PROFILE_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "target_type": self.target_type,
            "exists": self.exists,
            "languages": list(self.languages),
            "frameworks": list(self.frameworks),
            "package_files": list(self.package_files),
            "lockfiles": list(self.lockfiles),
            "iac_files": list(self.iac_files),
            "api_files": list(self.api_files),
            "traffic_files": list(self.traffic_files),
            "pdx_files": list(self.pdx_files),
            "recommended_flags": list(self.recommended_flags),
            "safety_notes": list(self.safety_notes),
        }


__all__ = ["TARGET_PROFILE_SCHEMA_VERSION", "TargetProfile"]
