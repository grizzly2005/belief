"""JSON manifest loading for BELIEF tool bridges."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ToolManifestError
from .schemas import ToolManifest, ToolRiskProfile


def builtin_manifest_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "tools_bundled" / "manifests"


def load_manifest(path: str | Path) -> ToolManifest:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ToolManifestError(f"manifest must be a JSON object: {path}")
    return manifest_from_dict(raw)


def load_builtin_manifest(tool_id: str) -> ToolManifest:
    return load_manifest(builtin_manifest_dir() / f"{tool_id}.json")


def load_builtin_manifests() -> list[ToolManifest]:
    directory = builtin_manifest_dir()
    if not directory.exists():
        return []
    return [
        load_manifest(path)
        for path in sorted(directory.glob("*.json"), key=lambda item: item.name)
    ]


def manifest_from_dict(raw: dict[str, Any]) -> ToolManifest:
    risk_raw = raw.get("risk") or {}
    if not isinstance(risk_raw, dict):
        raise ToolManifestError("manifest risk must be an object")
    risk = ToolRiskProfile(
        network=bool(risk_raw.get("network", False)),
        active_scanning=bool(risk_raw.get("active_scanning", False)),
        replays_requests=bool(risk_raw.get("replays_requests", False)),
        fuzzing=bool(risk_raw.get("fuzzing", False)),
        executes_target_code=bool(risk_raw.get("executes_target_code", False)),
        writes_files=bool(risk_raw.get("writes_files", False)),
        requires_auth_tokens=bool(risk_raw.get("requires_auth_tokens", False)),
        external_services=bool(risk_raw.get("external_services", False)),
        safe_default=bool(risk_raw.get("safe_default", True)),
    )
    required = ["tool_id", "name", "description", "execution_mode"]
    missing = [name for name in required if not raw.get(name)]
    if missing:
        raise ToolManifestError(f"manifest missing required fields: {', '.join(missing)}")
    return ToolManifest(
        tool_id=str(raw["tool_id"]),
        name=str(raw["name"]),
        repo=_optional_str(raw.get("repo")),
        license=_optional_str(raw.get("license")),
        description=str(raw["description"]),
        execution_mode=str(raw["execution_mode"]),  # type: ignore[arg-type]
        command=_optional_str(raw.get("command")),
        default_args=_strings(raw.get("default_args")),
        input_types=_strings(raw.get("input_types")),
        output_types=_strings(raw.get("output_types")),
        capabilities=_strings(raw.get("capabilities")),
        maps_to=_strings(raw.get("maps_to")),
        risk=risk,
        notes=_optional_str(raw.get("notes")),
    )


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text if text else None


__all__ = [
    "builtin_manifest_dir",
    "load_builtin_manifest",
    "load_builtin_manifests",
    "load_manifest",
    "manifest_from_dict",
]
