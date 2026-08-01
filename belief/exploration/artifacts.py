"""Strict local import boundary for external reachability path artifacts."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from belief.json_contracts import StrictJSONError, load_json_file

from .models import (
    ExplorationAssessment,
    ExplorationObjective,
    PathArtifact,
    assess_path_artifact,
)

MAX_PATH_ARTIFACT_BYTES = 1024 * 1024


class PathArtifactImportError(ValueError):
    """Raised when a path artifact is malformed or not objective-bound."""


def import_path_artifact(
    payload: Mapping[str, Any],
    *,
    objective: ExplorationObjective,
) -> tuple[PathArtifact, ExplorationAssessment]:
    try:
        artifact = PathArtifact.from_dict(payload)
        assessment = assess_path_artifact(objective, artifact)
    except (TypeError, ValueError) as exc:
        raise PathArtifactImportError(f"invalid path artifact: {exc}") from exc
    return artifact, assessment


def load_path_artifact(
    path: str | Path,
    *,
    objective: ExplorationObjective,
    max_bytes: int = MAX_PATH_ARTIFACT_BYTES,
) -> tuple[PathArtifact, ExplorationAssessment]:
    try:
        payload = load_json_file(path, max_bytes=max_bytes)
    except StrictJSONError as exc:
        raise PathArtifactImportError(f"cannot load path artifact: {exc}") from exc
    if not isinstance(payload, Mapping):
        raise PathArtifactImportError("path artifact document must be a JSON object")
    return import_path_artifact(payload, objective=objective)


__all__ = [
    "MAX_PATH_ARTIFACT_BYTES",
    "PathArtifactImportError",
    "import_path_artifact",
    "load_path_artifact",
]
