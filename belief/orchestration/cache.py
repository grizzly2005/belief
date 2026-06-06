"""Placeholder cache helpers for BELIEF orchestration v1."""

from __future__ import annotations

from pathlib import Path


def cache_dir(output_dir: str | Path) -> Path:
    path = Path(output_dir) / "cache"
    path.mkdir(parents=True, exist_ok=True)
    return path


__all__ = ["cache_dir"]
