"""Output layout helpers for BELIEF orchestration runs."""

from __future__ import annotations

from pathlib import Path


LAYOUT_DIRS = ("raw", "normalized", "audit", "reports", "logs", "metadata", "cache")


def build_output_layout(output_dir: str | Path) -> dict[str, str]:
    root = Path(output_dir)
    layout = {"root": root.as_posix()}
    for name in LAYOUT_DIRS:
        layout[name] = (root / name).as_posix()
    return layout


def ensure_output_layout(output_dir: str | Path) -> dict[str, str]:
    layout = build_output_layout(output_dir)
    for path in layout.values():
        Path(path).mkdir(parents=True, exist_ok=True)
    return layout


__all__ = ["LAYOUT_DIRS", "build_output_layout", "ensure_output_layout"]
