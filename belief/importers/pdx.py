"""Passive PDX JSON importer."""

from __future__ import annotations

from pathlib import Path

from belief.pdx.io import read_pdx_bundle
from belief.pdx.mapping import pdx_bundle_to_normalized_tool_result
from belief.tools.schemas import NormalizedToolResult


def import_pdx_bundle(path: Path | str) -> NormalizedToolResult:
    bundle = read_pdx_bundle(path)
    return pdx_bundle_to_normalized_tool_result(bundle)


__all__ = ["import_pdx_bundle"]
