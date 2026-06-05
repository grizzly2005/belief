"""Read and write BELIEF's JSON-only PDX bundle format."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import PDXBundle
from .redaction import redact_pdx_value


class PDXSchemaError(ValueError):
    """Raised when a PDX JSON bundle cannot be parsed."""


def pdx_bundle_to_dict(bundle: PDXBundle) -> dict[str, Any]:
    return redact_pdx_value(bundle.to_dict())


def pdx_bundle_from_dict(payload: dict[str, Any]) -> PDXBundle:
    try:
        return PDXBundle.from_dict(payload)
    except ValueError as exc:
        raise PDXSchemaError(str(exc)) from exc


def read_pdx_bundle(path: Path | str) -> PDXBundle:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PDXSchemaError(f"invalid PDX JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PDXSchemaError("PDX JSON must be an object")
    return pdx_bundle_from_dict(payload)


def write_pdx_bundle(bundle: PDXBundle, path: Path | str) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(pdx_bundle_to_dict(bundle), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


__all__ = [
    "PDXSchemaError",
    "pdx_bundle_from_dict",
    "pdx_bundle_to_dict",
    "read_pdx_bundle",
    "write_pdx_bundle",
]
