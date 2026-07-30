"""Fixed FastAPI path application for one opaque fixture identity."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ...worker.registry import RegisteredFixtureResult
from .._shared import path_policy_alpha
from ..fastapi_adapter import prepare_fastapi_path_app


def prepare_fixture(
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> Callable[[], RegisteredFixtureResult]:
    return prepare_fastapi_path_app(
        temporary_root,
        parameters,
        application_id="app_47e1a3",
        policy=path_policy_alpha,
    )


__all__ = ["prepare_fixture"]
