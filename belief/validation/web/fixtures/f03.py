"""Fixed Flask resource application for one opaque fixture identity."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ...worker.registry import RegisteredFixtureResult
from .._shared import resource_policy_alpha
from ..flask_adapter import prepare_flask_idor_app


def prepare_fixture(
    temporary_root: Path,
    parameters: Mapping[str, Any],
) -> Callable[[], RegisteredFixtureResult]:
    del temporary_root, parameters
    return prepare_flask_idor_app(
        application_id="app_2f6b10",
        policy=resource_policy_alpha,
    )


__all__ = ["prepare_fixture"]
