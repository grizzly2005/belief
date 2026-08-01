"""Trusted composition of one app with a physically independent evaluator."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ...worker.registry import RegisteredFixtureResult
def prepare_fixture(
    fixture_id: str,
    temporary_root: Path,
    parameters: Mapping[str, Any],
):
    """Return the closed fixture executor for one opaque registry identity."""

    include_symlink = parameters.get("include_symlink", True)
    if fixture_id == "fx_01d7c2_v1":
        from .apps.f01 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_18a4e9_v1":
        from .apps.f02 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_2f6b10_v1":
        from .apps.f03 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_3c8d57_v1":
        from .apps.f04 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_47e1a3_v1":
        from .apps.f05 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_5b9c20_v1":
        from .apps.f06 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_6d04f8_v1":
        from .apps.f07 import prepare

        application = prepare(temporary_root, parameters)
    elif fixture_id == "fx_7a2e61_v1":
        from .apps.f08 import prepare

        application = prepare(temporary_root, parameters)
    else:
        raise ValueError("unknown closed fixture identity")

    path_fixture = fixture_id in {
        "fx_01d7c2_v1",
        "fx_18a4e9_v1",
        "fx_47e1a3_v1",
        "fx_5b9c20_v1",
    }
    if path_fixture:
        from .ground_truth.path import PATH_SCENARIOS
        from .oracles.path import evaluate_path_application
    else:
        from .ground_truth.idor import IDOR_SCENARIOS
        from .oracles.idor import evaluate_resource_application

    def execute() -> RegisteredFixtureResult:
        if path_fixture:
            observations, limitations = evaluate_path_application(
                application,
                PATH_SCENARIOS,
                include_symlink=include_symlink,
            )
        else:
            observations, limitations = evaluate_resource_application(
                application,
                IDOR_SCENARIOS,
            )
        return RegisteredFixtureResult(
            observations=observations,
            limitations=limitations,
            capability_used=(
                "flask_test_client"
                if fixture_id
                in {
                    "fx_01d7c2_v1",
                    "fx_18a4e9_v1",
                    "fx_2f6b10_v1",
                    "fx_3c8d57_v1",
                }
                else "fastapi_bounded_sync_asgi_micro_harness"
            ),
        )

    return execute


__all__ = ["prepare_fixture"]
