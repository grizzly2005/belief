"""File-oriented service used by the conservative ``validate-plan`` CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .execution_models import load_validation_fixture_bundle
from .plans import load_validation_plan_bundle
from .runner import (
    run_validation_plan_bundle,
    write_validation_result_bundle,
)


def validate_plan_files(
    *,
    plan_path: str | Path,
    fixture_path: str | Path,
    output_path: str | Path,
) -> dict[str, Any]:
    """Validate exact plan/fixture artifacts and create a result bundle."""

    plan_payload, plans = load_validation_plan_bundle(plan_path)
    _fixture_payload, contexts = load_validation_fixture_bundle(
        fixture_path
    )
    result = run_validation_plan_bundle(
        plans,
        contexts=contexts,
        source_bundle_digest=str(
            plan_payload["deterministic_digest"]
        ),
    )
    write_validation_result_bundle(output_path, result)
    return result


__all__ = ["validate_plan_files"]
