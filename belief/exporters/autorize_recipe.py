"""Autorize-style validation recipe exporter without secrets."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from belief.access_model.models import AccessHypothesis
from belief.tools.schemas import AccessObservation, to_jsonable


SECURE_STATUS_CODES = [401, 403, 404]


def export_autorize_recipes(items: Iterable[AccessHypothesis | AccessObservation]) -> dict:
    recipes = []
    for item in items:
        if isinstance(item, AccessHypothesis):
            recipes.append(_hypothesis_recipe(item))
        else:
            recipes.append(_observation_recipe(item))
    recipes = sorted(recipes, key=lambda row: (row["path"], row["method"], row["title"]))
    return {
        "schema": "belief.autorize_recipe.v1",
        "secrets": "not_exported",
        "recipes": recipes,
    }


def write_autorize_recipes(items: Iterable[AccessHypothesis | AccessObservation], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(to_jsonable(export_autorize_recipes(items)), indent=2, sort_keys=True),
        encoding="utf-8",
    )


def _hypothesis_recipe(item: AccessHypothesis) -> dict:
    return {
        "title": item.title,
        "method": "REPLAY",
        "path": item.route or "",
        "roles_to_test": ["same_privilege_different_owner", "unauthenticated"],
        "high_privileged_context": "<provide manually outside repo>",
        "low_privileged_context": "<provide manually outside repo>",
        "unauthenticated_mode": True,
        "expected_secure_status_codes": SECURE_STATUS_CODES,
        "evidence_needed": list(item.validation_steps),
    }


def _observation_recipe(item: AccessObservation) -> dict:
    return {
        "title": f"{item.action or 'access'} {item.path or ''}".strip(),
        "method": item.method or "GET",
        "path": item.path or "",
        "roles_to_test": [item.role or "same_privilege_different_owner", "unauthenticated"],
        "high_privileged_context": "<provide manually outside repo>",
        "low_privileged_context": "<provide manually outside repo>",
        "unauthenticated_mode": True,
        "expected_secure_status_codes": SECURE_STATUS_CODES,
        "evidence_needed": list(item.evidence) or ["Compare high-privilege and low-privilege responses."],
    }


__all__ = ["SECURE_STATUS_CODES", "export_autorize_recipes", "write_autorize_recipes"]
