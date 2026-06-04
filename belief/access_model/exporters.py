"""Convenience exporters for access hypotheses."""

from __future__ import annotations

from belief.exporters.autorize_recipe import export_autorize_recipes
from belief.exporters.threatdragon_json import export_threatdragon_json

from .models import AccessHypothesis


def export_access_hypotheses(hypotheses: list[AccessHypothesis]) -> dict:
    return {
        "schema": "belief.access_hypotheses.v1",
        "hypotheses": [hyp.to_dict() for hyp in hypotheses],
        "autorize_recipes": export_autorize_recipes(hypotheses)["recipes"],
        "threat_model": export_threatdragon_json(hypotheses),
    }


__all__ = ["export_access_hypotheses"]
