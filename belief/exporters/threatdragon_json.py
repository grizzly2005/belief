"""Small threat-model JSON exporter inspired by OWASP Threat Dragon concepts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from belief.access_model.models import AccessHypothesis
from belief.tools.schemas import AccessObservation, to_jsonable


def export_threatdragon_json(items: Iterable[AccessHypothesis | AccessObservation]) -> dict:
    actors = set()
    threats = []
    data_flows = []
    for item in items:
        if isinstance(item, AccessHypothesis):
            actor = (item.actor.name if item.actor else "user")
            route = item.route or "unknown"
            title = item.title
            mitigations = [guard.expression for guard in item.detected_guards]
        else:
            actor = item.actor or item.role or "user"
            route = item.path or "unknown"
            title = f"{item.action or 'access'} {route}"
            mitigations = item.detected_guards
        actors.add(actor)
        data_flows.append({"from": actor, "to": route, "protocol": "HTTP"})
        threats.append({
            "title": title,
            "status": "candidate",
            "route": route,
            "mitigations": mitigations,
        })
    return {
        "schema": "belief.threatdragon.v1",
        "actors": sorted(actors),
        "assets": sorted({flow["to"] for flow in data_flows}),
        "data_flows": data_flows,
        "trust_boundaries": ["client/server", "actor/object"],
        "threats": sorted(threats, key=lambda item: (item["route"], item["title"])),
    }


def write_threatdragon_json(items: Iterable[AccessHypothesis | AccessObservation], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(to_jsonable(export_threatdragon_json(items)), indent=2, sort_keys=True),
        encoding="utf-8",
    )


__all__ = ["export_threatdragon_json", "write_threatdragon_json"]
