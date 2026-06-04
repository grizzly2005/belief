"""AuthMatrix-like deterministic JSON exporter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from belief.tools.schemas import AccessObservation, to_jsonable


def export_authmatrix_state(observations: Iterable[AccessObservation]) -> dict:
    rows = []
    roles = set()
    for obs in sorted(observations, key=lambda item: (item.path or "", item.method or "", item.role or "")):
        role = obs.role or "user"
        roles.add(role)
        rows.append({
            "method": obs.method or "GET",
            "path": obs.path or "",
            "role": role,
            "expected_allowed": not bool(obs.missing_guards),
            "expected_guard": obs.expected_guard,
            "detected_guards": list(obs.detected_guards),
            "missing_guards": list(obs.missing_guards),
            "object_id_source": obs.object_id_source,
            "mutation": bool(obs.mutation),
            "evidence": list(obs.evidence),
        })
    return {
        "schema": "belief.authmatrix.v1",
        "roles": sorted(roles),
        "requests": rows,
        "secrets": "not_exported",
    }


def write_authmatrix_state(observations: Iterable[AccessObservation], path: str | Path) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(to_jsonable(export_authmatrix_state(observations)), indent=2, sort_keys=True),
        encoding="utf-8",
    )


__all__ = ["export_authmatrix_state", "write_authmatrix_state"]
