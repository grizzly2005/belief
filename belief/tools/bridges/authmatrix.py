from __future__ import annotations

from pathlib import Path
from typing import Any

from belief.exporters.authmatrix import export_authmatrix_state
from belief.json_contracts import load_json_file
from belief.tools.schemas import AccessObservation, NormalizedToolResult

from .base import ManifestBridge


class AuthMatrixBridge(ManifestBridge):
    tool_id = "authmatrix"

    def is_available(self) -> bool:
        return False

    def import_file(self, path: str | Path) -> NormalizedToolResult:
        source = Path(path)
        payload = load_json_file(source)
        return NormalizedToolResult(
            tool_id=self.tool_id,
            access_observations=_authmatrix_observations(payload),
            artifacts=[source],
            raw={"format": "authmatrix-like-json"},
        )

    def export_state(self, observations: list[AccessObservation]) -> dict:
        return export_authmatrix_state(observations)


def _authmatrix_observations(payload: dict[str, Any]) -> list[AccessObservation]:
    requests = payload.get("requests") if isinstance(payload, dict) else []
    observations = []
    for row in requests if isinstance(requests, list) else []:
        if not isinstance(row, dict):
            continue
        expected = row.get("expected_allowed")
        missing = [] if expected is True else ["authorization_rule"]
        observations.append(AccessObservation(
            source_tool="authmatrix",
            actor=str(row.get("user") or "") or None,
            role=str(row.get("role") or "") or None,
            method=str(row.get("method") or "GET").upper(),
            path=str(row.get("path") or row.get("url") or ""),
            object_type=str(row.get("object_type") or "") or None,
            object_id_source=str(row.get("object_id_source") or "") or None,
            action=str(row.get("action") or "") or None,
            expected_guard=str(row.get("expected_guard") or "") or None,
            detected_guards=[str(v) for v in row.get("detected_guards", [])] if isinstance(row.get("detected_guards"), list) else [],
            missing_guards=missing,
            mutation=bool(row.get("mutation", False)),
            confidence=str(row.get("confidence") or "") or None,
            evidence=[str(v) for v in row.get("evidence", [])] if isinstance(row.get("evidence"), list) else [],
        ))
    return sorted(observations, key=lambda item: (item.path or "", item.method or "", item.role or ""))


__all__ = ["AuthMatrixBridge"]
