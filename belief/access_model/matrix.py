"""Small helpers for role/object access matrices."""

from __future__ import annotations

from belief.tools.schemas import AccessObservation


def observations_to_matrix(observations: list[AccessObservation]) -> dict:
    roles = sorted({obs.role or "user" for obs in observations})
    routes = sorted({f"{obs.method or 'GET'} {obs.path or ''}" for obs in observations})
    cells = {}
    for obs in observations:
        role = obs.role or "user"
        route = f"{obs.method or 'GET'} {obs.path or ''}"
        cells.setdefault(route, {})[role] = {
            "expected_guard": obs.expected_guard,
            "missing_guards": list(obs.missing_guards),
            "mutation": obs.mutation,
        }
    return {"roles": roles, "routes": routes, "cells": cells}


__all__ = ["observations_to_matrix"]
