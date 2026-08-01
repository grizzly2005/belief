"""Pure C-fragment exporter for manual reachability-tool integration."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from .models import ExplorationObjective, ExplorationTarget

C_REACHABILITY_PROBE_SCHEMA_VERSION = "belief.c_reachability_probe.v1"


@dataclass(frozen=True)
class CReachabilityProbe:
    objective_id: str
    source_plan_id: str
    target: ExplorationTarget
    integration_mode: str
    source: str
    source_sha256: str
    schema_version: str = C_REACHABILITY_PROBE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != C_REACHABILITY_PROBE_SCHEMA_VERSION:
            raise ValueError("unsupported CReachabilityProbe schema")
        if not isinstance(self.target, ExplorationTarget):
            raise ValueError("CReachabilityProbe target must be immutable")
        if self.integration_mode != "manual_function_scope_fragment":
            raise ValueError("unsupported CReachabilityProbe integration mode")
        if not isinstance(self.source, str) or not 1 <= len(self.source) <= 4096:
            raise ValueError("CReachabilityProbe source is not bounded")
        expected_digest = hashlib.sha256(self.source.encode("utf-8")).hexdigest()
        if self.source_sha256 != expected_digest:
            raise ValueError("CReachabilityProbe source digest does not match")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "objective_id": self.objective_id,
            "source_plan_id": self.source_plan_id,
            "target": self.target.to_dict(),
            "integration_mode": self.integration_mode,
            "source": self.source,
            "source_sha256": self.source_sha256,
            "compiled": False,
            "executed": False,
        }


def export_c_reachability_probe(
    objective: ExplorationObjective,
) -> CReachabilityProbe:
    """Render a bounded function-scope fragment without writing or executing it."""

    target = objective.target
    source = (
        "/*\n"
        " * BELIEF research reachability fragment.\n"
        f" * objective_id: {objective.objective_id}\n"
        f" * source_plan_id: {objective.source_plan_id}\n"
        f" * function_scope: {objective.function}\n"
        f" * target: {target.file}:{target.line}:{target.symbol}\n"
        " * integration_mode: manual_function_scope_fragment\n"
        " * BELIEF does not compile or execute this fragment.\n"
        " */\n"
        f"if ({objective.constraint.expression}) {{\n"
        "    BELIEF_REACHABILITY_TARGET();\n"
        "}\n"
    )
    return CReachabilityProbe(
        objective_id=objective.objective_id,
        source_plan_id=objective.source_plan_id,
        target=target,
        integration_mode="manual_function_scope_fragment",
        source=source,
        source_sha256=hashlib.sha256(source.encode("utf-8")).hexdigest(),
    )


__all__ = [
    "C_REACHABILITY_PROBE_SCHEMA_VERSION",
    "CReachabilityProbe",
    "export_c_reachability_probe",
]
