"""Versioned value objects for BELIEF's semantic analysis layer."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


FUNCTION_SUMMARY_SCHEMA_VERSION = "belief.function_summary.v2"
FLOW_STATE_SCHEMA_VERSION = "belief.flow_state.v1"
ANALYSIS_GAP_SCHEMA_VERSION = "belief.analysis_gap.v1"
GUARD_EFFECT_SCHEMA_VERSION = "belief.guard_effect.v1"
RESOURCE_IDENTITY_SCHEMA_VERSION = "belief.resource_identity.v2"
ROOT_CAUSE_IDENTITY_SCHEMA_VERSION = "belief.root_cause_identity.v2"
SECURITY_TRANSITION_SCHEMA_VERSION = "belief.security_transition.v1"


class SummaryKind(str, Enum):
    """Supported function-effect kinds."""

    IDENTITY = "identity"
    CONSTANT = "constant"
    PASSTHROUGH_ARGUMENT = "passthrough_argument"
    TRANSFORMED_ARGUMENT = "transformed_argument"
    SANITIZER = "sanitizer"
    VALIDATOR = "validator"
    PREDICATE_GUARD = "predicate_guard"
    ABORTIVE_GUARD = "abortive_guard"
    SOURCE = "source"
    SINK = "sink"
    WRAPPER = "wrapper"
    RECEIVER_OR_FIELD_READ = "receiver_or_field_read"
    RECEIVER_OR_FIELD_WRITE = "receiver_or_field_write"
    COLLECTION_INSERT = "collection_insert"
    COLLECTION_EXTRACT = "collection_extract"
    RETURN_FROM_PARAMETER = "return_from_parameter"
    RETURN_FROM_RECEIVER = "return_from_receiver"
    UNKNOWN = "unknown"


@dataclass(frozen=True, order=True)
class ResourceIdentity:
    """Stable identity for the value or resource affected by a security fact."""

    kind: str
    symbol: str
    path: tuple[str, ...] = ()
    context: str = ""

    def __post_init__(self) -> None:
        _require_text("resource kind", self.kind)
        _require_text("resource symbol", self.symbol)
        _validate_text_tuple("resource path", self.path, allow_empty=True)

    @property
    def canonical(self) -> str:
        suffix = ".".join(self.path)
        base = f"{self.kind}:{self.symbol}"
        if suffix:
            base = f"{base}.{suffix}"
        return f"{base}@{self.context}" if self.context else base

    @property
    def semantic_key(self) -> str:
        """Identity stable across harmless parameter and helper renames."""

        if self.kind == "parameter" and self.context.startswith("input:"):
            suffix = ".".join(self.path)
            base = f"{self.kind}:{self.context}"
            return f"{base}.{suffix}" if suffix else base
        return self.canonical

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RESOURCE_IDENTITY_SCHEMA_VERSION,
            "kind": self.kind,
            "symbol": self.symbol,
            "path": list(self.path),
            "context": self.context,
            "canonical": self.canonical,
            "semantic_key": self.semantic_key,
        }


@dataclass(frozen=True, order=True)
class FlowState:
    """One lattice fact attached to a value/resource and context."""

    property: str
    value: str
    resource: ResourceIdentity
    context: str = ""
    provenance: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text("flow-state property", self.property)
        _require_text("flow-state value", self.value)
        _validate_text_tuple(
            "flow-state provenance",
            self.provenance,
            allow_empty=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": FLOW_STATE_SCHEMA_VERSION,
            "property": self.property,
            "value": self.value,
            "resource": self.resource.to_dict(),
            "context": self.context,
            "provenance": list(self.provenance),
        }


@dataclass(frozen=True, order=True)
class GuardEffect:
    """Branch-specific change to a state for the same value/resource."""

    guard_id: str
    effect: str
    resource: ResourceIdentity
    state_property: str
    state_value: str
    branch: str = "true"
    abortive: bool = False
    dominates_sink: bool = False
    result_used: bool = True
    line: int | None = None

    def __post_init__(self) -> None:
        _require_text("guard ID", self.guard_id)
        _require_text("guard effect", self.effect)
        _require_text("guard state property", self.state_property)
        _require_text("guard state value", self.state_value)
        if self.branch not in {"true", "false", "both"}:
            raise ValueError("guard branch must be true, false, or both")
        _optional_positive_line(self.line)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": GUARD_EFFECT_SCHEMA_VERSION,
            "guard_id": self.guard_id,
            "effect": self.effect,
            "resource": self.resource.to_dict(),
            "state_property": self.state_property,
            "state_value": self.state_value,
            "branch": self.branch,
            "abortive": self.abortive,
            "dominates_sink": self.dominates_sink,
            "result_used": self.result_used,
            "line": self.line,
        }


@dataclass(frozen=True, order=True)
class RootCauseIdentity:
    """Semantic identity that survives harmless line and helper movement."""

    category: str
    source_kind: str
    sink_kind: str
    resource: ResourceIdentity
    security_property: str
    context: str = ""

    def __post_init__(self) -> None:
        for label, value in (
            ("root-cause category", self.category),
            ("root-cause source kind", self.source_kind),
            ("root-cause sink kind", self.sink_kind),
            ("root-cause security property", self.security_property),
        ):
            _require_text(label, value)

    @property
    def digest(self) -> str:
        return _semantic_digest(
            {
                "category": self.category,
                "source_kind": self.source_kind,
                "sink_kind": self.sink_kind,
                "resource": self.resource.semantic_key,
                "security_property": self.security_property,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ROOT_CAUSE_IDENTITY_SCHEMA_VERSION,
            "category": self.category,
            "source_kind": self.source_kind,
            "sink_kind": self.sink_kind,
            "resource": self.resource.to_dict(),
            "security_property": self.security_property,
            "context": self.context,
            "digest": self.digest,
        }


@dataclass(frozen=True, order=True)
class SecurityTransition:
    """One validated security-state transition."""

    transition_id: str
    kind: str
    resource: ResourceIdentity
    before: FlowState
    after: FlowState
    line: int | None = None
    control_path: tuple[str, ...] = ()
    result_used: bool = True

    def __post_init__(self) -> None:
        _require_text("transition ID", self.transition_id)
        _require_text("transition kind", self.kind)
        if self.before.resource != self.resource:
            raise ValueError("transition before-state resource mismatch")
        if self.after.resource != self.resource:
            raise ValueError("transition after-state resource mismatch")
        if self.before.property != self.after.property:
            raise ValueError("transition state property mismatch")
        _optional_positive_line(self.line)
        _validate_text_tuple(
            "transition control path",
            self.control_path,
            allow_empty=True,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SECURITY_TRANSITION_SCHEMA_VERSION,
            "transition_id": self.transition_id,
            "kind": self.kind,
            "resource": self.resource.to_dict(),
            "before": self.before.to_dict(),
            "after": self.after.to_dict(),
            "line": self.line,
            "control_path": list(self.control_path),
            "result_used": self.result_used,
        }


@dataclass(frozen=True)
class AnalysisGap:
    """Explicit evidence that bounded analysis did not complete a stage."""

    code: str
    stage: str
    reason: str
    file: str = ""
    function: str = ""
    line: int | None = None
    limit_name: str = ""
    limit_value: int | None = None
    observed_value: int | None = None
    details: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        _require_text("gap code", self.code)
        _require_text("gap stage", self.stage)
        _require_text("gap reason", self.reason)
        _optional_positive_line(self.line)
        for label, value in (
            ("gap limit", self.limit_value),
            ("gap observed value", self.observed_value),
        ):
            if value is not None and (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise ValueError(f"{label} must be a non-negative integer")
        if len({key for key, _ in self.details}) != len(self.details):
            raise ValueError("gap detail keys must be unique")
        for key, value in self.details:
            _require_text("gap detail key", key)
            _require_text("gap detail value", value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": ANALYSIS_GAP_SCHEMA_VERSION,
            "code": self.code,
            "stage": self.stage,
            "reason": self.reason,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "limit_name": self.limit_name,
            "limit_value": self.limit_value,
            "observed_value": self.observed_value,
            "details": dict(self.details),
        }

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.code,
            self.stage,
            self.reason,
            self.file,
            self.function,
            self.line or 0,
            self.limit_name,
            self.limit_value if self.limit_value is not None else -1,
            self.observed_value if self.observed_value is not None else -1,
            self.details,
        )


@dataclass(frozen=True)
class FunctionEffect:
    """One directly observed or propagated function behavior."""

    kind: SummaryKind
    value: str = ""
    parameter_index: int | None = None
    resource: ResourceIdentity | None = None
    context: str = ""
    line: int | None = None
    via: tuple[str, ...] = ()
    direct: bool = True
    result_used: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.kind, SummaryKind):
            raise ValueError("function effect kind must be SummaryKind")
        if self.parameter_index is not None and (
            not isinstance(self.parameter_index, int)
            or isinstance(self.parameter_index, bool)
            or self.parameter_index < 0
        ):
            raise ValueError(
                "function effect parameter index must be non-negative"
            )
        _optional_positive_line(self.line)
        _validate_text_tuple(
            "function effect propagation path",
            self.via,
            allow_empty=True,
        )
        if not isinstance(self.result_used, bool):
            raise ValueError("function effect result_used must be boolean")

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "value": self.value,
            "parameter_index": self.parameter_index,
            "resource": self.resource.to_dict() if self.resource else None,
            "context": self.context,
            "line": self.line,
            "via": list(self.via),
            "direct": self.direct,
            "result_used": self.result_used,
        }

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.kind.value,
            self.value,
            self.parameter_index if self.parameter_index is not None else -1,
            self.resource.canonical if self.resource else "",
            self.context,
            self.line or 0,
            self.via,
            self.direct,
            self.result_used,
        )


@dataclass(frozen=True)
class FunctionSummary:
    """Deterministic summary for one local function or method."""

    file: str
    qualified_name: str
    parameters: tuple[str, ...]
    effects: tuple[FunctionEffect, ...]
    callees: tuple[str, ...] = ()
    scc_id: int = 0
    iterations: int = 1
    complete: bool = True
    gaps: tuple[AnalysisGap, ...] = ()
    schema_version: str = field(
        default=FUNCTION_SUMMARY_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        _require_text("summary file", self.file)
        _require_text("summary qualified name", self.qualified_name)
        _validate_text_tuple(
            "summary parameters",
            self.parameters,
            allow_empty=True,
        )
        _validate_text_tuple(
            "summary callees",
            self.callees,
            allow_empty=True,
        )
        if len(set(self.parameters)) != len(self.parameters):
            raise ValueError("summary parameters must be unique")
        if len(set(self.callees)) != len(self.callees):
            raise ValueError("summary callees must be unique")
        if (
            not isinstance(self.scc_id, int)
            or isinstance(self.scc_id, bool)
            or self.scc_id < 0
        ):
            raise ValueError("summary SCC ID must be non-negative")
        if (
            not isinstance(self.iterations, int)
            or isinstance(self.iterations, bool)
            or self.iterations <= 0
        ):
            raise ValueError("summary iterations must be positive")
        if tuple(
            sorted(
                set(self.effects),
                key=lambda effect: effect.sort_key,
            )
        ) != self.effects:
            raise ValueError(
                "summary effects must be unique and deterministically sorted"
            )
        if tuple(
            sorted(
                set(self.gaps),
                key=lambda gap: gap.sort_key,
            )
        ) != self.gaps:
            raise ValueError(
                "summary gaps must be unique and deterministically sorted"
            )

    @property
    def deterministic_digest(self) -> str:
        return _semantic_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "file": self.file,
            "qualified_name": self.qualified_name,
            "parameters": list(self.parameters),
            "effects": [effect.to_dict() for effect in self.effects],
            "callees": list(self.callees),
            "scc_id": self.scc_id,
            "iterations": self.iterations,
            "complete": self.complete,
            "gaps": [gap.to_dict() for gap in self.gaps],
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._semantic_dict()
        payload["deterministic_digest"] = self.deterministic_digest
        return payload


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_text(label: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")


def _validate_text_tuple(
    label: str,
    value: tuple[str, ...],
    *,
    allow_empty: bool,
) -> None:
    if not isinstance(value, tuple):
        raise ValueError(f"{label} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{label} must not be empty")
    if any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{label} must contain non-empty strings")


def _optional_positive_line(value: int | None) -> None:
    if value is not None and (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value <= 0
    ):
        raise ValueError("line must be a positive integer")


__all__ = [
    "ANALYSIS_GAP_SCHEMA_VERSION",
    "FLOW_STATE_SCHEMA_VERSION",
    "FUNCTION_SUMMARY_SCHEMA_VERSION",
    "GUARD_EFFECT_SCHEMA_VERSION",
    "RESOURCE_IDENTITY_SCHEMA_VERSION",
    "ROOT_CAUSE_IDENTITY_SCHEMA_VERSION",
    "SECURITY_TRANSITION_SCHEMA_VERSION",
    "AnalysisGap",
    "FlowState",
    "FunctionEffect",
    "FunctionSummary",
    "GuardEffect",
    "ResourceIdentity",
    "RootCauseIdentity",
    "SecurityTransition",
    "SummaryKind",
]
