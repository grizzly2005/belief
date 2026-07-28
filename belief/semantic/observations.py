"""Deterministic output records for semantic flow-state analysis."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from ..models import Finding
from .models import (
    AnalysisGap,
    GuardEffect,
    ResourceIdentity,
    RootCauseIdentity,
    SecurityTransition,
)


SEMANTIC_FLOW_ANALYSIS_SCHEMA_VERSION = "belief.semantic_flow_analysis.v1"
SEMANTIC_CONCERN_SCHEMA_VERSION = "belief.semantic_concern.v1"


@dataclass(frozen=True)
class SemanticFlowLimits:
    """Hard limits for the composable flow-state pass."""

    max_files: int = 100
    max_functions: int = 2_000
    max_ast_nodes: int = 100_000
    max_concerns_per_function: int = 16
    max_guards_per_function: int = 32
    max_transitions_per_function: int = 32

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_files": self.max_files,
            "max_functions": self.max_functions,
            "max_ast_nodes": self.max_ast_nodes,
            "max_concerns_per_function": (self.max_concerns_per_function),
            "max_guards_per_function": self.max_guards_per_function,
            "max_transitions_per_function": (self.max_transitions_per_function),
        }


@dataclass(frozen=True)
class SemanticConcern:
    """One root-cause concern produced without benchmark metadata."""

    contract_id: str
    category: str
    cwe: str
    title: str
    description: str
    file: str
    line: int
    function: str
    class_name: str
    resource: ResourceIdentity
    source: str
    sink: str
    missing_states: tuple[str, ...]
    evidence: str
    confidence: float
    root_cause: RootCauseIdentity
    end_line: int | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("contract ID", self.contract_id),
            ("concern category", self.category),
            ("concern CWE", self.cwe),
            ("concern title", self.title),
            ("concern description", self.description),
            ("concern file", self.file),
            ("concern function", self.function),
            ("concern source", self.source),
            ("concern sink", self.sink),
            ("concern evidence", self.evidence),
        ):
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{label} must be a non-empty string")
        if not isinstance(self.line, int) or isinstance(self.line, bool) or self.line <= 0:
            raise ValueError("concern line must be positive")
        if self.end_line is not None and (
            not isinstance(self.end_line, int)
            or isinstance(self.end_line, bool)
            or self.end_line < self.line
        ):
            raise ValueError("concern end line must not precede line")
        if not self.missing_states or any(
            not isinstance(value, str) or not value.strip() for value in self.missing_states
        ):
            raise ValueError("concern missing states must contain non-empty strings")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise ValueError("concern confidence must be between zero and one")
        if self.root_cause.resource != self.resource:
            raise ValueError("concern root-cause resource mismatch")

    @property
    def deterministic_digest(self) -> str:
        return _semantic_digest(self._semantic_dict())

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.file,
            self.line,
            self.function,
            self.contract_id,
            self.root_cause.digest,
        )

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SEMANTIC_CONCERN_SCHEMA_VERSION,
            "contract_id": self.contract_id,
            "category": self.category,
            "cwe": self.cwe,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "function": self.function,
            "class_name": self.class_name,
            "resource": self.resource.to_dict(),
            "source": self.source,
            "sink": self.sink,
            "missing_states": list(self.missing_states),
            "evidence": self.evidence,
            "confidence": round(float(self.confidence), 6),
            "root_cause": self.root_cause.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._semantic_dict()
        payload["deterministic_digest"] = self.deterministic_digest
        return payload

    def to_finding(self) -> Finding:
        """Normalize the concern into BELIEF's stable finding model."""

        dataflow = {
            "source": self.source,
            "sink": self.sink,
            "missing_guarantees": list(self.missing_states),
            "guarantees": [],
            "sanitizers": [],
        }
        return Finding(
            source="belief.semantic",
            rule_id=self.contract_id,
            title=self.title,
            description=self.description,
            file=self.file,
            line=self.line,
            end_line=self.end_line,
            cwe=self.cwe,
            severity="high",
            confidence=self.confidence,
            evidence=self.evidence,
            dedup_key=self.root_cause.digest,
            metadata={
                "analysis_profile": "patch_review",
                "semantic_analysis": True,
                "semantic_category": self.category,
                "semantic_contract_id": self.contract_id,
                "semantic_concern_digest": self.deterministic_digest,
                "root_cause_identity": self.root_cause.to_dict(),
                "function_name": self.function,
                "class_name": self.class_name,
                "canonical_key": self.root_cause.digest,
                "dataflow": dataflow,
            },
        )


@dataclass(frozen=True)
class SemanticFlowAnalysis:
    """Bounded flow-state analysis with explicit incompleteness."""

    target: str
    concerns: tuple[SemanticConcern, ...]
    guards: tuple[GuardEffect, ...]
    transitions: tuple[SecurityTransition, ...]
    gaps: tuple[AnalysisGap, ...]
    limits: SemanticFlowLimits
    metrics: tuple[tuple[str, int], ...]
    function_summary_digest: str
    schema_version: str = field(
        default=SEMANTIC_FLOW_ANALYSIS_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        if not self.target:
            raise ValueError("semantic flow target must not be empty")
        if tuple(sorted(self.concerns, key=lambda item: item.sort_key)) != self.concerns:
            raise ValueError("semantic concerns must be sorted")
        if len(set(item.deterministic_digest for item in self.concerns)) != (len(self.concerns)):
            raise ValueError("semantic concerns must be unique")
        if tuple(sorted(self.guards, key=_guard_sort_key)) != self.guards:
            raise ValueError("semantic guards must be sorted")
        if tuple(sorted(self.transitions, key=_transition_sort_key)) != self.transitions:
            raise ValueError("semantic transitions must be sorted")
        if tuple(sorted(self.gaps, key=lambda gap: gap.sort_key)) != self.gaps:
            raise ValueError("semantic gaps must be sorted")
        if tuple(sorted(set(self.metrics))) != self.metrics:
            raise ValueError("semantic metrics must be sorted and unique")
        if any(value < 0 for _, value in self.metrics):
            raise ValueError("semantic metrics must be non-negative")
        _validate_digest(
            self.function_summary_digest,
            "function summary digest",
        )

    @property
    def deterministic_digest(self) -> str:
        return _semantic_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "concerns": [item.to_dict() for item in self.concerns],
            "guards": [item.to_dict() for item in self.guards],
            "transitions": [item.to_dict() for item in self.transitions],
            "gaps": [item.to_dict() for item in self.gaps],
            "limits": self.limits.to_dict(),
            "metrics": dict(self.metrics),
            "function_summary_digest": self.function_summary_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._semantic_dict()
        payload["deterministic_digest"] = self.deterministic_digest
        return payload


def _guard_sort_key(value: GuardEffect) -> tuple[Any, ...]:
    return (
        value.guard_id,
        value.resource.canonical,
        value.state_property,
        value.state_value,
        value.branch,
        value.line or 0,
    )


def _transition_sort_key(
    value: SecurityTransition,
) -> tuple[Any, ...]:
    return (
        value.transition_id,
        value.resource.canonical,
        value.before.property,
        value.before.value,
        value.after.value,
        value.line or 0,
    )


def _validate_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "SEMANTIC_CONCERN_SCHEMA_VERSION",
    "SEMANTIC_FLOW_ANALYSIS_SCHEMA_VERSION",
    "SemanticConcern",
    "SemanticFlowAnalysis",
    "SemanticFlowLimits",
]
