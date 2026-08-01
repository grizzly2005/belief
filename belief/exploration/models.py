"""Versioned contracts for the C reachability-objective research pilot."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from belief.json_contracts import strict_json_dumps

from .c_expression import normalize_c_boolean_expression

EXPLORATION_OBJECTIVE_SCHEMA_VERSION = "belief.exploration_objective.v1"
PATH_ARTIFACT_SCHEMA_VERSION = "belief.path_artifact.v1"
EXPLORATION_ASSESSMENT_SCHEMA_VERSION = "belief.exploration_assessment.v1"

EXPECTED_EXPLORATION_OUTPUTS = (
    "plausible_path_artifact",
    "no_plausible_path",
    "inconclusive",
)
EXPLORATION_INTERPRETATIONS = {"supported", "refuted", "inconclusive"}
CONSTRAINT_ORIGINS = {
    "human_reviewed_candidate",
    "llm_candidate_unverified",
    "missing_security_evidence",
}
PATH_STEP_KINDS = {"entry", "branch", "call", "target", "other"}

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SUBJECT_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,160}$")
_PLAN_ID = re.compile(r"^vp_[0-9a-f]{16}$")
_OBJECTIVE_ID = re.compile(r"^eo_[0-9a-f]{16}$")
_ARTIFACT_ID = re.compile(r"^pa_[0-9a-f]{16}$")
_TOOL_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")


@dataclass(frozen=True)
class ExplorationTarget:
    file: str
    line: int
    symbol: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _relative_c_path(self.file))
        object.__setattr__(self, "line", _positive_line(self.line))
        object.__setattr__(self, "symbol", _c_identifier(self.symbol, "target.symbol"))

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "symbol": self.symbol}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExplorationTarget":
        _exact_fields(payload, {"file", "line", "symbol"}, "target")
        return cls(
            file=payload["file"],
            line=payload["line"],
            symbol=payload["symbol"],
        )


@dataclass(frozen=True)
class ExplorationConstraint:
    expression: str
    logic: str = "c_boolean_expression_v1"
    origin: str = "missing_security_evidence"

    def __post_init__(self) -> None:
        if self.logic != "c_boolean_expression_v1":
            raise ValueError("unsupported exploration constraint logic")
        if self.origin not in CONSTRAINT_ORIGINS:
            raise ValueError("unsupported exploration constraint origin")
        object.__setattr__(
            self,
            "expression",
            normalize_c_boolean_expression(self.expression),
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "expression": self.expression,
            "logic": self.logic,
            "origin": self.origin,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExplorationConstraint":
        _exact_fields(payload, {"expression", "logic", "origin"}, "constraint")
        return cls(
            expression=payload["expression"],
            logic=payload["logic"],
            origin=payload["origin"],
        )


@dataclass(frozen=True)
class ExplorationObjective:
    subject_id: str
    source_plan_id: str
    function: str
    target: ExplorationTarget
    constraint: ExplorationConstraint
    language: str = "c"
    entry_boundary: str = "function_entry"
    expected_outputs: tuple[str, ...] = EXPECTED_EXPLORATION_OUTPUTS
    objective_id: str = ""
    schema_version: str = EXPLORATION_OBJECTIVE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EXPLORATION_OBJECTIVE_SCHEMA_VERSION:
            raise ValueError("unsupported ExplorationObjective schema")
        if self.language != "c":
            raise ValueError("the exploration pilot supports only C")
        if self.entry_boundary != "function_entry":
            raise ValueError("the exploration pilot supports only function entry")
        if tuple(self.expected_outputs) != EXPECTED_EXPLORATION_OUTPUTS:
            raise ValueError("ExplorationObjective expected outputs are fixed")
        if not isinstance(self.subject_id, str) or not _SUBJECT_ID.fullmatch(
            self.subject_id
        ):
            raise ValueError("ExplorationObjective subject_id is not canonical")
        if not isinstance(self.source_plan_id, str) or not _PLAN_ID.fullmatch(
            self.source_plan_id
        ):
            raise ValueError("ExplorationObjective source_plan_id is not canonical")
        if not isinstance(self.target, ExplorationTarget):
            raise ValueError("ExplorationObjective target must be an ExplorationTarget")
        if not isinstance(self.constraint, ExplorationConstraint):
            raise ValueError(
                "ExplorationObjective constraint must be an ExplorationConstraint"
            )
        object.__setattr__(
            self,
            "function",
            _c_identifier(self.function, "function"),
        )
        expected_id = _stable_id("eo_", self._identity_payload())
        if self.objective_id and self.objective_id != expected_id:
            raise ValueError("ExplorationObjective objective_id does not match content")
        object.__setattr__(self, "objective_id", expected_id)

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "subject_id": self.subject_id,
            "source_plan_id": self.source_plan_id,
            "language": self.language,
            "function": self.function,
            "entry_boundary": self.entry_boundary,
            "target": self.target.to_dict(),
            "constraint": self.constraint.to_dict(),
            "expected_outputs": list(self.expected_outputs),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "objective_id": self.objective_id,
            **self._identity_payload(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ExplorationObjective":
        _exact_fields(
            payload,
            {
                "schema_version",
                "objective_id",
                "subject_id",
                "source_plan_id",
                "language",
                "function",
                "entry_boundary",
                "target",
                "constraint",
                "expected_outputs",
            },
            "ExplorationObjective",
        )
        target = _mapping(payload["target"], "target")
        constraint = _mapping(payload["constraint"], "constraint")
        outputs = _string_sequence(payload["expected_outputs"], "expected_outputs")
        return cls(
            schema_version=payload["schema_version"],
            objective_id=payload["objective_id"],
            subject_id=payload["subject_id"],
            source_plan_id=payload["source_plan_id"],
            language=payload["language"],
            function=payload["function"],
            entry_boundary=payload["entry_boundary"],
            target=ExplorationTarget.from_dict(target),
            constraint=ExplorationConstraint.from_dict(constraint),
            expected_outputs=outputs,
        )


@dataclass(frozen=True)
class PathStep:
    file: str
    line: int
    symbol: str
    kind: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "file", _relative_c_path(self.file))
        object.__setattr__(self, "line", _positive_line(self.line))
        object.__setattr__(self, "symbol", _c_identifier(self.symbol, "path.symbol"))
        if self.kind not in PATH_STEP_KINDS:
            raise ValueError("unsupported path step kind")

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file,
            "line": self.line,
            "symbol": self.symbol,
            "kind": self.kind,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PathStep":
        _exact_fields(payload, {"file", "line", "symbol", "kind"}, "path step")
        return cls(
            file=payload["file"],
            line=payload["line"],
            symbol=payload["symbol"],
            kind=payload["kind"],
        )


@dataclass(frozen=True)
class PathArtifact:
    objective_id: str
    tool_id: str
    outcome: str
    reason: str
    path: tuple[PathStep, ...] = ()
    artifact_id: str = ""
    schema_version: str = PATH_ARTIFACT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != PATH_ARTIFACT_SCHEMA_VERSION:
            raise ValueError("unsupported PathArtifact schema")
        if not isinstance(self.objective_id, str) or not _OBJECTIVE_ID.fullmatch(
            self.objective_id
        ):
            raise ValueError("PathArtifact objective_id is not canonical")
        if not isinstance(self.tool_id, str) or not _TOOL_ID.fullmatch(self.tool_id):
            raise ValueError("PathArtifact tool_id is not canonical")
        if self.outcome not in EXPECTED_EXPLORATION_OUTPUTS:
            raise ValueError("unsupported PathArtifact outcome")
        reason = _bounded_text(self.reason, "reason", maximum=1000)
        object.__setattr__(self, "reason", reason)
        path = tuple(self.path)
        if len(path) > 256:
            raise ValueError("PathArtifact exceeds 256 path steps")
        if not all(isinstance(step, PathStep) for step in path):
            raise ValueError("PathArtifact path must contain PathStep values")
        if self.outcome == "plausible_path_artifact":
            if len(path) < 2 or path[0].kind != "entry" or path[-1].kind != "target":
                raise ValueError("plausible path must run from entry to target")
        elif self.outcome == "no_plausible_path" and path:
            raise ValueError("no_plausible_path must not contain path steps")
        object.__setattr__(self, "path", path)
        expected_id = _stable_id("pa_", self._identity_payload())
        if self.artifact_id and self.artifact_id != expected_id:
            raise ValueError("PathArtifact artifact_id does not match content")
        object.__setattr__(self, "artifact_id", expected_id)

    def _identity_payload(self) -> dict[str, Any]:
        return {
            "objective_id": self.objective_id,
            "tool_id": self.tool_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "path": [step.to_dict() for step in self.path],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "artifact_id": self.artifact_id,
            **self._identity_payload(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "PathArtifact":
        _exact_fields(
            payload,
            {
                "schema_version",
                "artifact_id",
                "objective_id",
                "tool_id",
                "outcome",
                "reason",
                "path",
            },
            "PathArtifact",
        )
        path_payload = payload["path"]
        if not isinstance(path_payload, list):
            raise ValueError("PathArtifact path must be an array")
        return cls(
            schema_version=payload["schema_version"],
            artifact_id=payload["artifact_id"],
            objective_id=payload["objective_id"],
            tool_id=payload["tool_id"],
            outcome=payload["outcome"],
            reason=payload["reason"],
            path=tuple(
                PathStep.from_dict(_mapping(item, "path step"))
                for item in path_payload
            ),
        )


@dataclass(frozen=True)
class ExplorationAssessment:
    objective_id: str
    artifact_id: str
    interpretation: str
    reason: str
    path_step_count: int
    schema_version: str = EXPLORATION_ASSESSMENT_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != EXPLORATION_ASSESSMENT_SCHEMA_VERSION:
            raise ValueError("unsupported ExplorationAssessment schema")
        if not isinstance(self.objective_id, str) or not _OBJECTIVE_ID.fullmatch(
            self.objective_id
        ):
            raise ValueError("ExplorationAssessment objective_id is not canonical")
        if not isinstance(self.artifact_id, str) or not _ARTIFACT_ID.fullmatch(
            self.artifact_id
        ):
            raise ValueError("ExplorationAssessment artifact_id is not canonical")
        if self.interpretation not in EXPLORATION_INTERPRETATIONS:
            raise ValueError("unsupported exploration interpretation")
        object.__setattr__(
            self,
            "reason",
            _bounded_text(self.reason, "reason", maximum=1000),
        )
        if (
            isinstance(self.path_step_count, bool)
            or not isinstance(self.path_step_count, int)
            or not 0 <= self.path_step_count <= 256
        ):
            raise ValueError("ExplorationAssessment path_step_count is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "objective_id": self.objective_id,
            "artifact_id": self.artifact_id,
            "interpretation": self.interpretation,
            "reason": self.reason,
            "path_step_count": self.path_step_count,
            "confirms_vulnerability": False,
        }


def assess_path_artifact(
    objective: ExplorationObjective,
    artifact: PathArtifact,
) -> ExplorationAssessment:
    if artifact.objective_id != objective.objective_id:
        raise ValueError("PathArtifact is not bound to the ExplorationObjective")
    if artifact.outcome == "plausible_path_artifact":
        first = artifact.path[0]
        target = artifact.path[-1]
        if (
            first.file != objective.target.file
            or first.symbol != objective.function
        ):
            raise ValueError("PathArtifact entry does not match objective function")
        if (
            target.file != objective.target.file
            or target.line != objective.target.line
            or target.symbol != objective.target.symbol
        ):
            raise ValueError("PathArtifact target does not match objective target")
        interpretation = "supported"
    elif artifact.outcome == "no_plausible_path":
        interpretation = "refuted"
    else:
        interpretation = "inconclusive"
    return ExplorationAssessment(
        objective_id=objective.objective_id,
        artifact_id=artifact.artifact_id,
        interpretation=interpretation,
        reason=artifact.reason,
        path_step_count=len(artifact.path),
    )


def _exact_fields(
    payload: Mapping[str, Any],
    expected: set[str],
    context: str,
) -> None:
    if not isinstance(payload, Mapping) or set(payload) != expected:
        actual = set(payload) if isinstance(payload, Mapping) else set()
        raise ValueError(
            f"{context} fields mismatch; missing={sorted(expected - actual)}, "
            f"unknown={sorted(actual - expected)}"
        )


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a JSON object")
    return value


def _string_sequence(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{field} must be an array")
    if not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field} must contain strings")
    return tuple(value)


def _relative_c_path(value: Any) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or "\\" in value
        or ":" in value
    ):
        raise ValueError("C target file must be a portable relative path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix.lower() != ".c"
    ):
        raise ValueError("C target file must be a normalized relative .c path")
    return value


def _positive_line(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 10_000_000:
        raise ValueError("source line must be a bounded positive integer")
    return value


def _c_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a C identifier")
    return value


def _bounded_text(value: Any, field: str, *, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    text = " ".join(value.strip().split())
    if not text or len(text) > maximum:
        raise ValueError(f"{field} must contain 1..{maximum} characters")
    return text


def _stable_id(prefix: str, payload: Any) -> str:
    encoded = strict_json_dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return prefix + hashlib.sha256(encoded).hexdigest()[:16]


__all__ = [
    "CONSTRAINT_ORIGINS",
    "EXPECTED_EXPLORATION_OUTPUTS",
    "EXPLORATION_ASSESSMENT_SCHEMA_VERSION",
    "EXPLORATION_INTERPRETATIONS",
    "EXPLORATION_OBJECTIVE_SCHEMA_VERSION",
    "PATH_ARTIFACT_SCHEMA_VERSION",
    "ExplorationAssessment",
    "ExplorationConstraint",
    "ExplorationObjective",
    "ExplorationTarget",
    "PathArtifact",
    "PathStep",
    "assess_path_artifact",
]
