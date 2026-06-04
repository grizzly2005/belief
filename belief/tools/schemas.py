from __future__ import annotations

from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Literal


ToolExecutionMode = Literal[
    "external_cli",
    "passive_import",
    "recipe_export",
    "docker",
    "python_module",
    "unavailable",
]


@dataclass(frozen=True)
class ToolRiskProfile:
    network: bool = False
    active_scanning: bool = False
    replays_requests: bool = False
    fuzzing: bool = False
    executes_target_code: bool = False
    writes_files: bool = False
    requires_auth_tokens: bool = False
    external_services: bool = False
    safe_default: bool = True


@dataclass(frozen=True)
class ToolManifest:
    tool_id: str
    name: str
    repo: str | None
    license: str | None
    description: str
    execution_mode: ToolExecutionMode
    command: str | None = None
    default_args: list[str] = field(default_factory=list)
    input_types: list[str] = field(default_factory=list)
    output_types: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    maps_to: list[str] = field(default_factory=list)
    risk: ToolRiskProfile = field(default_factory=ToolRiskProfile)
    notes: str | None = None


@dataclass
class ToolInput:
    target: Path | None = None
    output_dir: Path | None = None
    config: dict[str, Any] = field(default_factory=dict)
    import_file: Path | None = None
    allow_dynamic: bool = False
    allow_network: bool = False
    scope_file: Path | None = None
    timeout_seconds: int = 300


@dataclass
class ToolExecution:
    tool_id: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    artifacts: list[Path] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str | None = None


@dataclass
class ExternalFinding:
    tool_id: str
    rule_id: str | None
    title: str
    message: str | None = None
    severity: str | None = None
    confidence: str | None = None
    file: str | None = None
    line: int | None = None
    column: int | None = None
    end_line: int | None = None
    cwe: list[str] = field(default_factory=list)
    route: str | None = None
    evidence: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class AccessObservation:
    source_tool: str
    actor: str | None
    role: str | None
    method: str | None
    path: str | None
    object_type: str | None
    object_id_source: str | None
    action: str | None
    expected_guard: str | None
    detected_guards: list[str] = field(default_factory=list)
    missing_guards: list[str] = field(default_factory=list)
    mutation: bool = False
    response_exposes_object: bool = False
    confidence: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass
class RequestStep:
    method: str
    path: str
    produces: list[str] = field(default_factory=list)
    consumes: list[str] = field(default_factory=list)
    actor: str | None = None
    notes: str | None = None


@dataclass
class AttackPath:
    source_tool: str
    title: str
    steps: list[RequestStep]
    hypothesis: str
    evidence_needed: list[str] = field(default_factory=list)
    risk: str | None = None


@dataclass
class NormalizedToolResult:
    tool_id: str
    findings: list[ExternalFinding] = field(default_factory=list)
    access_observations: list[AccessObservation] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    artifacts: list[Path] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


def to_jsonable(value: Any) -> Any:
    """Return a deterministic JSON-friendly representation."""
    if isinstance(value, Path):
        return str(value)
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {str(k): to_jsonable(v) for k, v in sorted(value.items(), key=lambda item: str(item[0]))}
    if isinstance(value, (list, tuple)):
        return [to_jsonable(item) for item in value]
    return value


__all__ = [
    "AccessObservation",
    "AttackPath",
    "ExternalFinding",
    "NormalizedToolResult",
    "RequestStep",
    "ToolExecution",
    "ToolExecutionMode",
    "ToolInput",
    "ToolManifest",
    "ToolRiskProfile",
    "to_jsonable",
]
