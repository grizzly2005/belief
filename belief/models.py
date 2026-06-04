"""
BELIEF — Belief Extraction and Logical Inference for Exploitable Flaws

Core data models implementing the sextuplet formalization (P, S, C, D, E, L)
for representing implicit software beliefs.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

FINDING_SCHEMA_VERSION = "belief.finding.v1"
REPORT_SCHEMA_VERSION = "belief.report.v2"


# ─────────────────────────────────────────────
#  Enumerations
# ─────────────────────────────────────────────

class JustificationCategory(Enum):
    """Taxonomy of belief justification robustness (C1–C6, decreasing)."""

    C1_FORMAL_VERIFICATION = "C1"    # assert / static type / explicit check
    C2_CALLER_VERIFICATION = "C2"    # every known caller verifies
    C3_DOCUMENTED_CONVENTION = "C3"  # comment / docstring / docs
    C3_DOCUMENTED = "C3"             # backward-compatible alias
    C4_IMPLICIT_CONVENTION = "C4"    # domain standard, not written
    C5_NO_JUSTIFICATION = "C5"       # pure faith
    C6_OPAQUE_INFERENCE = "C6"       # inferred from opaque component

    @classmethod
    def parse(cls, value: object) -> "JustificationCategory":
        return _parse_enum_value(cls, value, cls.C5_NO_JUSTIFICATION)

    @property
    def robustness_score(self) -> float:
        """Numeric robustness (1.0 = strongest, 0.0 = weakest)."""
        scores = {
            "C1": 1.0, "C2": 0.8, "C3": 0.6,
            "C4": 0.4, "C5": 0.2, "C6": 0.1,
        }
        return scores[self.value]


class EpistemicStatus(Enum):
    """How the developer relates to the predicate."""

    BELIEF = "belief"    # developer assumes P is true
    HOPE = "hope"        # developer knows P is uncertain, codes as-if
    UNKNOWN = "unknown"  # cannot determine developer intent


class LogicType(Enum):
    """Determines which verifier handles the predicate."""

    FOL = "fol"                    # first-order logic → Z3
    SEMANTIC = "semantic"          # natural-language / semantic reasoning
    CONTRACT = "semantic"          # backward-compatible alias for semantic
    TEMPORAL = "temporal"          # LTL / CTL → Spin / omega
    INFORMATION_FLOW = "info_flow" # taint / non-interference → Joern
    BEHAVIORAL = "behavioral"     # functional properties → Hypothesis
    PROBABILISTIC = "probabilistic" # likelihood → LLM reasoning

    @classmethod
    def parse(cls, value: object) -> "LogicType":
        return _parse_enum_value(cls, value, cls.FOL)


class ConflictSeverity(Enum):
    """Severity of a detected belief conflict."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class DriftType(Enum):
    """Type of temporal belief drift."""

    PASSIVE = "passive"  # context changed, code unchanged
    ACTIVE = "active"    # code changed, beliefs not revalidated


class ArtifactKind(Enum):
    """Source artifact type for a belief."""

    SOURCE_CODE = "source_code"
    CONFIGURATION = "configuration"      # YAML, JSON, TOML config files
    INFRASTRUCTURE = "infrastructure"    # Dockerfile, K8s, Terraform
    CI_CD = "ci_cd"                      # pipeline definitions
    DOCUMENTATION = "documentation"      # README, API docs
    OPAQUE_API = "opaque_api"            # external API / closed-source lib


def _parse_enum_value(enum_cls: type[Enum], value: object, default: Enum) -> Enum:
    """Parse enum values from JSON using either enum value or member name."""
    if isinstance(value, enum_cls):
        return value
    if value is None:
        return default

    text = str(value).strip()
    if not text:
        return default

    try:
        return enum_cls(text)
    except ValueError:
        pass

    member = enum_cls.__members__.get(text) or enum_cls.__members__.get(text.upper())
    if member is not None:
        return member

    return default


def _json_safe(value: Any) -> Any:
    """Return a JSON-serializable copy, stringifying unknown objects."""
    try:
        return json.loads(json.dumps(value, default=str))
    except Exception:
        return str(value)


def _stable_digest(value: Any, length: int = 16) -> str:
    payload = json.dumps(_json_safe(value), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:length]


def _normalize_path(value: str | None) -> str:
    return (value or "").replace("\\", "/")


def _safe_int(value: object) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _safe_float(value: object, default: float = 0.5) -> float:
    if isinstance(value, str):
        mapped = {
            "critical": 0.95,
            "high": 0.85,
            "medium": 0.65,
            "low": 0.35,
            "info": 0.2,
            "unknown": default,
        }.get(value.strip().lower())
        if mapped is not None:
            return mapped
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return min(max(parsed, 0.0), 1.0)


def _scope_to_dict(scope: "Scope") -> dict:
    return {
        "file_path": scope.file_path,
        "function_name": scope.function_name,
        "class_name": scope.class_name,
        "module": scope.module,
        "line_start": scope.line_start,
        "line_end": scope.line_end,
        "introduced_commit": scope.introduced_commit,
        "last_validated_commit": scope.last_validated_commit,
    }


# ─────────────────────────────────────────────
#  Scope
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class Scope:
    """Spatial and temporal boundaries of a belief (S)."""

    file_path: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    module: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    introduced_commit: Optional[str] = None
    last_validated_commit: Optional[str] = None

    @property
    def qualified_name(self) -> str:
        parts = [self.module or self.file_path]
        if self.class_name:
            parts.append(self.class_name)
        if self.function_name:
            parts.append(self.function_name)
        return ".".join(parts)

    def overlaps(self, other: Scope) -> bool:
        """True if two scopes share any spatial overlap."""
        if self.file_path != other.file_path:
            return False
        if self.line_start and other.line_start and self.line_end and other.line_end:
            return not (self.line_end < other.line_start or other.line_end < self.line_start)
        # Same file, no line info → conservatively assume overlap
        return True


# ─────────────────────────────────────────────
#  Predicate
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class Predicate:
    """A logical assertion about program state (P)."""

    expression: str            # semi-formal: "input.length <= buffer.capacity"
    variables: tuple[str, ...] = ()  # referenced identifiers
    anchor_lines: tuple[int, ...] = ()  # lines in source that evidence this predicate
    natural_language: str = ""  # human-readable explanation

    def negation(self) -> str:
        """Return the logical negation of this predicate.

        v4 hotfix #3 (critique #43 part 2): apply flips to ALL occurrences
        (was applying to first only via .replace() which is fine by default
        but we wrap composed cases explicitly). For predicates that use
        and/or, use explicit De Morgan wrap rather than partial flip.
        """
        expr = self.expression.strip()
        if expr.startswith("not ") or expr.startswith("NOT "):
            return expr[4:]
        # Compound: use explicit wrap to keep logical semantics correct.
        if " and " in expr.lower() or " or " in expr.lower():
            return f"not ({expr})"
        # Atomic: flip the operator (replace() already substitutes all occurrences).
        if " <= " in expr:
            return expr.replace(" <= ", " > ")
        if " >= " in expr:
            return expr.replace(" >= ", " < ")
        if " < " in expr:
            return expr.replace(" < ", " >= ")
        if " > " in expr:
            return expr.replace(" > ", " <= ")
        if " == " in expr:
            return expr.replace(" == ", " != ")
        if " != " in expr:
            return expr.replace(" != ", " == ")
        if " in " in expr:
            return expr.replace(" in ", " not in ")
        if " is None" in expr:
            return expr.replace(" is None", " is not None")
        if " is not None" in expr:
            return expr.replace(" is not None", " is None")
        return f"not ({expr})"


# ─────────────────────────────────────────────
#  Belief (the sextuplet)
# ─────────────────────────────────────────────

@dataclass
class Belief:
    """
    The atomic unit of BELIEF analysis — a sextuplet (P, S, C, D, E, L).

    Represents a single implicit belief held by a software component.
    """

    predicate: Predicate                           # P
    scope: Scope                                   # S
    justification: JustificationCategory           # C
    dependencies: list[str] = field(default_factory=list)  # D — IDs of beliefs this depends on
    epistemic_status: EpistemicStatus = EpistemicStatus.BELIEF  # E
    logic_type: LogicType = LogicType.FOL           # L
    artifact_kind: ArtifactKind = ArtifactKind.SOURCE_CODE
    confidence_score: float = 0.5                   # LLM extraction confidence
    id: str = ""
    canonical_key: str = ""  # v4: stable key across LLM/bridge text drift
    cwe: str = ""            # v4: explicit CWE (set by bridges; guessed for LLM)
    source_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        # canonical_key: stable across text variations of the same belief.
        # Uses (cwe or guessed, file, function, line_bucket) — NOT the LLM text.
        if not self.canonical_key:
            line_bucket = 0
            if self.scope.line_start:
                # Bucket lines by 5 so minor formatting shifts don't break matching
                line_bucket = self.scope.line_start // 5
            cwe_part = self.cwe or "UNKNOWN"
            file_part = (self.scope.file_path or "").replace("\\", "/")
            raw_ck = (
                f"{cwe_part}:"
                f"{file_part}:"
                f"{self.scope.function_name or ''}:"
                f"{line_bucket}"
            )
            self.canonical_key = hashlib.sha256(raw_ck.encode()).hexdigest()[:16]
        if not self.id:
            if self.cwe:
                raw = f"stable:{self.canonical_key}"
            else:
                raw = f"{self.predicate.expression}:{self.scope.qualified_name}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]

    @property
    def fragility(self) -> float:
        """Combined fragility score (0 = solid, 1 = extremely fragile)."""
        justification_weight = 1.0 - self.justification.robustness_score
        epistemic_weight = {
            EpistemicStatus.BELIEF: 0.3,
            EpistemicStatus.HOPE: 0.7,
            EpistemicStatus.UNKNOWN: 0.9,
        }[self.epistemic_status]
        confidence_weight = 1.0 - self.confidence_score
        return (justification_weight * 0.4
                + epistemic_weight * 0.3
                + confidence_weight * 0.3)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "predicate": {
                "expression": self.predicate.expression,
                "variables": list(self.predicate.variables),
                "anchor_lines": list(self.predicate.anchor_lines),
                "natural_language": self.predicate.natural_language,
            },
            "scope": _scope_to_dict(self.scope),
            "justification": self.justification.value,
            "dependencies": self.dependencies,
            "epistemic_status": self.epistemic_status.value,
            "logic_type": self.logic_type.value,
            "artifact_kind": self.artifact_kind.value,
            "confidence_score": self.confidence_score,
            "canonical_key": self.canonical_key,
            "cwe": self.cwe,
            "source_metadata": _json_safe(self.source_metadata),
            "fragility": round(self.fragility, 3),
        }

    @classmethod
    def from_dict(cls, data: dict) -> Belief:
        # Safe enum parsing with fallbacks. JSON may carry either enum values
        # ("C3", "semantic") or historical member names ("C3_DOCUMENTED").
        justification = JustificationCategory.parse(data.get("justification", "C5"))
        epistemic = _parse_enum_value(
            EpistemicStatus, data.get("epistemic_status", "belief"),
            EpistemicStatus.BELIEF,
        )
        logic = LogicType.parse(data.get("logic_type", "fol"))
        artifact = _parse_enum_value(
            ArtifactKind, data.get("artifact_kind", "source_code"),
            ArtifactKind.SOURCE_CODE,
        )

        pred_data = data.get("predicate", {})
        scope_data = data.get("scope", {})

        return cls(
            predicate=Predicate(
                expression=pred_data.get("expression", ""),
                variables=tuple(pred_data.get("variables", [])),
                anchor_lines=tuple(pred_data.get("anchor_lines", [])),
                natural_language=pred_data.get("natural_language", ""),
            ),
            scope=Scope(
                file_path=scope_data.get("file_path", "unknown"),
                function_name=scope_data.get("function_name"),
                class_name=scope_data.get("class_name"),
                module=scope_data.get("module"),
                line_start=scope_data.get("line_start"),
                line_end=scope_data.get("line_end"),
                introduced_commit=scope_data.get("introduced_commit"),
                last_validated_commit=scope_data.get("last_validated_commit"),
            ),
            justification=justification,
            dependencies=data.get("dependencies", []),
            epistemic_status=epistemic,
            logic_type=logic,
            artifact_kind=artifact,
            confidence_score=data.get("confidence_score", 0.5),
            id=data.get("id", ""),
            canonical_key=data.get("canonical_key", ""),
            cwe=data.get("cwe", ""),
            source_metadata=data.get("source_metadata") or data.get("metadata") or {},
        )


# ─────────────────────────────────────────────
#  Finding (stable security/reporting result)
# ─────────────────────────────────────────────

@dataclass
class Finding:
    """Stable, tool-neutral finding used by JSON reports and bridges."""

    id: str = ""
    source: str = "belief"
    rule_id: str = ""
    title: str = ""
    description: str = ""
    file: str = ""
    line: int | None = None
    end_line: int | None = None
    cwe: str = ""
    severity: str = "info"
    confidence: float = 0.5
    evidence: str = ""
    fingerprint: str = ""
    dedup_key: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.source = str(self.source or "belief")
        self.rule_id = str(self.rule_id or "")
        self.title = str(self.title or self.description or self.rule_id or "Finding")
        self.description = str(self.description or self.title)
        self.file = _normalize_path(str(self.file or ""))
        self.line = _safe_int(self.line)
        self.end_line = _safe_int(self.end_line)
        self.cwe = str(self.cwe or "")
        self.severity = str(self.severity or "info").strip().lower()
        self.confidence = _safe_float(self.confidence)
        self.evidence = str(self.evidence or "")
        if not isinstance(self.metadata, dict):
            self.metadata = {"value": _json_safe(self.metadata)}

        if not self.dedup_key:
            self.dedup_key = _stable_digest({
                "source": self.source,
                "rule_id": self.rule_id,
                "cwe": self.cwe,
                "file": self.file,
                "line": self.line,
                "end_line": self.end_line,
                "canonical_key": self.metadata.get("canonical_key", ""),
            })
        if not self.fingerprint:
            self.fingerprint = _stable_digest({
                "source": self.source,
                "rule_id": self.rule_id,
                "cwe": self.cwe,
                "file": self.file,
                "line": self.line,
                "end_line": self.end_line,
                "title": self.title,
                "evidence": self.evidence,
            })
        if not self.id:
            self.id = self.fingerprint

    @classmethod
    def from_belief(cls, belief: Belief, source: str = "belief") -> "Finding":
        metadata = dict(getattr(belief, "source_metadata", {}) or {})
        metadata.update({
            "belief_id": belief.id,
            "canonical_key": belief.canonical_key,
            "logic_type": belief.logic_type.value,
            "justification": belief.justification.value,
            "epistemic_status": belief.epistemic_status.value,
        })
        text = belief.predicate.natural_language or belief.predicate.expression
        return cls(
            source=str(metadata.get("source") or source),
            rule_id=str(metadata.get("rule_id") or metadata.get("test_id") or ""),
            title=str(metadata.get("title") or belief.predicate.expression or "Belief finding"),
            description=text,
            file=belief.scope.file_path,
            line=belief.scope.line_start,
            end_line=belief.scope.line_end,
            cwe=belief.cwe or str(metadata.get("cwe") or ""),
            severity=str(metadata.get("severity") or _severity_from_confidence(belief.confidence_score)),
            confidence=belief.confidence_score,
            evidence=text,
            dedup_key=belief.canonical_key,
            metadata=metadata,
        )

    @classmethod
    def from_dict(cls, data: dict) -> "Finding":
        if not isinstance(data, dict):
            return cls(description=str(data))

        metadata = data.get("metadata") or data.get("source_metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {"value": metadata}
        source = data.get("source") or metadata.get("source") or "unknown"
        rule_id = (
            data.get("rule_id")
            or data.get("test_id")
            or data.get("check_id")
            or data.get("code")
            or metadata.get("rule_id")
            or metadata.get("test_id")
            or ""
        )
        description = (
            data.get("description")
            or data.get("issue_text")
            or data.get("message")
            or data.get("natural_language")
            or data.get("title")
            or ""
        )
        return cls(
            id=str(data.get("id") or ""),
            source=str(source),
            rule_id=str(rule_id),
            title=str(data.get("title") or data.get("message") or rule_id or description or "Finding"),
            description=str(description),
            file=str(data.get("file") or data.get("path") or data.get("filename") or data.get("anchor_file") or ""),
            line=_safe_int(data.get("line") or data.get("line_start") or data.get("lineno") or data.get("anchor_line")),
            end_line=_safe_int(data.get("end_line") or data.get("line_end") or data.get("anchor_line_end")),
            cwe=str(data.get("cwe") or metadata.get("cwe") or ""),
            severity=str(data.get("severity") or metadata.get("severity") or "info"),
            confidence=_safe_float(data.get("confidence", data.get("confidence_score", metadata.get("confidence", 0.5)))),
            evidence=str(data.get("evidence") or data.get("code") or data.get("snippet") or description or ""),
            fingerprint=str(data.get("fingerprint") or ""),
            dedup_key=str(data.get("dedup_key") or data.get("canonical_key") or metadata.get("canonical_key") or ""),
            metadata=metadata,
        )

    def to_dict(self) -> dict:
        return {
            "schema_version": FINDING_SCHEMA_VERSION,
            "id": self.id,
            "source": self.source,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "file": self.file,
            "line": self.line,
            "end_line": self.end_line,
            "cwe": self.cwe,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
            "dedup_key": self.dedup_key,
            "metadata": _json_safe(self.metadata),
            "canonical_key": self.metadata.get("canonical_key", self.dedup_key),
            "source_metadata": _json_safe(self.metadata),
        }


def _severity_from_confidence(confidence: float) -> str:
    if confidence >= 0.9:
        return "critical"
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.6:
        return "medium"
    if confidence >= 0.3:
        return "low"
    return "info"


# ─────────────────────────────────────────────
#  Trust Profile (inspired by Claude Code Tool.ts)
# ─────────────────────────────────────────────

@dataclass
class TrustProfile:
    """
    Rich trust characterization of a frontier boundary.

    Inspired by Claude Code's Tool.ts permission model:
    - isReadOnly → whether the callee only reads or also writes
    - needsPermission → whether the operation requires explicit authorization
    - validateInput → whether inputs are validated before use
    - hasTimeout → whether the operation has bounded execution time
    - hasSandbox → whether execution is isolated
    """

    is_read_only: bool = False       # callee only reads, never writes/mutates
    needs_permission: bool = False   # operation requires explicit auth/approval
    validates_input: bool = False    # callee validates inputs before use
    has_timeout: bool = False        # operation has bounded execution time
    has_sandbox: bool = False        # execution is isolated from host
    crosses_network: bool = False    # data crosses a network boundary
    crosses_process: bool = False    # data crosses a process boundary
    handles_untrusted: bool = False  # caller handles data from untrusted source
    error_handling: str = "none"     # none | partial | comprehensive

    @property
    def risk_score(self) -> float:
        """Aggregate risk score (0 = safe, 1 = high risk)."""
        score = 0.0
        if not self.is_read_only:
            score += 0.15
        if not self.validates_input:
            score += 0.2
        if not self.has_timeout:
            score += 0.1
        if not self.has_sandbox:
            score += 0.15
        if self.crosses_network:
            score += 0.15
        if self.handles_untrusted:
            score += 0.15
        if self.error_handling == "none":
            score += 0.1
        return min(score, 1.0)


# ─────────────────────────────────────────────
#  Frontier
# ─────────────────────────────────────────────

@dataclass
class Frontier:
    """A boundary between two components where beliefs may conflict."""

    caller_scope: Scope
    callee_scope: Scope
    call_site_line: Optional[int] = None
    trust_asymmetry: float = 0.0  # 0 = symmetric, 1 = maximum asymmetry
    trust_profile: Optional[TrustProfile] = None
    description: str = ""
    id: str = ""

    def __post_init__(self):
        if not self.id:
            raw = f"{self.caller_scope.qualified_name}->{self.callee_scope.qualified_name}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]


# ─────────────────────────────────────────────
#  Conflict
# ─────────────────────────────────────────────

@dataclass
class Conflict:
    """A detected contradiction between two beliefs."""

    belief_a: Belief
    belief_b: Belief
    frontier: Optional[Frontier] = None
    severity: ConflictSeverity = ConflictSeverity.MEDIUM
    is_transitive: bool = False
    transitive_path: list[str] = field(default_factory=list)  # belief IDs
    description: str = ""
    exploitable: Optional[bool] = None
    possible_world: Optional[str] = None  # Z3 model as string
    verified_by: str = ""  # which verifier confirmed

    def to_dict(self) -> dict:
        return {
            "belief_a_id": self.belief_a.id,
            "belief_b_id": self.belief_b.id,
            "frontier_id": self.frontier.id if self.frontier else None,
            "severity": self.severity.value,
            "is_transitive": self.is_transitive,
            "transitive_path": self.transitive_path,
            "description": self.description,
            "exploitable": self.exploitable,
            "possible_world": self.possible_world,
            "verified_by": self.verified_by,
        }


# ─────────────────────────────────────────────
#  Drift Event
# ─────────────────────────────────────────────

@dataclass
class DriftEvent:
    """A detected temporal drift in a belief."""

    belief: Belief
    drift_type: DriftType
    commit_hash: str = ""
    commit_message: str = ""
    commit_date: str = ""
    old_scope_description: str = ""
    new_scope_description: str = ""
    risk_assessment: str = ""

    def to_dict(self) -> dict:
        return {
            "belief_id": self.belief.id,
            "drift_type": self.drift_type.value,
            "commit_hash": self.commit_hash,
            "commit_message": self.commit_message,
            "commit_date": self.commit_date,
            "old_scope": self.old_scope_description,
            "new_scope": self.new_scope_description,
            "risk_assessment": self.risk_assessment,
        }


# ─────────────────────────────────────────────
#  Analysis Report
# ─────────────────────────────────────────────

@dataclass
class AnalysisReport:
    """Complete BELIEF analysis results for a codebase."""

    project_name: str
    beliefs: list[Belief] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    frontiers: list[Frontier] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    drift_events: list[DriftEvent] = field(default_factory=list)
    incomprehensible_zones: list[Scope] = field(default_factory=list)
    bridge_summary: dict[str, Any] = field(default_factory=dict)
    source_metadata: dict[str, Any] = field(default_factory=dict)
    run_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def epistemic_health(self) -> dict:
        """Distribution of justification categories across all beliefs."""
        dist = {c.value: 0 for c in JustificationCategory}
        for b in self.beliefs:
            dist[b.justification.value] += 1
        total = len(self.beliefs) or 1
        return {k: {"count": v, "percent": round(v / total * 100, 1)} for k, v in dist.items()}

    @property
    def cognitive_debt(self) -> float:
        """Fraction of beliefs with weak justification (C4–C6)."""
        if not self.beliefs:
            return 0.0
        weak = sum(1 for b in self.beliefs if b.justification.robustness_score <= 0.4)
        return round(weak / len(self.beliefs), 3)

    @property
    def mean_fragility(self) -> float:
        if not self.beliefs:
            return 0.0
        return round(sum(b.fragility for b in self.beliefs) / len(self.beliefs), 3)

    def to_dict(self) -> dict:
        beliefs = sorted(self.beliefs, key=_belief_sort_key)
        report_findings = self.findings or [
            Finding.from_belief(b)
            for b in self.beliefs
            if getattr(b, "cwe", "") or getattr(b, "source_metadata", {})
        ]
        findings = sorted(report_findings, key=_finding_sort_key)
        frontiers = sorted(self.frontiers, key=_frontier_sort_key)
        conflicts = sorted(self.conflicts, key=_conflict_sort_key)
        drift_events = sorted(self.drift_events, key=_drift_sort_key)
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "project_name": self.project_name,
            "summary": {
                "total_beliefs": len(self.beliefs),
                "total_findings": len(report_findings),
                "total_frontiers": len(self.frontiers),
                "total_conflicts": len(self.conflicts),
                "total_drift_events": len(self.drift_events),
                "incomprehensible_zones": len(self.incomprehensible_zones),
                "cognitive_debt": self.cognitive_debt,
                "mean_fragility": self.mean_fragility,
                "epistemic_health": self.epistemic_health,
            },
            "beliefs": [b.to_dict() for b in beliefs],
            "findings": [f.to_dict() for f in findings],
            "frontiers": [
                {
                    "id": f.id,
                    "caller": f.caller_scope.qualified_name,
                    "callee": f.callee_scope.qualified_name,
                    "caller_scope": _scope_to_dict(f.caller_scope),
                    "callee_scope": _scope_to_dict(f.callee_scope),
                    "call_site_line": f.call_site_line,
                    "trust_asymmetry": f.trust_asymmetry,
                    "description": f.description,
                }
                for f in frontiers
            ],
            "conflicts": [c.to_dict() for c in conflicts],
            "drift_events": [d.to_dict() for d in drift_events],
            "bridge_summary": _json_safe(self.bridge_summary),
            "source_metadata": _json_safe(self.source_metadata),
            "run_metadata": _json_safe(self.run_metadata),
        }

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, sort_keys=True)

    @classmethod
    def load(cls, path: str) -> AnalysisReport:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        report = cls(project_name=data.get("project_name", "unknown"))
        report.bridge_summary = data.get("bridge_summary", {}) or {}
        report.source_metadata = data.get("source_metadata", {}) or {}
        report.run_metadata = data.get("run_metadata", {}) or {}

        # Restore beliefs (skip any that fail to parse)
        for raw_belief in data.get("beliefs", []):
            try:
                if not isinstance(raw_belief, dict):
                    continue
                report.beliefs.append(Belief.from_dict(raw_belief))
            except Exception:
                continue

        for raw_finding in data.get("findings", []):
            try:
                if isinstance(raw_finding, dict):
                    report.findings.append(Finding.from_dict(raw_finding))
            except Exception:
                continue

        # Restore frontiers as lightweight objects
        belief_map = {b.id: b for b in report.beliefs}
        for raw_frontier in data.get("frontiers", []):
            try:
                caller_scope_data = raw_frontier.get("caller_scope") or {}
                callee_scope_data = raw_frontier.get("callee_scope") or {}
                caller_name = raw_frontier.get("caller", "")
                callee_name = raw_frontier.get("callee", "")
                frontier = Frontier(
                    caller_scope=Scope(
                        file_path=caller_scope_data.get("file_path", ""),
                        function_name=caller_scope_data.get("function_name"),
                        class_name=caller_scope_data.get("class_name"),
                        module=caller_scope_data.get("module", caller_name),
                        line_start=caller_scope_data.get("line_start"),
                        line_end=caller_scope_data.get("line_end"),
                        introduced_commit=caller_scope_data.get("introduced_commit"),
                        last_validated_commit=caller_scope_data.get("last_validated_commit"),
                    ),
                    callee_scope=Scope(
                        file_path=callee_scope_data.get("file_path", ""),
                        function_name=callee_scope_data.get("function_name"),
                        class_name=callee_scope_data.get("class_name"),
                        module=callee_scope_data.get("module", callee_name),
                        line_start=callee_scope_data.get("line_start"),
                        line_end=callee_scope_data.get("line_end"),
                        introduced_commit=callee_scope_data.get("introduced_commit"),
                        last_validated_commit=callee_scope_data.get("last_validated_commit"),
                    ),
                    call_site_line=raw_frontier.get("call_site_line"),
                    trust_asymmetry=raw_frontier.get("trust_asymmetry", 0.0),
                    description=raw_frontier.get("description", ""),
                    id=raw_frontier.get("id", ""),
                )
                report.frontiers.append(frontier)
            except (KeyError, TypeError):
                continue

        # Restore conflicts as lightweight objects
        for raw_conflict in data.get("conflicts", []):
            try:
                ba = belief_map.get(raw_conflict.get("belief_a_id"))
                bb = belief_map.get(raw_conflict.get("belief_b_id"))
                if not ba or not bb:
                    continue
                severity_str = raw_conflict.get("severity", "medium")
                try:
                    severity = ConflictSeverity(severity_str)
                except ValueError:
                    severity = ConflictSeverity.MEDIUM
                conflict = Conflict(
                    belief_a=ba,
                    belief_b=bb,
                    severity=severity,
                    is_transitive=raw_conflict.get("is_transitive", False),
                    transitive_path=raw_conflict.get("transitive_path", []),
                    description=raw_conflict.get("description", ""),
                    verified_by=raw_conflict.get("verified_by", ""),
                )
                report.conflicts.append(conflict)
            except (KeyError, TypeError):
                continue

        return report


def _belief_sort_key(belief: Belief) -> tuple:
    scope = belief.scope
    return (
        _normalize_path(scope.file_path),
        scope.line_start or 0,
        scope.line_end or 0,
        belief.cwe,
        belief.canonical_key,
        belief.id,
    )


def _finding_sort_key(finding: Finding) -> tuple:
    return (
        _normalize_path(finding.file),
        finding.line or 0,
        finding.end_line or 0,
        finding.cwe,
        finding.source,
        finding.rule_id,
        finding.dedup_key,
        finding.id,
    )


def _frontier_sort_key(frontier: Frontier) -> tuple:
    return (
        _normalize_path(frontier.caller_scope.file_path),
        frontier.caller_scope.line_start or 0,
        _normalize_path(frontier.callee_scope.file_path),
        frontier.callee_scope.line_start or 0,
        frontier.id,
    )


def _conflict_sort_key(conflict: Conflict) -> tuple:
    return (
        conflict.severity.value,
        conflict.belief_a.id,
        conflict.belief_b.id,
        conflict.frontier.id if conflict.frontier else "",
    )


def _drift_sort_key(drift: DriftEvent) -> tuple:
    return (
        drift.belief.id,
        drift.drift_type.value,
        drift.commit_hash,
        drift.commit_date,
    )
