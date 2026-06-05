"""Stable JSON models for BELIEF's minimal PDX adapter."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from .redaction import redact_pdx_value


PDX_SCHEMA_VERSION = "belief.pdx.v1"
PDX_TOOL_ID = "pdx"
PDX_VECTOR_LABELS = (
    "severity",
    "confidence",
    "exploitability",
    "auth_relevance",
    "data_exposure",
    "injection_surface",
    "config_weakness",
    "crypto_weakness",
    "logic_flaw",
    "timing_anomaly",
    "version_risk",
    "chain_potential",
    "persistence",
    "noise_level",
    "novelty",
    "context_dependency",
)


@dataclass(frozen=True)
class PDXMeta:
    format_version: int = 1
    source_file_name: str = ""
    source_file_hash: str = ""
    target_fingerprint: str = ""
    protocol: str = ""
    port: int | None = None
    tech_stack: tuple[str, ...] = ()
    provenance_chain: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "format_version": self.format_version,
            "source_file_name": self.source_file_name,
            "source_file_hash": self.source_file_hash,
            "target_fingerprint": self.target_fingerprint,
            "protocol": self.protocol,
            "port": self.port,
            "tech_stack": list(self.tech_stack),
            "provenance_chain": list(self.provenance_chain),
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXMeta":
        data = _as_dict(payload)
        return cls(
            format_version=_safe_int(data.get("format_version"), default=1) or 1,
            source_file_name=str(data.get("source_file_name") or ""),
            source_file_hash=str(data.get("source_file_hash") or ""),
            target_fingerprint=str(data.get("target_fingerprint") or ""),
            protocol=str(data.get("protocol") or ""),
            port=_safe_int(data.get("port")),
            tech_stack=tuple(_strings(data.get("tech_stack"))),
            provenance_chain=tuple(_strings(data.get("provenance_chain"))),
            raw=_unknown_fields(data, {
                "format_version", "source_file_name", "source_file_hash",
                "target_fingerprint", "protocol", "port", "tech_stack",
                "provenance_chain",
            }),
        )


@dataclass(frozen=True)
class PDXDelta:
    id: str
    spec_ref: str = ""
    delta_type: str = "UNKNOWN"
    category: str = ""
    description: str = ""
    expected: Any = None
    observed: Any = None
    vector: dict[str, float] = field(default_factory=dict)
    file: str = ""
    line: int | None = None
    column: int | None = None
    route: str = ""
    evidence: tuple[str, ...] = ()
    cwe: tuple[str, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            object.__setattr__(self, "id", _stable_id("pdx_delta", self.to_key_payload()))
        object.__setattr__(self, "delta_type", str(self.delta_type or "UNKNOWN").upper())
        object.__setattr__(self, "vector", _normalize_vector(self.vector))
        object.__setattr__(self, "evidence", tuple(str(item) for item in self.evidence if str(item)))
        object.__setattr__(self, "cwe", tuple(str(item) for item in self.cwe if str(item)))

    def to_key_payload(self) -> dict[str, Any]:
        return {
            "spec_ref": self.spec_ref,
            "delta_type": self.delta_type,
            "description": self.description,
            "expected": redact_pdx_value(self.expected),
            "observed": redact_pdx_value(self.observed),
            "file": self.file,
            "line": self.line,
            "route": self.route,
        }

    def to_dict(self) -> dict[str, Any]:
        data = {
            "id": self.id,
            "spec_ref": self.spec_ref,
            "delta_type": self.delta_type,
            "category": self.category,
            "description": self.description,
            "expected": redact_pdx_value(self.expected),
            "observed": redact_pdx_value(self.observed),
            "vector": dict(sorted(self.vector.items())),
            "file": self.file,
            "line": self.line,
            "column": self.column,
            "route": self.route,
            "evidence": list(self.evidence),
            "cwe": list(self.cwe),
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXDelta":
        data = _as_dict(payload)
        return cls(
            id=str(data.get("id") or data.get("delta_id") or ""),
            spec_ref=str(data.get("spec_ref") or data.get("spec") or ""),
            delta_type=str(data.get("delta_type") or data.get("type_name") or data.get("type") or "UNKNOWN"),
            category=str(data.get("category") or ""),
            description=str(data.get("description") or ""),
            expected=data.get("expected"),
            observed=data.get("observed"),
            vector=_normalize_vector(data.get("vector")),
            file=str(data.get("file") or data.get("path") or ""),
            line=_safe_int(data.get("line")),
            column=_safe_int(data.get("column")),
            route=str(data.get("route") or data.get("url") or ""),
            evidence=tuple(_strings(data.get("evidence"))),
            cwe=tuple(_strings(data.get("cwe"))),
            raw=_unknown_fields(data, {
                "id", "delta_id", "spec_ref", "spec", "delta_type", "type_name", "type",
                "category", "description", "expected", "observed", "vector", "file",
                "path", "line", "column", "route", "url", "evidence", "cwe",
            }),
        )


@dataclass(frozen=True)
class PDXVerdict:
    delta_ref: str
    result: str = "UNCERTAIN"
    tested: bool = False
    human_validated: bool = False
    method: str = ""
    reason: str = ""
    conditions_stack: tuple[str, ...] = ()
    train_positive: bool = False
    train_negative: bool = False
    weight: float = 0.5
    corrections: tuple[str, ...] = ()
    human_agreement: float | None = None
    original_result: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "result", str(self.result or "UNCERTAIN").upper())
        object.__setattr__(self, "weight", _clamp_float(self.weight, default=0.5))
        object.__setattr__(self, "conditions_stack", tuple(str(item) for item in self.conditions_stack if str(item)))
        object.__setattr__(self, "corrections", tuple(str(item) for item in self.corrections if str(item)))

    def to_dict(self) -> dict[str, Any]:
        data = {
            "delta_ref": self.delta_ref,
            "result": self.result,
            "tested": bool(self.tested),
            "human_validated": bool(self.human_validated),
            "method": self.method,
            "reason": self.reason,
            "conditions_stack": list(self.conditions_stack),
            "train_positive": bool(self.train_positive),
            "train_negative": bool(self.train_negative),
            "weight": round(float(self.weight), 3),
            "corrections": list(self.corrections),
            "human_agreement": self.human_agreement,
            "original_result": self.original_result,
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXVerdict":
        data = _as_dict(payload)
        return cls(
            delta_ref=str(data.get("delta_ref") or data.get("delta_id") or ""),
            result=str(data.get("result") or "UNCERTAIN"),
            tested=bool(data.get("tested", False)),
            human_validated=bool(data.get("human_validated", False)),
            method=str(data.get("method") or ""),
            reason=str(data.get("reason") or ""),
            conditions_stack=tuple(_strings(data.get("conditions_stack"))),
            train_positive=bool(data.get("train_positive", False)),
            train_negative=bool(data.get("train_negative", False)),
            weight=_clamp_float(data.get("weight"), default=0.5),
            corrections=tuple(_strings(data.get("corrections"))),
            human_agreement=_optional_float(data.get("human_agreement")),
            original_result=str(data.get("original_result") or ""),
            raw=_unknown_fields(data, {
                "delta_ref", "delta_id", "result", "tested", "human_validated",
                "method", "reason", "conditions_stack", "train_positive",
                "train_negative", "weight", "corrections", "human_agreement",
                "original_result",
            }),
        )


@dataclass(frozen=True)
class PDXChain:
    chain_id: str
    delta_refs: tuple[str, ...] = ()
    combined_severity: float = 0.0
    combined_exploitability: float = 0.0
    description: str = ""
    fully_exploited: bool = False
    raw: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "delta_refs", tuple(str(item) for item in self.delta_refs if str(item)))
        if not self.chain_id:
            object.__setattr__(self, "chain_id", _stable_id("pdx_chain", list(self.delta_refs)))

    def to_dict(self) -> dict[str, Any]:
        data = {
            "chain_id": self.chain_id,
            "delta_refs": list(self.delta_refs),
            "combined_severity": round(float(self.combined_severity), 3),
            "combined_exploitability": round(float(self.combined_exploitability), 3),
            "description": self.description,
            "fully_exploited": bool(self.fully_exploited),
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXChain":
        data = _as_dict(payload)
        return cls(
            chain_id=str(data.get("chain_id") or ""),
            delta_refs=tuple(_strings(data.get("delta_refs"))),
            combined_severity=_clamp_float(data.get("combined_severity"), default=0.0),
            combined_exploitability=_clamp_float(data.get("combined_exploitability"), default=0.0),
            description=str(data.get("description") or ""),
            fully_exploited=bool(data.get("fully_exploited", False)),
            raw=_unknown_fields(data, {
                "chain_id", "delta_refs", "combined_severity",
                "combined_exploitability", "description", "fully_exploited",
            }),
        )


@dataclass(frozen=True)
class PDXConflict:
    delta_ref: str
    opus_vector: dict[str, float] = field(default_factory=dict)
    local_vector: dict[str, float] = field(default_factory=dict)
    divergence_score: float = 0.0
    resolution: str = "HUMAN_REQUIRED"
    opus_rationale: str = ""
    local_rationale: str = ""
    resolution_reason: str = ""
    resolution_correct: bool | None = None
    post_resolution_weight: float | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "delta_ref": self.delta_ref,
            "opus_vector": dict(sorted(self.opus_vector.items())),
            "local_vector": dict(sorted(self.local_vector.items())),
            "divergence_score": round(float(self.divergence_score), 3),
            "resolution": self.resolution,
            "opus_rationale": self.opus_rationale,
            "local_rationale": self.local_rationale,
            "resolution_reason": self.resolution_reason,
            "resolution_correct": self.resolution_correct,
            "post_resolution_weight": self.post_resolution_weight,
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXConflict":
        data = _as_dict(payload)
        return cls(
            delta_ref=str(data.get("delta_ref") or data.get("delta_id") or ""),
            opus_vector=_normalize_vector(data.get("opus_vector")),
            local_vector=_normalize_vector(data.get("local_vector")),
            divergence_score=_clamp_float(data.get("divergence_score"), default=0.0),
            resolution=str(data.get("resolution") or "HUMAN_REQUIRED"),
            opus_rationale=str(data.get("opus_rationale") or ""),
            local_rationale=str(data.get("local_rationale") or ""),
            resolution_reason=str(data.get("resolution_reason") or ""),
            resolution_correct=_optional_bool(data.get("resolution_correct")),
            post_resolution_weight=_optional_float(data.get("post_resolution_weight")),
            raw=_unknown_fields(data, {
                "delta_ref", "delta_id", "opus_vector", "local_vector",
                "divergence_score", "resolution", "opus_rationale",
                "local_rationale", "resolution_reason", "resolution_correct",
                "post_resolution_weight",
            }),
        )


@dataclass(frozen=True)
class PDXTrainEntry:
    is_positive: bool = False
    weight: float = 0.5
    observation: str = ""
    action: str = ""
    reason: str = ""
    delta_vector: dict[str, float] = field(default_factory=dict)
    chain: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "is_positive": bool(self.is_positive),
            "weight": round(float(self.weight), 3),
            "observation": self.observation,
            "action": self.action,
            "reason": self.reason,
            "delta_vector": dict(sorted(self.delta_vector.items())),
            "chain": self.chain,
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXTrainEntry":
        data = _as_dict(payload)
        return cls(
            is_positive=bool(data.get("is_positive", False)),
            weight=_clamp_float(data.get("weight"), default=0.5),
            observation=str(data.get("observation") or ""),
            action=str(data.get("action") or ""),
            reason=str(data.get("reason") or ""),
            delta_vector=_normalize_vector(data.get("delta_vector")),
            chain=str(data.get("chain") or ""),
            raw=_unknown_fields(data, {
                "is_positive", "weight", "observation", "action",
                "reason", "delta_vector", "chain",
            }),
        )


@dataclass(frozen=True)
class PDXBundle:
    schema_version: str = PDX_SCHEMA_VERSION
    tool_id: str = PDX_TOOL_ID
    meta: PDXMeta = field(default_factory=PDXMeta)
    deltas: tuple[PDXDelta, ...] = ()
    verdicts: tuple[PDXVerdict, ...] = ()
    chains: tuple[PDXChain, ...] = ()
    conflicts: tuple[PDXConflict, ...] = ()
    train_entries: tuple[PDXTrainEntry, ...] = ()
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "tool_id": self.tool_id,
            "meta": self.meta.to_dict(),
            "deltas": [item.to_dict() for item in sorted(self.deltas, key=lambda item: item.id)],
            "verdicts": [item.to_dict() for item in sorted(self.verdicts, key=lambda item: (item.delta_ref, item.result, item.method))],
            "chains": [item.to_dict() for item in sorted(self.chains, key=lambda item: item.chain_id)],
            "conflicts": [item.to_dict() for item in sorted(self.conflicts, key=lambda item: (item.delta_ref, item.resolution))],
            "train_entries": [item.to_dict() for item in self.train_entries],
        }
        if self.raw:
            data["raw"] = redact_pdx_value(self.raw)
        return data

    @classmethod
    def from_dict(cls, payload: Any) -> "PDXBundle":
        data = _as_dict(payload)
        schema = str(data.get("schema_version") or PDX_SCHEMA_VERSION)
        if schema != PDX_SCHEMA_VERSION:
            raise ValueError(f"unsupported PDX bundle schema: {schema!r}")
        return cls(
            schema_version=schema,
            tool_id=str(data.get("tool_id") or PDX_TOOL_ID),
            meta=PDXMeta.from_dict(data.get("meta") or {}),
            deltas=tuple(PDXDelta.from_dict(item) for item in _as_list(data.get("deltas"))),
            verdicts=tuple(PDXVerdict.from_dict(item) for item in _as_list(data.get("verdicts"))),
            chains=tuple(PDXChain.from_dict(item) for item in _as_list(data.get("chains"))),
            conflicts=tuple(PDXConflict.from_dict(item) for item in _as_list(data.get("conflicts"))),
            train_entries=tuple(PDXTrainEntry.from_dict(item) for item in _as_list(data.get("train_entries"))),
            raw=_unknown_fields(data, {
                "schema_version", "tool_id", "meta", "deltas", "verdicts",
                "chains", "conflicts", "train_entries",
            }),
        )


def _normalize_vector(value: Any) -> dict[str, float]:
    if isinstance(value, dict):
        dims = value.get("dims")
        if isinstance(dims, list):
            return _normalize_vector(dims)
        return {
            str(key): _clamp_float(raw, default=0.0)
            for key, raw in sorted(value.items(), key=lambda item: str(item[0]))
            if key != "dims"
        }
    if isinstance(value, list):
        return {
            PDX_VECTOR_LABELS[idx]: _clamp_float(raw, default=0.0)
            for idx, raw in enumerate(value[:len(PDX_VECTOR_LABELS)])
        }
    return {}


def _stable_id(prefix: str, value: Any) -> str:
    digest = hashlib.sha256(
        json.dumps(redact_pdx_value(value), sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return f"{prefix}_{digest}"


def _unknown_fields(data: dict[str, Any], known: set[str]) -> dict[str, Any]:
    return {key: redact_pdx_value(value) for key, value in sorted(data.items()) if key not in known}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else ([] if value in (None, "") else [value])


def _strings(value: Any) -> list[str]:
    return [str(item) for item in _as_list(value) if str(item)]


def _safe_int(value: Any, default: int | None = None) -> int | None:
    if value in (None, ""):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _clamp_float(value: Any, default: float = 0.5) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        parsed = default
    return min(max(parsed, 0.0), 1.0)


def _optional_float(value: Any) -> float | None:
    if value in (None, ""):
        return None
    return _clamp_float(value)


def _optional_bool(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    return bool(value)


__all__ = [
    "PDX_SCHEMA_VERSION",
    "PDX_TOOL_ID",
    "PDX_VECTOR_LABELS",
    "PDXBundle",
    "PDXChain",
    "PDXConflict",
    "PDXDelta",
    "PDXMeta",
    "PDXTrainEntry",
    "PDXVerdict",
]
