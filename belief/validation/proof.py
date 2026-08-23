"""Typed, fail-closed proof links for BELIEF validation results.

Serialized validation results are untrusted inputs.  In particular, legacy
``tested`` and ``human_validated`` booleans are claims, not authority.  A
caller may only promote a result by supplying a separate ``VerifiedProofIndex``
that was built from a trusted attempt/result/evidence ledger.

The index is deliberately not serializable into a validation result.  This
keeps a result payload from declaring its own proof verified.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from belief.json_contracts import StrictJSONError, strict_json_clone, strict_json_dumps

from .models import VALIDATION_OUTCOMES, ValidationResult


VALIDATION_PROOF_SCHEMA_VERSION = "belief.validation_proof.v1"
VALIDATION_PROOF_STATES = frozenset({"signal_only", "quarantined", "verified"})
EVIDENCE_KINDS = frozenset(
    {
        "request",
        "response",
        "observation",
        "oracle",
        "log",
        "artifact",
    }
)

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PROOF_FIELDS = frozenset(
    {
        "schema_version",
        "proof_id",
        "engagement_id",
        "target_id",
        "subject_id",
        "subject_kind",
        "plan_id",
        "attempt_id",
        "result_id",
        "outcome",
        "oracle_id",
        "oracle_version",
        "evidence_refs",
    }
)
_EVIDENCE_REF_FIELDS = frozenset(
    {"evidence_id", "kind", "sha256", "media_type"}
)


class ValidationProofError(ValueError):
    """Raised when a proof link or trusted ledger binding is invalid."""


ProofState = Literal["signal_only", "quarantined", "verified"]


@dataclass(frozen=True)
class ValidationEvidenceRef:
    """Content-addressed evidence referenced by one validation proof."""

    evidence_id: str
    kind: str
    sha256: str
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "evidence_id",
            _identifier(self.evidence_id, field_name="evidence_id"),
        )
        kind = str(self.kind or "").strip().lower()
        if kind not in EVIDENCE_KINDS:
            raise ValidationProofError(f"unsupported evidence kind: {kind!r}")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(
            self,
            "sha256",
            _sha256(self.sha256, field_name="evidence sha256"),
        )
        media_type = str(self.media_type or "").strip().lower()
        if not media_type or len(media_type) > 255 or any(
            ord(character) < 32 for character in media_type
        ):
            raise ValidationProofError("evidence media_type is invalid")
        object.__setattr__(self, "media_type", media_type)

    def to_dict(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "sha256": self.sha256,
            "media_type": self.media_type,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationEvidenceRef":
        data = _strict_object(
            payload,
            allowed=_EVIDENCE_REF_FIELDS,
            required={"evidence_id", "kind", "sha256", "media_type"},
            field_name="validation evidence reference",
        )
        return cls(
            evidence_id=_strict_string(data["evidence_id"], "evidence_id"),
            kind=_strict_string(data["kind"], "evidence kind"),
            sha256=_strict_string(data["sha256"], "evidence sha256"),
            media_type=_strict_string(data["media_type"], "evidence media_type"),
        )


@dataclass(frozen=True)
class ValidationProof:
    """Canonical link from a subject to a completed attempt and its evidence."""

    engagement_id: str
    target_id: str
    subject_id: str
    subject_kind: str
    plan_id: str
    attempt_id: str
    result_id: str
    outcome: str
    oracle_id: str
    oracle_version: str
    evidence_refs: tuple[ValidationEvidenceRef, ...]
    proof_id: str = ""
    schema_version: str = VALIDATION_PROOF_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != VALIDATION_PROOF_SCHEMA_VERSION:
            raise ValidationProofError(
                f"unsupported validation proof schema: {self.schema_version!r}"
            )
        for field_name in (
            "engagement_id",
            "target_id",
            "subject_id",
            "subject_kind",
            "plan_id",
            "attempt_id",
            "result_id",
            "oracle_id",
            "oracle_version",
        ):
            object.__setattr__(
                self,
                field_name,
                _identifier(getattr(self, field_name), field_name=field_name),
            )
        outcome = str(self.outcome or "").strip().lower()
        if outcome not in VALIDATION_OUTCOMES:
            raise ValidationProofError(
                f"unsupported validation proof outcome: {outcome!r}"
            )
        object.__setattr__(self, "outcome", outcome)

        refs = tuple(
            sorted(
                tuple(self.evidence_refs),
                key=lambda item: (item.evidence_id, item.kind, item.sha256),
            )
        )
        if not refs:
            raise ValidationProofError(
                "validation proof requires at least one evidence reference"
            )
        ids = [item.evidence_id for item in refs]
        if len(ids) != len(set(ids)):
            raise ValidationProofError(
                "validation proof contains duplicate evidence ids"
            )
        object.__setattr__(self, "evidence_refs", refs)

        expected = "vproof_" + _canonical_sha256(self._unsigned_payload())[:24]
        supplied = str(self.proof_id or "").strip()
        if supplied and supplied != expected:
            raise ValidationProofError(
                "validation proof id does not match its canonical content"
            )
        object.__setattr__(self, "proof_id", expected)

    def _unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "plan_id": self.plan_id,
            "attempt_id": self.attempt_id,
            "result_id": self.result_id,
            "outcome": self.outcome,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "evidence_refs": [item.to_dict() for item in self.evidence_refs],
        }

    def to_dict(self) -> dict[str, Any]:
        return {"proof_id": self.proof_id, **self._unsigned_payload()}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ValidationProof":
        data = _strict_object(
            payload,
            allowed=_PROOF_FIELDS,
            required=_PROOF_FIELDS,
            field_name="validation proof",
        )
        refs = data["evidence_refs"]
        if not isinstance(refs, list):
            raise ValidationProofError(
                "validation proof evidence_refs must be an array"
            )
        return cls(
            schema_version=_strict_string(data["schema_version"], "schema_version"),
            proof_id=_strict_string(data["proof_id"], "proof_id"),
            engagement_id=_strict_string(data["engagement_id"], "engagement_id"),
            target_id=_strict_string(data["target_id"], "target_id"),
            subject_id=_strict_string(data["subject_id"], "subject_id"),
            subject_kind=_strict_string(data["subject_kind"], "subject_kind"),
            plan_id=_strict_string(data["plan_id"], "plan_id"),
            attempt_id=_strict_string(data["attempt_id"], "attempt_id"),
            result_id=_strict_string(data["result_id"], "result_id"),
            outcome=_strict_string(data["outcome"], "outcome"),
            oracle_id=_strict_string(data["oracle_id"], "oracle_id"),
            oracle_version=_strict_string(data["oracle_version"], "oracle_version"),
            evidence_refs=tuple(
                ValidationEvidenceRef.from_dict(item)
                for item in refs
            ),
        )


@dataclass(frozen=True)
class VerifiedProofMaterial:
    """Trusted ledger material used to verify one serialized proof link.

    Construct this object only from the authority, attempt, result and evidence
    stores.  It intentionally repeats every binding so a proof cannot validate
    itself by supplying internally consistent forged fields.
    """

    proof: ValidationProof
    engagement_id: str
    target_id: str
    subject_id: str
    subject_kind: str
    plan_id: str
    attempt_id: str
    result_id: str
    outcome: str
    oracle_id: str
    oracle_version: str
    evidence_sha256: Mapping[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        expected = {
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "subject_id": self.subject_id,
            "subject_kind": self.subject_kind,
            "plan_id": self.plan_id,
            "attempt_id": self.attempt_id,
            "result_id": self.result_id,
            "outcome": str(self.outcome or "").strip().lower(),
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
        }
        mismatches = [
            field_name
            for field_name, value in expected.items()
            if getattr(self.proof, field_name) != value
        ]
        if mismatches:
            raise ValidationProofError(
                "validation proof ledger binding mismatch: "
                + ", ".join(sorted(mismatches))
            )

        supplied = {
            _identifier(key, field_name="evidence id"): _sha256(
                value,
                field_name=f"evidence digest for {key}",
            )
            for key, value in dict(self.evidence_sha256).items()
        }
        referenced = {
            item.evidence_id: item.sha256 for item in self.proof.evidence_refs
        }
        if set(supplied) != set(referenced):
            missing = sorted(set(referenced) - set(supplied))
            extra = sorted(set(supplied) - set(referenced))
            detail = []
            if missing:
                detail.append("missing=" + ",".join(missing))
            if extra:
                detail.append("orphan=" + ",".join(extra))
            raise ValidationProofError(
                "validation proof evidence set mismatch: " + "; ".join(detail)
            )
        mismatched_digests = sorted(
            evidence_id
            for evidence_id, digest in referenced.items()
            if supplied[evidence_id] != digest
        )
        if mismatched_digests:
            raise ValidationProofError(
                "validation proof evidence digest mismatch: "
                + ",".join(mismatched_digests)
            )


class VerifiedProofIndex:
    """In-memory projection of proof records verified against trusted stores."""

    def __init__(self, materials: Iterable[VerifiedProofMaterial] = ()) -> None:
        proofs: dict[str, ValidationProof] = {}
        for material in materials:
            material.validate()
            existing = proofs.get(material.proof.proof_id)
            if existing is not None and existing != material.proof:
                raise ValidationProofError(
                    "duplicate proof id has conflicting canonical content"
                )
            proofs[material.proof.proof_id] = material.proof
        self._proofs = proofs

    def resolve(
        self,
        proof: ValidationProof,
        *,
        engagement_id: str,
        target_id: str,
        subject_id: str,
        subject_kind: str,
        plan_id: str,
        result_id: str,
        outcome: str,
    ) -> tuple[bool, tuple[str, ...]]:
        stored = self._proofs.get(proof.proof_id)
        if stored is None:
            return False, ("validation_proof_orphaned",)
        if stored != proof:
            return False, ("validation_proof_content_mismatch",)
        expected = {
            "engagement_id": engagement_id,
            "target_id": target_id,
            "subject_id": subject_id,
            "subject_kind": subject_kind,
            "plan_id": plan_id,
            "result_id": result_id,
            "outcome": str(outcome or "").strip().lower(),
        }
        mismatches = tuple(
            f"validation_proof_{field_name}_mismatch"
            for field_name, value in expected.items()
            if getattr(stored, field_name) != value
        )
        return (not mismatches), mismatches


@dataclass(frozen=True)
class ProofAssessment:
    state: ProofState
    proof_id: str = ""
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProofAuthorityContext:
    """Trusted engagement/target scope supplied outside an audit-case payload."""

    engagement_id: str
    target_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "engagement_id",
            _identifier(self.engagement_id, field_name="engagement_id"),
        )
        object.__setattr__(
            self,
            "target_id",
            _identifier(self.target_id, field_name="target_id"),
        )


def assess_validation_result_proof(
    result: ValidationResult | Mapping[str, Any],
    *,
    proof_index: VerifiedProofIndex | None,
    engagement_id: str,
    target_id: str,
    subject_id: str,
    subject_kind: str,
    plan_id: str,
) -> ProofAssessment:
    """Classify a result without trusting any self-asserted verification flag."""

    try:
        payload = (
            result.to_dict()
            if isinstance(result, ValidationResult)
            else _json_object(result)
        )
    except (ValidationProofError, TypeError, ValueError):
        return ProofAssessment(
            "quarantined",
            reasons=("validation_result_not_finite_json",),
        )
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return ProofAssessment("signal_only", reasons=("validation_proof_missing",))
    raw_proof = metadata.get("validation_proof")
    if raw_proof is None:
        return ProofAssessment("signal_only", reasons=("validation_proof_missing",))
    if not isinstance(raw_proof, Mapping):
        return ProofAssessment(
            "quarantined",
            reasons=("validation_proof_not_an_object",),
        )
    try:
        proof = ValidationProof.from_dict(raw_proof)
    except (ValidationProofError, TypeError, ValueError) as exc:
        return ProofAssessment(
            "quarantined",
            reasons=(f"validation_proof_invalid:{exc}",),
        )

    structural_mismatches = tuple(
        reason
        for condition, reason in (
            (proof.result_id != str(payload.get("result_id") or ""), "validation_proof_result_id_mismatch"),
            (proof.subject_id != str(payload.get("subject_id") or ""), "validation_proof_subject_id_mismatch"),
            (proof.subject_kind != str(payload.get("subject_kind") or ""), "validation_proof_subject_kind_mismatch"),
            (proof.outcome != str(payload.get("outcome") or "").lower(), "validation_proof_outcome_mismatch"),
        )
        if condition
    )
    if structural_mismatches:
        return ProofAssessment(
            "quarantined",
            proof_id=proof.proof_id,
            reasons=structural_mismatches,
        )
    if proof_index is None:
        return ProofAssessment(
            "quarantined",
            proof_id=proof.proof_id,
            reasons=("validation_proof_unresolved",),
        )
    if not all((engagement_id, target_id, subject_id, subject_kind, plan_id)):
        return ProofAssessment(
            "quarantined",
            proof_id=proof.proof_id,
            reasons=("validation_proof_binding_context_missing",),
        )
    resolved, reasons = proof_index.resolve(
        proof,
        engagement_id=engagement_id,
        target_id=target_id,
        subject_id=subject_id,
        subject_kind=subject_kind,
        plan_id=plan_id,
        result_id=str(payload.get("result_id") or ""),
        outcome=str(payload.get("outcome") or ""),
    )
    if not resolved:
        return ProofAssessment(
            "quarantined",
            proof_id=proof.proof_id,
            reasons=reasons,
        )
    return ProofAssessment("verified", proof_id=proof.proof_id)


def _strict_object(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    required: set[str] | frozenset[str],
    field_name: str,
) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValidationProofError(f"{field_name} must be a JSON object")
    data = dict(value)
    unknown = sorted(set(data) - set(allowed))
    missing = sorted(set(required) - set(data))
    if unknown:
        raise ValidationProofError(
            f"{field_name} has unknown fields: {', '.join(unknown)}"
        )
    if missing:
        raise ValidationProofError(
            f"{field_name} is missing fields: {', '.join(missing)}"
        )
    return _json_object(data)


def _json_object(value: Mapping[str, Any]) -> dict[str, Any]:
    try:
        cloned = strict_json_clone(dict(value))
    except StrictJSONError as exc:
        raise ValidationProofError(f"validation proof is not finite JSON: {exc}") from exc
    if not isinstance(cloned, dict):
        raise ValidationProofError("validation proof must be a JSON object")
    return cloned


def _strict_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationProofError(f"{field_name} must be a string")
    return value


def _identifier(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip()
    if (
        not text
        or len(text) > 512
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
    ):
        raise ValidationProofError(f"{field_name} is invalid")
    return text


def _sha256(value: Any, *, field_name: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise ValidationProofError(f"{field_name} must be lowercase SHA-256")
    return text


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        strict_json_dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


__all__ = [
    "EVIDENCE_KINDS",
    "ProofAssessment",
    "ProofAuthorityContext",
    "ProofState",
    "VALIDATION_PROOF_SCHEMA_VERSION",
    "VALIDATION_PROOF_STATES",
    "ValidationEvidenceRef",
    "ValidationProof",
    "ValidationProofError",
    "VerifiedProofIndex",
    "VerifiedProofMaterial",
    "assess_validation_result_proof",
]
