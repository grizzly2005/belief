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
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Any, Literal

from belief.json_contracts import StrictJSONError, strict_json_clone, strict_json_dumps

from .models import VALIDATION_OUTCOMES, ValidationResult


VALIDATION_PROOF_SCHEMA_VERSION = "belief.validation_proof.v1"
VALIDATION_PROOF_STATES = frozenset({"signal_only", "unresolved", "quarantined", "verified"})
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
_EVIDENCE_REF_FIELDS = frozenset({"evidence_id", "kind", "sha256", "media_type"})


class ValidationProofError(ValueError):
    """Raised when a proof link or trusted ledger binding is invalid."""


ProofState = Literal["signal_only", "unresolved", "quarantined", "verified"]


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
        if (
            not media_type
            or len(media_type) > 255
            or any(ord(character) < 32 for character in media_type)
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
            raise ValidationProofError(f"unsupported validation proof outcome: {outcome!r}")
        object.__setattr__(self, "outcome", outcome)

        refs = tuple(
            sorted(
                tuple(self.evidence_refs),
                key=lambda item: (item.evidence_id, item.kind, item.sha256),
            )
        )
        if not refs:
            raise ValidationProofError("validation proof requires at least one evidence reference")
        ids = [item.evidence_id for item in refs]
        if len(ids) != len(set(ids)):
            raise ValidationProofError("validation proof contains duplicate evidence ids")
        object.__setattr__(self, "evidence_refs", refs)

        expected = "vproof_" + _canonical_sha256(self._unsigned_payload())[:24]
        supplied = str(self.proof_id or "").strip()
        if supplied and supplied != expected:
            raise ValidationProofError("validation proof id does not match its canonical content")
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
            raise ValidationProofError("validation proof evidence_refs must be an array")
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
            evidence_refs=tuple(ValidationEvidenceRef.from_dict(item) for item in refs),
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
    subject_sha256: str
    plan_sha256: str
    result_sha256: str
    evidence_bindings: Mapping[str, ValidationEvidenceRef]
    evidence_sha256: Mapping[str, str]
    evidence_sizes: Mapping[str, int]

    def __post_init__(self) -> None:
        for field_name in ("subject_sha256", "plan_sha256", "result_sha256"):
            object.__setattr__(
                self,
                field_name,
                _sha256(
                    getattr(self, field_name),
                    field_name=field_name.replace("_", " "),
                ),
            )
        object.__setattr__(
            self,
            "evidence_bindings",
            MappingProxyType(dict(self.evidence_bindings)),
        )
        object.__setattr__(
            self,
            "evidence_sha256",
            MappingProxyType(dict(self.evidence_sha256)),
        )
        object.__setattr__(
            self,
            "evidence_sizes",
            MappingProxyType(dict(self.evidence_sizes)),
        )

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
                "validation proof ledger binding mismatch: " + ", ".join(sorted(mismatches))
            )

        supplied = {
            _identifier(key, field_name="evidence id"): _sha256(
                value,
                field_name=f"evidence digest for {key}",
            )
            for key, value in dict(self.evidence_sha256).items()
        }
        referenced = {item.evidence_id: item.sha256 for item in self.proof.evidence_refs}
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
                "validation proof evidence digest mismatch: " + ",".join(mismatched_digests)
            )

        trusted_bindings: dict[str, ValidationEvidenceRef] = {}
        for evidence_id, reference in dict(self.evidence_bindings).items():
            normalized_id = _identifier(evidence_id, field_name="evidence id")
            if not isinstance(reference, ValidationEvidenceRef):
                raise ValidationProofError(
                    "trusted evidence binding must be a ValidationEvidenceRef"
                )
            if normalized_id != reference.evidence_id:
                raise ValidationProofError(
                    "trusted evidence binding key does not match evidence_id"
                )
            trusted_bindings[normalized_id] = reference
        serialized_bindings = {
            reference.evidence_id: reference for reference in self.proof.evidence_refs
        }
        if trusted_bindings != serialized_bindings:
            raise ValidationProofError("validation proof evidence metadata binding mismatch")
        trusted_sizes = dict(self.evidence_sizes)
        if set(trusted_sizes) != set(trusted_bindings) or any(
            not isinstance(size, int) or isinstance(size, bool) or size < 0
            for size in trusted_sizes.values()
        ):
            raise ValidationProofError("validation proof evidence size binding mismatch")


class VerifiedProofIndex:
    """In-memory projection of proof records verified against trusted stores."""

    __slots__ = ("_proofs", "_quarantined_proofs", "_sealed")

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("VerifiedProofIndex is immutable")
        object.__setattr__(self, name, value)

    def __delattr__(self, name: str) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("VerifiedProofIndex is immutable")
        object.__delattr__(self, name)

    def __init__(self, materials: Iterable[VerifiedProofMaterial] = ()) -> None:
        material_list = tuple(materials)
        seen_proofs: dict[str, VerifiedProofMaterial] = {}
        quarantined_proofs: dict[str, str] = {}
        result_digests_by_id: dict[str, set[str]] = {}

        for material in material_list:
            material.validate()
            existing = seen_proofs.get(material.proof.proof_id)
            if existing is not None and existing != material:
                raise ValidationProofError("duplicate proof id has conflicting canonical content")
            seen_proofs[material.proof.proof_id] = material
            result_digests_by_id.setdefault(material.result_id, set()).add(material.result_sha256)

        colliding_result_ids = {
            result_id for result_id, digests in result_digests_by_id.items() if len(digests) > 1
        }
        quarantined_result_evidence_ids = {
            f"validation-result:{result_id}" for result_id in colliding_result_ids
        }

        proofs: dict[str, VerifiedProofMaterial] = {}
        attempt_ids: dict[str, str] = {}
        result_digests: dict[str, str] = {}
        plan_digests: dict[str, str] = {}
        subject_digests: dict[tuple[str, str, str, str], str] = {}
        evidence_ids: dict[str, tuple[str, str, str, int]] = {}
        for material in material_list:
            _bind_global_identifier(
                attempt_ids,
                identifier=material.attempt_id,
                proof_id=material.proof.proof_id,
                field_name="attempt_id",
            )
            if material.result_id not in colliding_result_ids:
                _bind_global_digest(
                    result_digests,
                    identifier=material.result_id,
                    digest=material.result_sha256,
                    field_name="result_id",
                )
            _bind_global_digest(
                plan_digests,
                identifier=material.plan_id,
                digest=material.plan_sha256,
                field_name="plan_id",
            )
            subject_key = (
                material.engagement_id,
                material.target_id,
                material.subject_kind,
                material.subject_id,
            )
            previous_subject = subject_digests.get(subject_key)
            if previous_subject is not None and previous_subject != material.subject_sha256:
                raise ValidationProofError(
                    "subject identity has conflicting canonical digests: "
                    f"{material.engagement_id}:{material.target_id}:"
                    f"{material.subject_kind}:{material.subject_id}"
                )
            subject_digests[subject_key] = material.subject_sha256
            for reference in material.evidence_bindings.values():
                if reference.evidence_id in quarantined_result_evidence_ids:
                    expected_result_evidence_id = f"validation-result:{material.result_id}"
                    if (
                        material.result_id not in colliding_result_ids
                        or reference.evidence_id != expected_result_evidence_id
                    ):
                        raise ValidationProofError(
                            "quarantined result evidence id is reused by another material: "
                            + reference.evidence_id
                        )
                    if (
                        reference.kind != "artifact"
                        or reference.media_type
                        != "application/vnd.belief.validation-result.v1+json"
                        or reference.sha256 != material.result_sha256
                    ):
                        raise ValidationProofError(
                            "quarantined result evidence binding is not canonical: "
                            + reference.evidence_id
                        )
                    continue
                identity = (
                    reference.sha256,
                    reference.kind,
                    reference.media_type,
                    material.evidence_sizes[reference.evidence_id],
                )
                previous = evidence_ids.get(reference.evidence_id)
                if previous is not None and previous != identity:
                    raise ValidationProofError(
                        "evidence_id has conflicting global identity: " + reference.evidence_id
                    )
                evidence_ids[reference.evidence_id] = identity
        for material in material_list:
            if material.result_id in colliding_result_ids:
                quarantined_proofs[material.proof.proof_id] = "validation_proof_result_id_collision"
                continue
            proofs[material.proof.proof_id] = material
        self._proofs = MappingProxyType(proofs)
        self._quarantined_proofs = MappingProxyType(quarantined_proofs)
        self._sealed = True

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
        subject_sha256: str,
        plan_sha256: str,
        result_sha256: str,
    ) -> tuple[bool, tuple[str, ...]]:
        quarantine_reason = self._quarantined_proofs.get(proof.proof_id)
        if quarantine_reason is not None:
            return False, (quarantine_reason,)
        material = self._proofs.get(proof.proof_id)
        if material is None:
            return False, ("validation_proof_orphaned",)
        stored = material.proof
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
        digest_mismatches = tuple(
            reason
            for supplied, trusted, reason in (
                (
                    str(subject_sha256 or "").lower(),
                    material.subject_sha256,
                    "validation_proof_subject_sha256_mismatch",
                ),
                (
                    str(result_sha256 or "").lower(),
                    material.result_sha256,
                    "validation_proof_result_sha256_mismatch",
                ),
                (
                    str(plan_sha256 or "").lower(),
                    material.plan_sha256,
                    "validation_proof_plan_sha256_mismatch",
                ),
            )
            if supplied != trusted
        )
        reasons = (*mismatches, *digest_mismatches)
        return (not reasons), reasons


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
    subject_sha256: str,
) -> ProofAssessment:
    """Classify a result without trusting any self-asserted verification flag."""

    try:
        payload = result.to_dict() if isinstance(result, ValidationResult) else _json_object(result)
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
            (
                proof.result_id != str(payload.get("result_id") or ""),
                "validation_proof_result_id_mismatch",
            ),
            (
                proof.subject_id != str(payload.get("subject_id") or ""),
                "validation_proof_subject_id_mismatch",
            ),
            (
                proof.subject_kind != str(payload.get("subject_kind") or ""),
                "validation_proof_subject_kind_mismatch",
            ),
            (
                proof.outcome != str(payload.get("outcome") or "").lower(),
                "validation_proof_outcome_mismatch",
            ),
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
            "unresolved",
            proof_id=proof.proof_id,
            reasons=("validation_proof_unresolved",),
        )
    plan_sha256 = str(metadata.get("validation_plan_digest") or "").lower()
    if not all(
        (
            engagement_id,
            target_id,
            subject_id,
            subject_kind,
            plan_id,
            subject_sha256,
            plan_sha256,
        )
    ):
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
        subject_sha256=subject_sha256,
        plan_sha256=plan_sha256,
        result_sha256=validation_result_proof_digest(payload),
    )
    if not resolved:
        return ProofAssessment(
            "quarantined",
            proof_id=proof.proof_id,
            reasons=reasons,
        )
    return ProofAssessment("verified", proof_id=proof.proof_id)


def proof_subject_digest(subject: Any) -> str:
    """Digest a subject snapshot while excluding post-validation projections.

    Validation results and reportability are derived children of an audit case;
    including them would make a proof recursively depend on itself. External
    intelligence is context-only and may be refreshed independently, so it is
    excluded for the same reason. Every other subject field remains bound.
    """

    serializer = getattr(subject, "to_dict", None)
    source_metadata = getattr(subject, "metadata", None)
    if callable(serializer) and isinstance(source_metadata, Mapping):
        bound_metadata = dict(source_metadata)
        _remove_derived_proof_projections(bound_metadata)
        try:
            value = replace(subject, metadata=bound_metadata).to_dict()
        except TypeError:
            value = serializer()
    else:
        value = serializer() if callable(serializer) else subject
    if not isinstance(value, Mapping):
        raise ValidationProofError("proof subject must be a JSON object")
    payload = _json_object(value)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        bound_metadata = dict(metadata)
        _remove_derived_proof_projections(bound_metadata)
        if bound_metadata:
            payload["metadata"] = bound_metadata
        else:
            payload.pop("metadata", None)
    return _canonical_sha256(payload)


def _remove_derived_proof_projections(metadata: dict[str, Any]) -> None:
    for field_name in (
        "external_intelligence",
        "proofs",
        "reasoning",
        "reportability",
        "validation_results",
    ):
        metadata.pop(field_name, None)

    external_raw = metadata.get("external_raw")
    if not isinstance(external_raw, Mapping):
        return
    bound_external_raw = dict(external_raw)
    bound_external_raw.pop("proofs", None)
    bound_external_raw.pop("validation_results", None)
    pdx = bound_external_raw.get("pdx")
    if isinstance(pdx, Mapping):
        bound_pdx = dict(pdx)
        bound_pdx.pop("proofs", None)
        bound_pdx.pop("validation_results", None)
        if bound_pdx:
            bound_external_raw["pdx"] = bound_pdx
        else:
            bound_external_raw.pop("pdx", None)
    if bound_external_raw:
        metadata["external_raw"] = bound_external_raw
    else:
        metadata.pop("external_raw", None)


def validation_result_proof_digest(
    result: ValidationResult | Mapping[str, Any],
) -> str:
    """Digest the complete result claim, excluding only its embedded proof link."""

    payload = result.to_dict() if isinstance(result, ValidationResult) else _json_object(result)
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        unlinked = dict(metadata)
        unlinked.pop("validation_proof", None)
        if unlinked:
            payload["metadata"] = unlinked
        else:
            payload.pop("metadata", None)
    return _canonical_sha256(payload)


def _bind_global_identifier(
    identities: dict[str, str],
    *,
    identifier: str,
    proof_id: str,
    field_name: str,
) -> None:
    previous = identities.get(identifier)
    if previous is not None and previous != proof_id:
        raise ValidationProofError(
            f"{field_name} is bound to multiple validation proofs: {identifier}"
        )
    identities[identifier] = proof_id


def _bind_global_digest(
    identities: dict[str, str],
    *,
    identifier: str,
    digest: str,
    field_name: str,
) -> None:
    previous = identities.get(identifier)
    if previous is not None and previous != digest:
        raise ValidationProofError(f"{field_name} has conflicting canonical digests: {identifier}")
    identities[identifier] = digest


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
        raise ValidationProofError(f"{field_name} has unknown fields: {', '.join(unknown)}")
    if missing:
        raise ValidationProofError(f"{field_name} is missing fields: {', '.join(missing)}")
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
    "proof_subject_digest",
    "validation_result_proof_digest",
]
