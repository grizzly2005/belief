"""Fail-closed proof publication for explicitly authorized audit cases.

This module deliberately does not discover executors, import code from an
artifact, or expose a command/shell field.  A trusted host must inject one
already-bounded callback whose immutable identity is pinned by the authority
policy registered in the validation ledger.
"""

from __future__ import annotations

import hashlib
import math
import re
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from belief.audit_case import AuditCase
from belief.json_contracts import strict_json_dumps

from .models import ValidationResult
from .plan_models import ValidationPlan, canonical_digest
from .proof import (
    ProofAuthorityContext,
    ValidationEvidenceRef,
    proof_subject_digest,
    validation_result_proof_digest,
)


AUDIT_CASE_PROOF_POLICY_SCHEMA_VERSION = "belief.audit_case_proof_policy.v1"
AUDIT_CASE_EXECUTION_REQUEST_SCHEMA_VERSION = "belief.audit_case_execution_request.v1"
AUDIT_CASE_EXECUTION_RESPONSE_SCHEMA_VERSION = "belief.audit_case_execution_response.v1"
AUDIT_CASE_REQUEST_MEDIA_TYPE = (
    "application/vnd.belief.audit-case-execution-request.v1+json"
)
AUDIT_CASE_RESPONSE_MEDIA_TYPE = (
    "application/vnd.belief.audit-case-execution-response.v1+json"
)

_CONCLUSIVE_OUTCOMES = frozenset(
    {"bypassed", "validated_candidate", "enforced", "false_positive"}
)
_EVIDENCE_KINDS = frozenset({"observation", "oracle", "log", "artifact"})
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_REVISION_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class AuditCaseProofError(ValueError):
    """Raised when real-target proof material is not explicitly authorized."""


def _canonical_bytes(value: Any) -> bytes:
    return strict_json_dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _identifier(value: Any, field_name: str) -> str:
    normalized = str(value or "").strip()
    if _IDENTIFIER_RE.fullmatch(normalized) is None:
        raise AuditCaseProofError(f"{field_name} is not a canonical identifier")
    return normalized


def _sha256(value: Any, field_name: str) -> str:
    normalized = str(value or "").strip().lower()
    if _SHA256_RE.fullmatch(normalized) is None:
        raise AuditCaseProofError(f"{field_name} must be a SHA-256")
    return normalized


def _revision(value: Any) -> str:
    normalized = str(value or "").strip().lower()
    if _REVISION_RE.fullmatch(normalized) is None:
        raise AuditCaseProofError(
            "target_revision must be a full 40- or 64-character hexadecimal revision"
        )
    return normalized


def _text(value: Any, field_name: str, *, required: bool = True) -> str:
    normalized = " ".join(str(value or "").strip().split())
    if required and not normalized:
        raise AuditCaseProofError(f"{field_name} is required")
    if len(normalized) > 4096:
        raise AuditCaseProofError(f"{field_name} exceeds its size limit")
    return normalized


def _strict_object(
    payload: Mapping[str, Any],
    *,
    keys: frozenset[str],
    field_name: str,
) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or any(not isinstance(key, str) for key in payload):
        raise AuditCaseProofError(f"{field_name} must be a JSON object")
    if set(payload) != keys:
        raise AuditCaseProofError(f"{field_name} keys are not exact")
    return dict(payload)


def _canonical_case(case: AuditCase) -> AuditCase:
    if type(case) is not AuditCase:
        raise TypeError("audit-case proof requires an AuditCase")
    try:
        canonical = AuditCase.from_dict(case.to_dict())
    except (TypeError, ValueError) as exc:
        raise AuditCaseProofError("audit case is not canonical") from exc
    if canonical.to_dict() != case.to_dict():
        raise AuditCaseProofError("audit case round trip is not canonical")
    return canonical


def _canonical_plan(plan: ValidationPlan) -> ValidationPlan:
    if type(plan) is not ValidationPlan:
        raise TypeError("audit-case proof requires a ValidationPlan")
    try:
        canonical = ValidationPlan.from_dict(plan.to_dict())
    except (TypeError, ValueError) as exc:
        raise AuditCaseProofError("validation plan is not canonical") from exc
    if canonical.to_dict() != plan.to_dict():
        raise AuditCaseProofError("validation plan round trip is not canonical")
    return canonical


@dataclass(frozen=True)
class AuditCaseProofGrant:
    """One exact subject/plan pair authorized by a target policy."""

    subject_id: str
    subject_sha256: str
    plan_id: str
    plan_sha256: str
    case_type: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "subject_id", _identifier(self.subject_id, "subject_id"))
        object.__setattr__(
            self,
            "subject_sha256",
            _sha256(self.subject_sha256, "subject_sha256"),
        )
        object.__setattr__(self, "plan_id", _identifier(self.plan_id, "plan_id"))
        object.__setattr__(self, "plan_sha256", _sha256(self.plan_sha256, "plan_sha256"))
        object.__setattr__(self, "case_type", _identifier(self.case_type, "case_type"))

    @classmethod
    def for_case(cls, case: AuditCase, plan: ValidationPlan) -> "AuditCaseProofGrant":
        case = _canonical_case(case)
        plan = _canonical_plan(plan)
        _validate_case_plan(case, plan)
        return cls(
            subject_id=case.case_id,
            subject_sha256=proof_subject_digest(case),
            plan_id=plan.plan_id,
            plan_sha256=canonical_digest(plan.to_dict()),
            case_type=case.case_type,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "subject_id": self.subject_id,
            "subject_sha256": self.subject_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "case_type": self.case_type,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuditCaseProofGrant":
        data = _strict_object(
            payload,
            keys=frozenset(
                {"subject_id", "subject_sha256", "plan_id", "plan_sha256", "case_type"}
            ),
            field_name="audit-case proof grant",
        )
        return cls(**data)


@dataclass(frozen=True)
class AuditCaseProofPolicy:
    """Externally pinned authority for one immutable target revision."""

    authority_id: str
    authority_version: str
    engagement_id: str
    target_id: str
    target_revision: str
    target_sha256: str
    executor_id: str
    executor_version: str
    executor_sha256: str
    oracle_id: str
    oracle_version: str
    oracle_sha256: str
    grants: tuple[AuditCaseProofGrant, ...]
    allowed_outcomes: tuple[str, ...] = ("bypassed",)
    max_evidence_refs: int = 8
    max_total_evidence_bytes: int = 1024 * 1024
    policy_id: str = ""
    schema_version: str = AUDIT_CASE_PROOF_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_CASE_PROOF_POLICY_SCHEMA_VERSION:
            raise AuditCaseProofError("unsupported audit-case proof policy schema")
        for field_name in (
            "authority_id",
            "authority_version",
            "engagement_id",
            "target_id",
            "executor_id",
            "executor_version",
            "oracle_id",
            "oracle_version",
        ):
            object.__setattr__(self, field_name, _identifier(getattr(self, field_name), field_name))
        if self.target_id.startswith("registered-fixture:"):
            raise AuditCaseProofError("audit-case policy cannot authorize a registered fixture")
        object.__setattr__(self, "target_revision", _revision(self.target_revision))
        for field_name in ("target_sha256", "executor_sha256", "oracle_sha256"):
            object.__setattr__(self, field_name, _sha256(getattr(self, field_name), field_name))

        grants = tuple(self.grants)
        if not grants or any(type(item) is not AuditCaseProofGrant for item in grants):
            raise AuditCaseProofError("audit-case policy requires typed grants")
        grants = tuple(sorted(grants, key=lambda item: (item.subject_id, item.plan_id)))
        grant_keys = {(item.subject_id, item.plan_id) for item in grants}
        if len(grant_keys) != len(grants):
            raise AuditCaseProofError("audit-case policy contains duplicate grants")
        object.__setattr__(self, "grants", grants)

        outcomes = tuple(sorted({_text(item, "allowed outcome").lower() for item in self.allowed_outcomes}))
        if not outcomes or any(item not in _CONCLUSIVE_OUTCOMES for item in outcomes):
            raise AuditCaseProofError("audit-case policy allowed_outcomes are not conclusive")
        object.__setattr__(self, "allowed_outcomes", outcomes)
        if (
            not isinstance(self.max_evidence_refs, int)
            or isinstance(self.max_evidence_refs, bool)
            or not 1 <= self.max_evidence_refs <= 32
        ):
            raise AuditCaseProofError("audit-case policy max_evidence_refs is invalid")
        if (
            not isinstance(self.max_total_evidence_bytes, int)
            or isinstance(self.max_total_evidence_bytes, bool)
            or not 1 <= self.max_total_evidence_bytes <= 16 * 1024 * 1024
        ):
            raise AuditCaseProofError("audit-case policy evidence byte budget is invalid")

        expected = "acpolicy_" + self.policy_sha256[:24]
        supplied = str(self.policy_id or "").strip()
        if supplied and supplied != expected:
            raise AuditCaseProofError("audit-case policy id does not match its content digest")
        object.__setattr__(self, "policy_id", expected)

    def _unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority_id": self.authority_id,
            "authority_version": self.authority_version,
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "target_revision": self.target_revision,
            "target_sha256": self.target_sha256,
            "executor_id": self.executor_id,
            "executor_version": self.executor_version,
            "executor_sha256": self.executor_sha256,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "oracle_sha256": self.oracle_sha256,
            "grants": [item.to_dict() for item in self.grants],
            "allowed_outcomes": list(self.allowed_outcomes),
            "max_evidence_refs": self.max_evidence_refs,
            "max_total_evidence_bytes": self.max_total_evidence_bytes,
        }

    @property
    def policy_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self._unsigned_payload())).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            **self._unsigned_payload(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuditCaseProofPolicy":
        keys = frozenset(
            {
                "schema_version",
                "policy_id",
                "policy_sha256",
                "authority_id",
                "authority_version",
                "engagement_id",
                "target_id",
                "target_revision",
                "target_sha256",
                "executor_id",
                "executor_version",
                "executor_sha256",
                "oracle_id",
                "oracle_version",
                "oracle_sha256",
                "grants",
                "allowed_outcomes",
                "max_evidence_refs",
                "max_total_evidence_bytes",
            }
        )
        data = _strict_object(payload, keys=keys, field_name="audit-case proof policy")
        grants = data["grants"]
        outcomes = data["allowed_outcomes"]
        if not isinstance(grants, list) or not isinstance(outcomes, list):
            raise AuditCaseProofError("audit-case policy arrays are invalid")
        policy = cls(
            authority_id=data["authority_id"],
            authority_version=data["authority_version"],
            engagement_id=data["engagement_id"],
            target_id=data["target_id"],
            target_revision=data["target_revision"],
            target_sha256=data["target_sha256"],
            executor_id=data["executor_id"],
            executor_version=data["executor_version"],
            executor_sha256=data["executor_sha256"],
            oracle_id=data["oracle_id"],
            oracle_version=data["oracle_version"],
            oracle_sha256=data["oracle_sha256"],
            grants=tuple(AuditCaseProofGrant.from_dict(item) for item in grants),
            allowed_outcomes=tuple(outcomes),
            max_evidence_refs=data["max_evidence_refs"],
            max_total_evidence_bytes=data["max_total_evidence_bytes"],
            policy_id=data["policy_id"],
            schema_version=data["schema_version"],
        )
        if data["policy_sha256"] != policy.policy_sha256 or policy.to_dict() != data:
            raise AuditCaseProofError("audit-case policy digest or canonical form is invalid")
        return policy

    def grant_for(self, case: AuditCase, plan: ValidationPlan) -> AuditCaseProofGrant:
        expected = AuditCaseProofGrant.for_case(case, plan)
        if expected not in self.grants:
            raise AuditCaseProofError("audit case and validation plan are not granted by policy")
        return expected


@dataclass(frozen=True)
class AuditCaseEvidence:
    """One explicit evidence object returned by the bounded executor."""

    evidence_id: str
    kind: str
    content: bytes = field(repr=False)
    media_type: str = "application/octet-stream"

    def __post_init__(self) -> None:
        object.__setattr__(self, "evidence_id", _identifier(self.evidence_id, "evidence_id"))
        if self.evidence_id.startswith("validation-"):
            raise AuditCaseProofError("executor evidence_id uses a ledger-reserved prefix")
        kind = str(self.kind or "").strip().lower()
        if kind not in _EVIDENCE_KINDS:
            raise AuditCaseProofError("executor evidence kind is invalid")
        object.__setattr__(self, "kind", kind)
        if not isinstance(self.content, bytes):
            raise TypeError("executor evidence content must be bytes")
        media_type = str(self.media_type or "").strip().lower()
        if not media_type or len(media_type) > 255 or any(ord(char) < 32 for char in media_type):
            raise AuditCaseProofError("executor evidence media_type is invalid")
        object.__setattr__(self, "media_type", media_type)

    @property
    def reference(self) -> ValidationEvidenceRef:
        return ValidationEvidenceRef(
            evidence_id=self.evidence_id,
            kind=self.kind,
            sha256=hashlib.sha256(self.content).hexdigest(),
            media_type=self.media_type,
        )

    def reference_for(self, attempt_id: str) -> ValidationEvidenceRef:
        """Namespace executor evidence so distinct attempts cannot collide."""

        namespace = hashlib.sha256(self.evidence_id.encode("utf-8")).hexdigest()[:24]
        return ValidationEvidenceRef(
            evidence_id=f"audit-evidence:{_identifier(attempt_id, 'attempt_id')}:{namespace}",
            kind=self.kind,
            sha256=hashlib.sha256(self.content).hexdigest(),
            media_type=self.media_type,
        )


@dataclass(frozen=True)
class AuditCaseExecutorOutput:
    """Bounded callback output; only a passed oracle can be published."""

    outcome: str
    oracle_passed: bool
    observed_target_revision: str
    observed_target_sha256: str
    observed_subject_sha256: str
    method: str
    reason: str
    evidence: tuple[AuditCaseEvidence, ...]
    confidence: float = 1.0
    limitations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        outcome = str(self.outcome or "").strip().lower()
        if outcome not in _CONCLUSIVE_OUTCOMES:
            raise AuditCaseProofError("executor output outcome is not conclusive")
        object.__setattr__(self, "outcome", outcome)
        if not isinstance(self.oracle_passed, bool):
            raise AuditCaseProofError("executor oracle_passed must be boolean")
        object.__setattr__(self, "observed_target_revision", _revision(self.observed_target_revision))
        object.__setattr__(
            self,
            "observed_target_sha256",
            _sha256(self.observed_target_sha256, "observed_target_sha256"),
        )
        object.__setattr__(
            self,
            "observed_subject_sha256",
            _sha256(self.observed_subject_sha256, "observed_subject_sha256"),
        )
        object.__setattr__(self, "method", _text(self.method, "executor method"))
        object.__setattr__(self, "reason", _text(self.reason, "executor reason"))
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise AuditCaseProofError("executor confidence is invalid")
        object.__setattr__(self, "confidence", float(self.confidence))
        evidence = tuple(self.evidence)
        if not evidence or any(type(item) is not AuditCaseEvidence for item in evidence):
            raise AuditCaseProofError("executor output requires typed evidence")
        if len({item.evidence_id for item in evidence}) != len(evidence):
            raise AuditCaseProofError("executor output contains duplicate evidence ids")
        if not any(item.kind == "oracle" for item in evidence):
            raise AuditCaseProofError("executor output requires oracle evidence")
        object.__setattr__(self, "evidence", evidence)
        limitations = tuple(sorted({_text(item, "limitation") for item in self.limitations}))
        object.__setattr__(self, "limitations", limitations)


@dataclass(frozen=True)
class BoundedAuditCaseExecutor:
    """Host-injected callback plus the immutable identity pinned by policy."""

    executor_id: str
    executor_version: str
    executor_sha256: str
    oracle_id: str
    oracle_version: str
    oracle_sha256: str
    callback: Callable[["AuditCaseExecutionRequest"], AuditCaseExecutorOutput] = field(
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        for field_name in ("executor_id", "executor_version", "oracle_id", "oracle_version"):
            object.__setattr__(self, field_name, _identifier(getattr(self, field_name), field_name))
        for field_name in ("executor_sha256", "oracle_sha256"):
            object.__setattr__(self, field_name, _sha256(getattr(self, field_name), field_name))
        if not callable(self.callback):
            raise TypeError("bounded audit-case executor callback must be callable")

    def execute(self, request: "AuditCaseExecutionRequest") -> AuditCaseExecutorOutput:
        output = self.callback(request)
        if type(output) is not AuditCaseExecutorOutput:
            raise AuditCaseProofError("bounded executor returned an unsupported output type")
        return output


@dataclass(frozen=True)
class AuditCaseExecutionRequest:
    """Canonical request made durable before the bounded callback runs."""

    attempt_id: str
    policy: AuditCaseProofPolicy
    audit_case: AuditCase
    plan: ValidationPlan
    schema_version: str = AUDIT_CASE_EXECUTION_REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_CASE_EXECUTION_REQUEST_SCHEMA_VERSION:
            raise AuditCaseProofError("unsupported audit-case execution request schema")
        object.__setattr__(self, "attempt_id", _identifier(self.attempt_id, "attempt_id"))
        if type(self.policy) is not AuditCaseProofPolicy:
            raise TypeError("audit-case request requires an authority policy")
        case = _canonical_case(self.audit_case)
        plan = _canonical_plan(self.plan)
        self.policy.grant_for(case, plan)
        object.__setattr__(self, "audit_case", case)
        object.__setattr__(self, "plan", plan)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "policy": self.policy.to_dict(),
            "audit_case": self.audit_case.to_dict(),
            "validation_plan": self.plan.to_dict(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuditCaseExecutionRequest":
        data = _strict_object(
            payload,
            keys=frozenset(
                {"schema_version", "attempt_id", "policy", "audit_case", "validation_plan"}
            ),
            field_name="audit-case execution request",
        )
        try:
            request = cls(
                attempt_id=data["attempt_id"],
                policy=AuditCaseProofPolicy.from_dict(data["policy"]),
                audit_case=AuditCase.from_dict(data["audit_case"]),
                plan=ValidationPlan.from_dict(data["validation_plan"]),
                schema_version=data["schema_version"],
            )
        except (TypeError, ValueError) as exc:
            if isinstance(exc, AuditCaseProofError):
                raise
            raise AuditCaseProofError("audit-case execution request is invalid") from exc
        if request.to_dict() != data:
            raise AuditCaseProofError("audit-case execution request is not canonical")
        return request


@dataclass(frozen=True)
class AuditCaseExecutionResponse:
    """Canonical, replay-resistant response derived from one request."""

    attempt_id: str
    request_sha256: str
    policy_id: str
    policy_sha256: str
    engagement_id: str
    target_id: str
    target_revision: str
    target_sha256: str
    subject_id: str
    subject_sha256: str
    plan_id: str
    plan_sha256: str
    executor_id: str
    executor_version: str
    executor_sha256: str
    oracle_id: str
    oracle_version: str
    oracle_sha256: str
    outcome: str
    confidence: float
    method: str
    reason: str
    evidence_refs: tuple[ValidationEvidenceRef, ...]
    limitations: tuple[str, ...] = ()
    response_id: str = ""
    schema_version: str = AUDIT_CASE_EXECUTION_RESPONSE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != AUDIT_CASE_EXECUTION_RESPONSE_SCHEMA_VERSION:
            raise AuditCaseProofError("unsupported audit-case execution response schema")
        for field_name in (
            "attempt_id",
            "policy_id",
            "engagement_id",
            "target_id",
            "subject_id",
            "plan_id",
            "executor_id",
            "executor_version",
            "oracle_id",
            "oracle_version",
        ):
            object.__setattr__(self, field_name, _identifier(getattr(self, field_name), field_name))
        object.__setattr__(self, "target_revision", _revision(self.target_revision))
        for field_name in (
            "request_sha256",
            "policy_sha256",
            "target_sha256",
            "subject_sha256",
            "plan_sha256",
            "executor_sha256",
            "oracle_sha256",
        ):
            object.__setattr__(self, field_name, _sha256(getattr(self, field_name), field_name))
        outcome = str(self.outcome or "").strip().lower()
        if outcome not in _CONCLUSIVE_OUTCOMES:
            raise AuditCaseProofError("audit-case response outcome is not conclusive")
        object.__setattr__(self, "outcome", outcome)
        if (
            not isinstance(self.confidence, (int, float))
            or isinstance(self.confidence, bool)
            or not math.isfinite(float(self.confidence))
            or not 0.0 <= float(self.confidence) <= 1.0
        ):
            raise AuditCaseProofError("audit-case response confidence is invalid")
        object.__setattr__(self, "confidence", float(self.confidence))
        object.__setattr__(self, "method", _text(self.method, "response method"))
        object.__setattr__(self, "reason", _text(self.reason, "response reason"))
        refs = tuple(self.evidence_refs)
        if (
            not refs
            or any(type(item) is not ValidationEvidenceRef for item in refs)
            or len({item.evidence_id for item in refs}) != len(refs)
            or not any(item.kind == "oracle" for item in refs)
            or any(item.kind not in _EVIDENCE_KINDS for item in refs)
        ):
            raise AuditCaseProofError("audit-case response evidence references are invalid")
        refs = tuple(sorted(refs, key=lambda item: item.evidence_id))
        object.__setattr__(self, "evidence_refs", refs)
        limitations = tuple(sorted({_text(item, "limitation") for item in self.limitations}))
        object.__setattr__(self, "limitations", limitations)
        expected = "acresponse_" + canonical_digest(self._unsigned_payload())[:24]
        supplied = str(self.response_id or "").strip()
        if supplied and supplied != expected:
            raise AuditCaseProofError("audit-case response id does not match its content")
        object.__setattr__(self, "response_id", expected)

    @classmethod
    def from_output(
        cls,
        request: AuditCaseExecutionRequest,
        *,
        request_sha256: str,
        output: AuditCaseExecutorOutput,
    ) -> "AuditCaseExecutionResponse":
        policy = request.policy
        grant = policy.grant_for(request.audit_case, request.plan)
        if not output.oracle_passed:
            raise AuditCaseProofError("audit-case oracle did not pass")
        if output.outcome not in policy.allowed_outcomes:
            raise AuditCaseProofError("executor outcome is not authorized by policy")
        if (
            output.observed_target_revision != policy.target_revision
            or output.observed_target_sha256 != policy.target_sha256
            or output.observed_subject_sha256 != grant.subject_sha256
        ):
            raise AuditCaseProofError("executor observation does not match the authorized target")
        return cls(
            attempt_id=request.attempt_id,
            request_sha256=request_sha256,
            policy_id=policy.policy_id,
            policy_sha256=policy.policy_sha256,
            engagement_id=policy.engagement_id,
            target_id=policy.target_id,
            target_revision=policy.target_revision,
            target_sha256=policy.target_sha256,
            subject_id=grant.subject_id,
            subject_sha256=grant.subject_sha256,
            plan_id=grant.plan_id,
            plan_sha256=grant.plan_sha256,
            executor_id=policy.executor_id,
            executor_version=policy.executor_version,
            executor_sha256=policy.executor_sha256,
            oracle_id=policy.oracle_id,
            oracle_version=policy.oracle_version,
            oracle_sha256=policy.oracle_sha256,
            outcome=output.outcome,
            confidence=output.confidence,
            method=output.method,
            reason=output.reason,
            evidence_refs=tuple(
                item.reference_for(request.attempt_id) for item in output.evidence
            ),
            limitations=output.limitations,
        )

    def _unsigned_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "attempt_id": self.attempt_id,
            "request_sha256": self.request_sha256,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "engagement_id": self.engagement_id,
            "target_id": self.target_id,
            "target_revision": self.target_revision,
            "target_sha256": self.target_sha256,
            "subject_id": self.subject_id,
            "subject_sha256": self.subject_sha256,
            "plan_id": self.plan_id,
            "plan_sha256": self.plan_sha256,
            "executor_id": self.executor_id,
            "executor_version": self.executor_version,
            "executor_sha256": self.executor_sha256,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "oracle_sha256": self.oracle_sha256,
            "outcome": self.outcome,
            "confidence": round(self.confidence, 3),
            "method": self.method,
            "reason": self.reason,
            "evidence_refs": [item.to_dict() for item in self.evidence_refs],
            "limitations": list(self.limitations),
        }

    def to_dict(self) -> dict[str, Any]:
        return {"response_id": self.response_id, **self._unsigned_payload()}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "AuditCaseExecutionResponse":
        keys = frozenset(
            {
                "schema_version",
                "response_id",
                "attempt_id",
                "request_sha256",
                "policy_id",
                "policy_sha256",
                "engagement_id",
                "target_id",
                "target_revision",
                "target_sha256",
                "subject_id",
                "subject_sha256",
                "plan_id",
                "plan_sha256",
                "executor_id",
                "executor_version",
                "executor_sha256",
                "oracle_id",
                "oracle_version",
                "oracle_sha256",
                "outcome",
                "confidence",
                "method",
                "reason",
                "evidence_refs",
                "limitations",
            }
        )
        data = _strict_object(payload, keys=keys, field_name="audit-case execution response")
        refs = data["evidence_refs"]
        limitations = data["limitations"]
        if not isinstance(refs, list) or not isinstance(limitations, list):
            raise AuditCaseProofError("audit-case response arrays are invalid")
        response = cls(
            **{
                key: value
                for key, value in data.items()
                if key not in {"evidence_refs", "limitations"}
            },
            evidence_refs=tuple(ValidationEvidenceRef.from_dict(item) for item in refs),
            limitations=tuple(limitations),
        )
        if response.to_dict() != data:
            raise AuditCaseProofError("audit-case response is not canonical")
        return response

    def validate_for(self, request: AuditCaseExecutionRequest) -> None:
        policy = request.policy
        grant = policy.grant_for(request.audit_case, request.plan)
        expected = {
            "attempt_id": request.attempt_id,
            "request_sha256": hashlib.sha256(_canonical_bytes(request.to_dict())).hexdigest(),
            "policy_id": policy.policy_id,
            "policy_sha256": policy.policy_sha256,
            "engagement_id": policy.engagement_id,
            "target_id": policy.target_id,
            "target_revision": policy.target_revision,
            "target_sha256": policy.target_sha256,
            "subject_id": grant.subject_id,
            "subject_sha256": grant.subject_sha256,
            "plan_id": grant.plan_id,
            "plan_sha256": grant.plan_sha256,
            "executor_id": policy.executor_id,
            "executor_version": policy.executor_version,
            "executor_sha256": policy.executor_sha256,
            "oracle_id": policy.oracle_id,
            "oracle_version": policy.oracle_version,
            "oracle_sha256": policy.oracle_sha256,
        }
        mismatches = sorted(
            field_name for field_name, value in expected.items() if getattr(self, field_name) != value
        )
        if mismatches:
            raise AuditCaseProofError(
                "audit-case response binding mismatch: " + ", ".join(mismatches)
            )
        if self.outcome not in policy.allowed_outcomes:
            raise AuditCaseProofError("audit-case response outcome is not authorized")
        prefix = f"audit-evidence:{request.attempt_id}:"
        if any(
            not item.evidence_id.startswith(prefix)
            or re.fullmatch(r"[0-9a-f]{24}", item.evidence_id[len(prefix):]) is None
            for item in self.evidence_refs
        ):
            raise AuditCaseProofError("audit-case evidence is not bound to this attempt")

    def to_validation_result(self) -> ValidationResult:
        execution = {
            "schema_version": self.schema_version,
            "response_id": self.response_id,
            "request_sha256": self.request_sha256,
            "policy_id": self.policy_id,
            "policy_sha256": self.policy_sha256,
            "target_revision": self.target_revision,
            "target_sha256": self.target_sha256,
            "subject_sha256": self.subject_sha256,
            "executor_id": self.executor_id,
            "executor_version": self.executor_version,
            "executor_sha256": self.executor_sha256,
            "oracle_id": self.oracle_id,
            "oracle_version": self.oracle_version,
            "oracle_sha256": self.oracle_sha256,
            "evidence_refs": [item.to_dict() for item in self.evidence_refs],
            "limitations": list(self.limitations),
        }
        return ValidationResult(
            subject_id=self.subject_id,
            subject_kind="audit_case",
            source=f"{self.executor_id}@{self.executor_version}",
            outcome=self.outcome,
            confidence=self.confidence,
            tested=True,
            human_validated=False,
            method=self.method,
            reason=self.reason,
            evidence=tuple(item.evidence_id for item in self.evidence_refs),
            metadata={
                "validation_plan_id": self.plan_id,
                "validation_plan_digest": self.plan_sha256,
                "proof_subject_sha256": self.subject_sha256,
                "audit_case_execution": execution,
            },
        )


def _validate_case_plan(case: AuditCase, plan: ValidationPlan) -> None:
    subject_digest = proof_subject_digest(case)
    if (
        plan.subject_kind != "audit_case"
        or plan.subject_id != case.case_id
        or plan.case_type != case.case_type
        or plan.case_status != case.status
        or plan.metadata.get("proof_subject_sha256") != subject_digest
    ):
        raise AuditCaseProofError("validation plan does not bind the exact audit case")


def _executor_matches_policy(
    executor: BoundedAuditCaseExecutor,
    policy: AuditCaseProofPolicy,
) -> None:
    for field_name in (
        "executor_id",
        "executor_version",
        "executor_sha256",
        "oracle_id",
        "oracle_version",
        "oracle_sha256",
    ):
        if getattr(executor, field_name) != getattr(policy, field_name):
            raise AuditCaseProofError(f"bounded executor {field_name} is not authorized")


def validate_audit_case_execution_material(
    *,
    authority_context: ProofAuthorityContext,
    expected_authority_sha256: str,
    attempt: Mapping[str, Any],
    request_bytes: bytes,
    response_bytes: bytes,
    result: ValidationResult,
    evidence_refs: Sequence[ValidationEvidenceRef],
    request_ref: ValidationEvidenceRef,
    response_ref: ValidationEvidenceRef,
) -> AuditCaseProofPolicy:
    """Re-derive every authority/result/evidence binding from durable bytes."""

    from belief.json_contracts import StrictJSONError, strict_json_loads

    try:
        request_payload = strict_json_loads(request_bytes)
        response_payload = strict_json_loads(response_bytes)
    except StrictJSONError as exc:
        raise AuditCaseProofError("audit-case evidence envelopes are not strict JSON") from exc
    if not isinstance(request_payload, Mapping) or not isinstance(response_payload, Mapping):
        raise AuditCaseProofError("audit-case evidence envelopes must be objects")
    request = AuditCaseExecutionRequest.from_dict(request_payload)
    response = AuditCaseExecutionResponse.from_dict(response_payload)
    policy = request.policy
    if (
        not isinstance(authority_context, ProofAuthorityContext)
        or authority_context.engagement_id != policy.engagement_id
        or authority_context.target_id != policy.target_id
        or _sha256(expected_authority_sha256, "expected_authority_sha256")
        != policy.policy_sha256
    ):
        raise AuditCaseProofError("audit-case policy is not the registered scope authority")
    attempt_bindings = {
        "attempt_id": request.attempt_id,
        "engagement_id": policy.engagement_id,
        "target_id": policy.target_id,
        "subject_id": request.audit_case.case_id,
        "subject_kind": "audit_case",
        "plan_id": request.plan.plan_id,
        "subject_sha256": proof_subject_digest(request.audit_case),
        "plan_sha256": canonical_digest(request.plan.to_dict()),
        "oracle_id": policy.oracle_id,
        "oracle_version": policy.oracle_version,
    }
    mismatches = sorted(
        name for name, value in attempt_bindings.items() if attempt.get(name) != value
    )
    if mismatches:
        raise AuditCaseProofError(
            "audit-case request does not match durable attempt: " + ", ".join(mismatches)
        )
    request_digest = hashlib.sha256(request_bytes).hexdigest()
    if response.request_sha256 != request_digest or request_ref.sha256 != request_digest:
        raise AuditCaseProofError("audit-case response does not bind its request bytes")
    response.validate_for(request)
    if response.to_validation_result().to_dict() != result.to_dict():
        raise AuditCaseProofError("audit-case result is not derived from its response")

    result_ref = ValidationEvidenceRef(
        evidence_id=f"validation-result:{result.result_id}",
        kind="artifact",
        sha256=validation_result_proof_digest(result),
        media_type="application/vnd.belief.validation-result.v1+json",
    )
    expected_refs = tuple(
        sorted(
            (request_ref, response_ref, result_ref, *response.evidence_refs),
            key=lambda item: (item.evidence_id, item.kind, item.sha256),
        )
    )
    supplied_refs = tuple(
        sorted(tuple(evidence_refs), key=lambda item: (item.evidence_id, item.kind, item.sha256))
    )
    if supplied_refs != expected_refs:
        raise AuditCaseProofError("audit-case proof evidence set is not exact")
    if response_ref.sha256 != hashlib.sha256(response_bytes).hexdigest():
        raise AuditCaseProofError("audit-case response evidence digest mismatch")
    if len(response.evidence_refs) > policy.max_evidence_refs:
        raise AuditCaseProofError("audit-case response exceeds its evidence reference budget")
    return policy


def run_audit_case_validation_with_ledger(
    ledger: Any,
    authority_context: ProofAuthorityContext,
    case: AuditCase,
    plan: ValidationPlan,
    *,
    policy: AuditCaseProofPolicy,
    expected_authority_sha256: str,
    executor: BoundedAuditCaseExecutor,
    attempt_id: str = "",
    on_attempt: Callable[[Any], None] | None = None,
) -> ValidationResult:
    """Run one policy-pinned callback and publish only re-verifiable proof."""

    from .ledger import (
        EvidenceArtifact,
        ValidationProofLedger,
        ValidationProofLedgerError,
    )

    if not isinstance(ledger, ValidationProofLedger):
        raise TypeError("ledger must be a ValidationProofLedger")
    if not isinstance(authority_context, ProofAuthorityContext):
        raise TypeError("authority_context must be a ProofAuthorityContext")
    case = _canonical_case(case)
    plan = _canonical_plan(plan)
    if not isinstance(policy, AuditCaseProofPolicy):
        raise TypeError("policy must be an AuditCaseProofPolicy")
    if not isinstance(executor, BoundedAuditCaseExecutor):
        raise TypeError("executor must be a BoundedAuditCaseExecutor")
    if (
        authority_context.engagement_id != policy.engagement_id
        or authority_context.target_id != policy.target_id
        or _sha256(expected_authority_sha256, "expected_authority_sha256")
        != policy.policy_sha256
    ):
        raise ValidationProofLedgerError("audit-case policy is not pinned by this scope")
    policy.grant_for(case, plan)
    _executor_matches_policy(executor, policy)
    if (
        policy.max_evidence_refs > ledger.max_evidence_refs - 3
        or policy.max_total_evidence_bytes > ledger.max_total_evidence_bytes
    ):
        raise ValidationProofLedgerError("audit-case policy exceeds ledger evidence bounds")

    identifier = attempt_id or f"vattempt_{uuid.uuid4().hex}"
    request = AuditCaseExecutionRequest(identifier, policy, case, plan)
    request_bytes = _canonical_bytes(request.to_dict())
    attempt = ledger.begin_attempt(
        authority_context,
        plan,
        expected_authority_sha256=expected_authority_sha256,
        subject_sha256=proof_subject_digest(case),
        request_bytes=request_bytes,
        request_media_type=AUDIT_CASE_REQUEST_MEDIA_TYPE,
        oracle_id=policy.oracle_id,
        oracle_version=policy.oracle_version,
        attempt_id=identifier,
    )
    try:
        if on_attempt is not None:
            on_attempt(attempt)
        output = executor.execute(request)
    except Exception as exc:
        ledger.finish_attempt(
            attempt,
            terminal_status="crashed",
            result=None,
            evidence=(
                EvidenceArtifact(
                    kind="log",
                    content=_canonical_bytes(
                        {"failure": "bounded_executor_exception", "type": type(exc).__name__}
                    ),
                    media_type="application/json",
                ),
            ),
        )
        raise

    try:
        total_bytes = sum(len(item.content) for item in output.evidence)
        if (
            len(output.evidence) > policy.max_evidence_refs
            or total_bytes > policy.max_total_evidence_bytes
        ):
            raise AuditCaseProofError("bounded executor output exceeds policy evidence bounds")
        response = AuditCaseExecutionResponse.from_output(
            request,
            request_sha256=attempt.request_ref.sha256,
            output=output,
        )
        result = response.to_validation_result()
        artifacts = tuple(
            EvidenceArtifact(
                evidence_id=item.reference_for(attempt.attempt_id).evidence_id,
                kind=item.kind,
                content=item.content,
                media_type=item.media_type,
            )
            for item in output.evidence
        )
    except Exception as exc:
        ledger.finish_attempt(
            attempt,
            terminal_status="failed",
            result=None,
            evidence=(
                EvidenceArtifact(
                    kind="log",
                    content=_canonical_bytes(
                        {"failure": "bounded_executor_output_rejected", "type": type(exc).__name__}
                    ),
                    media_type="application/json",
                ),
            ),
        )
        raise

    receipt = ledger._finish_audit_case_attempt(
        attempt,
        expected_authority_sha256=expected_authority_sha256,
        result=result,
        response=response,
        evidence=artifacts,
    )
    if receipt.result is None or receipt.proof is None:
        raise ValidationProofLedgerError("audit-case terminal omitted its durable proof")
    return receipt.result


__all__ = [
    "AUDIT_CASE_EXECUTION_REQUEST_SCHEMA_VERSION",
    "AUDIT_CASE_EXECUTION_RESPONSE_SCHEMA_VERSION",
    "AUDIT_CASE_PROOF_POLICY_SCHEMA_VERSION",
    "AUDIT_CASE_REQUEST_MEDIA_TYPE",
    "AUDIT_CASE_RESPONSE_MEDIA_TYPE",
    "AuditCaseEvidence",
    "AuditCaseExecutionRequest",
    "AuditCaseExecutionResponse",
    "AuditCaseExecutorOutput",
    "AuditCaseProofError",
    "AuditCaseProofGrant",
    "AuditCaseProofPolicy",
    "BoundedAuditCaseExecutor",
    "run_audit_case_validation_with_ledger",
    "validate_audit_case_execution_material",
]
