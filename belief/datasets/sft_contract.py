"""Pure authority-safe projection shared by SFT export and validation."""

from __future__ import annotations

from dataclasses import fields, replace
from typing import Any

from belief.audit_case import AuditCase
from belief.json_contracts import strict_json_clone, strict_json_dumps
from belief.pdx.redaction import redact_pdx_value
from belief.reportability.scoring import assess_audit_case_reportability
from belief.validation.proof import proof_subject_digest


SFT_SCHEMA_VERSION = "belief.sft.v2"
SFT_ASSESSMENT_SOURCE = "belief.reportability.recomputed_without_authority.v1"
SFT_SYSTEM_MESSAGE = (
    "Classify BELIEF audit evidence for conservative human review without adding "
    "exploit instructions."
)

_UNTRUSTED_DERIVED_METADATA_FIELDS = {
    "duplicate",
    "feedback_adjustment",
    "feedback_events",
    "out_of_scope",
    "reasoning",
    "reportability",
}


def build_authority_safe_sft_row(case: AuditCase) -> dict[str, Any]:
    """Build one row whose complete visible input determines its target."""
    training_case = project_training_case(case)
    assessment = assess_audit_case_reportability(training_case)
    if assessment.proof_state == "verified" or assessment.verdict == "reportable_candidate":
        raise ValueError("belief.sft.v2 cannot encode authority-bearing proof labels")

    user_payload = {
        "audit_case": training_case.to_dict(),
        "proof_authority": "none",
    }
    assistant_payload = redact_pdx_value(
        {
            "missing_evidence": list(assessment.missing_evidence),
            "negative_factors": list(assessment.negative_factors),
            "next_step": "",
            "positive_factors": list(assessment.positive_factors),
            "proof_state": assessment.proof_state,
            "score": int(assessment.score),
            "validation_steps": [],
            "verdict": assessment.verdict,
            "verified_proof_ids": [],
        }
    )
    return {
        "messages": [
            {"role": "system", "content": SFT_SYSTEM_MESSAGE},
            {
                "role": "user",
                "content": _canonical_content(user_payload),
            },
            {
                "role": "assistant",
                "content": _canonical_content(assistant_payload),
            },
        ],
        "metadata": {
            "assessment_source": SFT_ASSESSMENT_SOURCE,
            "authority_sha256": None,
            "case_id": training_case.case_id,
            "case_type": training_case.case_type,
            "ledger_snapshot_id": None,
            "proof_state": assessment.proof_state,
            "schema_version": SFT_SCHEMA_VERSION,
            "source": "belief",
            "subject_sha256": proof_subject_digest(training_case),
            "verified_proof_ids": [],
        },
    }


def project_training_case(case: AuditCase) -> AuditCase:
    """Remove untrusted targets, redact inputs, and return the exact scored case."""
    if not isinstance(case, AuditCase):
        raise TypeError("SFT projection accepts only AuditCase instances")
    raw_case = {
        field.name: getattr(case, field.name)
        for field in fields(AuditCase)
    }
    canonical_case = AuditCase.from_dict(strict_json_clone(raw_case))
    metadata = {
        key: value
        for key, value in canonical_case.metadata.items()
        if key not in _UNTRUSTED_DERIVED_METADATA_FIELDS
    }
    projected = replace(
        canonical_case,
        human_next_steps=(),
        metadata=metadata,
    )
    redacted = redact_pdx_value(projected.to_dict())
    if not isinstance(redacted, dict):
        raise ValueError("redacted audit case must remain a JSON object")
    return AuditCase.from_dict(redacted)


def _canonical_content(payload: Any) -> str:
    return strict_json_dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


__all__ = [
    "SFT_ASSESSMENT_SOURCE",
    "SFT_SCHEMA_VERSION",
    "SFT_SYSTEM_MESSAGE",
    "build_authority_safe_sft_row",
    "project_training_case",
]
