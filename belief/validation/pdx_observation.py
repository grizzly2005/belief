"""Adapt accepted PDX receipt metadata into informational validation signals."""

from __future__ import annotations

from belief.pdx.attestation_store import AcceptedPDXObservation, SIGNAL_ONLY_PROOF_STATE

from .models import ValidationResult


def pdx_observation_to_validation_result(observation: AcceptedPDXObservation) -> ValidationResult:
    """Preserve receipt lineage without creating execution or proof authority.

    Obtain the projection through PDXEvidenceStore.iter_accepted_observations.
    This adapter cannot authenticate a manually constructed projection, and
    never treats its metadata as a successful test or a human validation.
    """
    if not isinstance(observation, AcceptedPDXObservation):
        raise TypeError("expected an AcceptedPDXObservation projection")
    return ValidationResult(
        subject_id=observation.capture_id,
        subject_kind="pdx_observation",
        source="pdx",
        outcome="informational",
        confidence=0.5,
        tested=False,
        human_validated=False,
        method="pdx.attestation_receipt",
        reason="Accepted observation metadata has no BELIEF execution proof.",
        evidence=(
            observation.receipt_id,
            observation.attestation_id,
            f"observation:sha256:{observation.observation_hash}",
        ),
        metadata={
            "pdx_observation": observation.to_dict(),
            "positive_evidence": False,
            "proof_state": SIGNAL_ONLY_PROOF_STATE,
            "missing_proof_references": ["attempt_id", "result_id", "evidence_refs"],
        },
    )


__all__ = ["pdx_observation_to_validation_result"]
