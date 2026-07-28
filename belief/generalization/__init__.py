"""Versioned contracts for BELIEF generalization experiments."""

from .failure_report import (
    FAILURE_CATEGORIES,
    GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION,
    FailureCaseAttribution,
    load_generalization_failure_report,
    validate_generalization_failure_report,
    write_generalization_failure_report,
)
from .holdout_attestation import (
    HOLDOUT_ATTESTATION_SCHEMA_VERSION,
    REQUIRED_AUTHORIZATION_ENVIRONMENT,
    REQUIRED_CACHE_PATCH_FIELDS,
    REQUIRED_CANDIDATE_SEMANTIC_MODE,
    REQUIRED_DEVELOPMENT_ARTIFACTS,
    REQUIRED_THRESHOLDS,
    REQUIRED_VALIDATION_CHECKS,
    authorize_holdout_execution,
    load_holdout_attestation,
    runtime_fingerprint,
    validate_holdout_attestation,
    verify_holdout_attestation_inputs,
    write_holdout_attestation,
)

__all__ = [
    "FAILURE_CATEGORIES",
    "GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION",
    "HOLDOUT_ATTESTATION_SCHEMA_VERSION",
    "REQUIRED_AUTHORIZATION_ENVIRONMENT",
    "REQUIRED_CACHE_PATCH_FIELDS",
    "REQUIRED_CANDIDATE_SEMANTIC_MODE",
    "REQUIRED_DEVELOPMENT_ARTIFACTS",
    "REQUIRED_THRESHOLDS",
    "REQUIRED_VALIDATION_CHECKS",
    "FailureCaseAttribution",
    "authorize_holdout_execution",
    "load_generalization_failure_report",
    "load_holdout_attestation",
    "runtime_fingerprint",
    "validate_generalization_failure_report",
    "validate_holdout_attestation",
    "verify_holdout_attestation_inputs",
    "write_generalization_failure_report",
    "write_holdout_attestation",
]
