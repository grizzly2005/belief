"""Strict JSON contracts for the isolated validation worker."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..plan_models import canonical_digest, clean_text, unique_strings


WORKER_REQUEST_SCHEMA_VERSION = "belief.validation_worker_request.v2"
WORKER_RESPONSE_SCHEMA_VERSION = "belief.validation_worker_response.v2"
WORKER_ATTESTATION_SCHEMA_VERSION = "belief.validation_worker_attestation.v2"
WORKER_DIAGNOSTICS_SCHEMA_VERSION = "belief.validation_worker_diagnostics.v1"

MAX_WORKER_REQUEST_BYTES = 16 * 1024
MAX_WORKER_RESPONSE_BYTES = 256 * 1024
MAX_WORKER_OBSERVATIONS = 32
MAX_WORKER_DIAGNOSTIC_CHARS = 4_096
MAX_JSON_DEPTH = 12
MAX_JSON_COLLECTION_LENGTH = 64
MAX_JSON_STRING_CHARS = 4_096
MAX_JSON_NODES = 4_096
MIN_WORKER_TIMEOUT_MS = 100
MAX_WORKER_TIMEOUT_MS = 30_000

WORKER_STATUSES = {
    "completed",
    "inconclusive",
    "unsupported",
    "invalid_request",
    "crashed",
    "timed_out",
    "cancelled",
    "policy_violation",
}
WORKER_ERROR_CODES = {
    "invalid_request",
    "unsupported_protocol",
    "unknown_fixture",
    "binding_mismatch",
    "dependency_unavailable",
    "timeout",
    "cancelled",
    "child_crash",
    "malformed_response",
    "response_too_large",
    "policy_violation",
    "internal_error",
}

_FIXTURE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_PLAN_ID_RE = re.compile(r"^vp_[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+@-]{0,159}$")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
_SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+@/-]{0,255}$")

_REQUEST_FIELDS = {
    "schema_version",
    "fixture_id",
    "validation_plan_id",
    "validation_plan_digest",
    "source_revision",
    "test_parameters",
    "timeout_ms",
    "correlation_id",
}
_TEST_PARAMETER_FIELDS = {"include_symlink"}
_OBSERVATION_FIELDS = {
    "scenario",
    "stimulus",
    "oracle",
    "expected",
    "actual",
    "baseline",
    "oracle_evaluated",
    "oracle_passed",
    "evidence",
    "limitations",
    "cost_units",
}
_ERROR_FIELDS = {"code", "message"}
_RESOURCE_LIMIT_FIELDS = {
    "cpu",
    "open_files",
    "file_size",
    "child_processes",
}
_ATTESTATION_FIELDS = {
    "schema_version",
    "protocol_version",
    "fixture_id",
    "fixture_registry_digest",
    "fixture_source_digest",
    "validation_plan_id",
    "validation_plan_digest",
    "source_revision",
    "framework",
    "framework_version",
    "python_version",
    "platform",
    "environment_policy_installed",
    "environment_secret_probe_passed",
    "filesystem_policy_installed",
    "network_policy_installed",
    "process_policy_installed",
    "timeout_enforced",
    "cleanup_completed",
    "resource_limits",
    "io_policy_violations",
    "limitations",
}
_DIAGNOSTIC_FIELDS = {
    "schema_version",
    "summary",
    "stdout",
    "stderr",
    "stdout_truncated",
    "stderr_truncated",
    "child_exit_code",
    "cancellation_reason",
}
_RESPONSE_FIELDS = {
    "schema_version",
    "correlation_id",
    "fixture_id",
    "validation_plan_id",
    "validation_plan_digest",
    "worker_status",
    "observations",
    "baseline",
    "oracles",
    "limitations",
    "errors",
    "duration_ms",
    "attestation",
    "diagnostics",
    "semantic_digest",
}
_ORACLE_FIELDS = {"evaluated", "passed", "failed", "unevaluated"}


class WorkerProtocolError(ValueError):
    """Raised when a worker message violates its strict JSON contract."""

    def __init__(self, code: str, message: str) -> None:
        if code not in WORKER_ERROR_CODES:
            code = "internal_error"
        super().__init__(message)
        self.code = code


class _DuplicateKeyError(ValueError):
    pass


@dataclass(frozen=True)
class WorkerRequest:
    """The complete caller-controlled message accepted by the worker."""

    fixture_id: str
    validation_plan_id: str
    validation_plan_digest: str
    source_revision: str
    test_parameters: dict[str, Any] = field(default_factory=dict)
    timeout_ms: int = 5_000
    correlation_id: str = "correlation"
    schema_version: str = WORKER_REQUEST_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != WORKER_REQUEST_SCHEMA_VERSION:
            raise WorkerProtocolError(
                "unsupported_protocol",
                "unsupported worker request schema",
            )
        _require_pattern(
            self.fixture_id,
            _FIXTURE_ID_RE,
            code="invalid_request",
            message="fixture ID is invalid",
        )
        _require_pattern(
            self.validation_plan_id,
            _PLAN_ID_RE,
            code="invalid_request",
            message="validation plan ID is invalid",
        )
        digest = _require_pattern(
            self.validation_plan_digest,
            _SHA256_RE,
            code="invalid_request",
            message="validation plan digest is invalid",
        )
        object.__setattr__(self, "validation_plan_digest", digest)
        _require_pattern(
            self.source_revision,
            _REVISION_RE,
            code="invalid_request",
            message="source revision is invalid",
        )
        _require_pattern(
            self.correlation_id,
            _CORRELATION_RE,
            code="invalid_request",
            message="correlation ID is invalid",
        )
        if (
            not isinstance(self.timeout_ms, int)
            or isinstance(self.timeout_ms, bool)
            or not MIN_WORKER_TIMEOUT_MS <= self.timeout_ms <= MAX_WORKER_TIMEOUT_MS
        ):
            raise WorkerProtocolError(
                "invalid_request",
                "worker timeout is outside the allowed range",
            )
        object.__setattr__(
            self,
            "test_parameters",
            _strict_test_parameters(self.test_parameters),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "fixture_id": self.fixture_id,
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "source_revision": self.source_revision,
            "test_parameters": copy.deepcopy(self.test_parameters),
            "timeout_ms": self.timeout_ms,
            "correlation_id": self.correlation_id,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerRequest":
        _require_exact_fields(payload, _REQUEST_FIELDS, "worker request", "invalid_request")
        for field_name in (
            "schema_version",
            "fixture_id",
            "validation_plan_id",
            "validation_plan_digest",
            "source_revision",
            "correlation_id",
        ):
            if not isinstance(payload[field_name], str):
                raise WorkerProtocolError(
                    "invalid_request",
                    f"worker request {field_name} must be a string",
                )
        request = cls(
            schema_version=payload["schema_version"],
            fixture_id=payload["fixture_id"],
            validation_plan_id=payload["validation_plan_id"],
            validation_plan_digest=payload["validation_plan_digest"],
            source_revision=payload["source_revision"],
            test_parameters=payload["test_parameters"],
            timeout_ms=payload["timeout_ms"],
            correlation_id=payload["correlation_id"],
        )
        if request.to_dict() != dict(payload):
            raise WorkerProtocolError(
                "invalid_request",
                "worker request is not canonical",
            )
        return request


@dataclass(frozen=True)
class WorkerObservation:
    """Framework-neutral evidence returned by one registered fixture."""

    scenario: str
    stimulus: str
    oracle: str
    expected: str
    actual: dict[str, Any]
    baseline: bool
    oracle_evaluated: bool
    oracle_passed: bool | None
    evidence: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    cost_units: int = 1

    def __post_init__(self) -> None:
        for field_name in ("scenario", "stimulus", "oracle", "expected"):
            value = clean_text(getattr(self, field_name))
            if not value or len(value) > 512 or _contains_invalid_unicode(value):
                raise WorkerProtocolError(
                    "malformed_response",
                    f"worker observation {field_name} is invalid",
                )
            object.__setattr__(self, field_name, value)
        if not isinstance(self.baseline, bool):
            raise WorkerProtocolError(
                "malformed_response",
                "worker observation baseline must be boolean",
            )
        if not isinstance(self.oracle_evaluated, bool):
            raise WorkerProtocolError(
                "malformed_response",
                "worker observation oracle_evaluated must be boolean",
            )
        if self.oracle_passed is not True and self.oracle_passed is not False:
            if self.oracle_passed is not None:
                raise WorkerProtocolError(
                    "malformed_response",
                    "worker observation oracle_passed is invalid",
                )
        if self.oracle_passed is not None and not self.oracle_evaluated:
            raise WorkerProtocolError(
                "malformed_response",
                "unevaluated worker oracle cannot have a verdict",
            )
        if (
            not isinstance(self.cost_units, int)
            or isinstance(self.cost_units, bool)
            or not 0 <= self.cost_units <= 100
        ):
            raise WorkerProtocolError(
                "malformed_response",
                "worker observation cost is invalid",
            )
        object.__setattr__(self, "actual", _json_object(self.actual))
        object.__setattr__(
            self,
            "evidence",
            _bounded_strings(self.evidence, code="malformed_response"),
        )
        object.__setattr__(
            self,
            "limitations",
            _bounded_strings(self.limitations, code="malformed_response"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario,
            "stimulus": self.stimulus,
            "oracle": self.oracle,
            "expected": self.expected,
            "actual": copy.deepcopy(self.actual),
            "baseline": self.baseline,
            "oracle_evaluated": self.oracle_evaluated,
            "oracle_passed": self.oracle_passed,
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
            "cost_units": self.cost_units,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerObservation":
        _require_exact_fields(
            payload,
            _OBSERVATION_FIELDS,
            "worker observation",
            "malformed_response",
        )
        observation = cls(
            scenario=_strict_string(payload["scenario"], "scenario"),
            stimulus=_strict_string(payload["stimulus"], "stimulus"),
            oracle=_strict_string(payload["oracle"], "oracle"),
            expected=_strict_string(payload["expected"], "expected"),
            actual=payload["actual"],
            baseline=payload["baseline"],
            oracle_evaluated=payload["oracle_evaluated"],
            oracle_passed=payload["oracle_passed"],
            evidence=_strict_string_sequence(payload["evidence"], "evidence"),
            limitations=_strict_string_sequence(payload["limitations"], "limitations"),
            cost_units=payload["cost_units"],
        )
        if observation.to_dict() != dict(payload):
            raise WorkerProtocolError(
                "malformed_response",
                "worker observation is not canonical",
            )
        return observation


@dataclass(frozen=True)
class WorkerError:
    """One normalized worker error from the closed taxonomy."""

    code: str
    message: str

    def __post_init__(self) -> None:
        if self.code not in WORKER_ERROR_CODES:
            raise WorkerProtocolError(
                "malformed_response",
                "worker error code is outside the protocol taxonomy",
            )
        message = clean_text(self.message)
        if not message or len(message) > 256 or _contains_invalid_unicode(message):
            raise WorkerProtocolError(
                "malformed_response",
                "worker error message is invalid",
            )
        object.__setattr__(self, "message", message)

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerError":
        _require_exact_fields(
            payload,
            _ERROR_FIELDS,
            "worker error",
            "malformed_response",
        )
        return cls(
            code=_strict_string(payload["code"], "error code"),
            message=_strict_string(payload["message"], "error message"),
        )


@dataclass(frozen=True)
class WorkerAttestation:
    """Versioned semantic statement about one isolated worker run."""

    fixture_id: str
    fixture_registry_digest: str
    fixture_source_digest: str
    validation_plan_id: str
    validation_plan_digest: str
    source_revision: str
    framework: str
    framework_version: str
    python_version: str
    platform: str
    environment_policy_installed: bool | None
    environment_secret_probe_passed: bool | None
    filesystem_policy_installed: bool | None
    network_policy_installed: bool | None
    process_policy_installed: bool | None
    timeout_enforced: bool | None
    cleanup_completed: bool | None
    resource_limits: dict[str, bool | None] = field(default_factory=dict)
    io_policy_violations: tuple[str, ...] = ()
    limitations: tuple[str, ...] = ()
    protocol_version: str = WORKER_RESPONSE_SCHEMA_VERSION
    schema_version: str = WORKER_ATTESTATION_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != WORKER_ATTESTATION_SCHEMA_VERSION:
            raise WorkerProtocolError(
                "malformed_response",
                "unsupported worker attestation schema",
            )
        if self.protocol_version != WORKER_RESPONSE_SCHEMA_VERSION:
            raise WorkerProtocolError(
                "malformed_response",
                "worker attestation protocol mismatch",
            )
        _require_pattern(
            self.fixture_id,
            _FIXTURE_ID_RE,
            code="malformed_response",
            message="attested fixture ID is invalid",
        )
        _require_pattern(
            self.validation_plan_id,
            _PLAN_ID_RE,
            code="malformed_response",
            message="attested validation plan ID is invalid",
        )
        for field_name in (
            "fixture_registry_digest",
            "fixture_source_digest",
            "validation_plan_digest",
        ):
            _require_pattern(
                getattr(self, field_name),
                _SHA256_RE,
                code="malformed_response",
                message=f"attested {field_name} is invalid",
            )
        _require_pattern(
            self.source_revision,
            _REVISION_RE,
            code="malformed_response",
            message="attested source revision is invalid",
        )
        for field_name in (
            "framework",
            "framework_version",
            "python_version",
            "platform",
        ):
            value = getattr(self, field_name)
            if value and (
                not isinstance(value, str)
                or not _SAFE_TOKEN_RE.fullmatch(value)
                or _contains_invalid_unicode(value)
            ):
                raise WorkerProtocolError(
                    "malformed_response",
                    f"attested {field_name} is invalid",
                )
        for field_name in (
            "environment_policy_installed",
            "environment_secret_probe_passed",
            "filesystem_policy_installed",
            "network_policy_installed",
            "process_policy_installed",
            "timeout_enforced",
            "cleanup_completed",
        ):
            _require_tristate(getattr(self, field_name), field_name)
        resource_limits = dict(self.resource_limits)
        if set(resource_limits) != _RESOURCE_LIMIT_FIELDS:
            raise WorkerProtocolError(
                "malformed_response",
                "worker resource-limit attestation fields are invalid",
            )
        for name, value in resource_limits.items():
            _require_tristate(value, f"resource limit {name}")
        object.__setattr__(self, "resource_limits", resource_limits)
        object.__setattr__(
            self,
            "io_policy_violations",
            _bounded_strings(self.io_policy_violations, code="malformed_response"),
        )
        object.__setattr__(
            self,
            "limitations",
            _bounded_strings(self.limitations, code="malformed_response"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "protocol_version": self.protocol_version,
            "fixture_id": self.fixture_id,
            "fixture_registry_digest": self.fixture_registry_digest,
            "fixture_source_digest": self.fixture_source_digest,
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "source_revision": self.source_revision,
            "framework": self.framework,
            "framework_version": self.framework_version,
            "python_version": self.python_version,
            "platform": self.platform,
            "environment_policy_installed": self.environment_policy_installed,
            "environment_secret_probe_passed": self.environment_secret_probe_passed,
            "filesystem_policy_installed": self.filesystem_policy_installed,
            "network_policy_installed": self.network_policy_installed,
            "process_policy_installed": self.process_policy_installed,
            "timeout_enforced": self.timeout_enforced,
            "cleanup_completed": self.cleanup_completed,
            "resource_limits": dict(self.resource_limits),
            "io_policy_violations": list(self.io_policy_violations),
            "limitations": list(self.limitations),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerAttestation":
        _require_exact_fields(
            payload,
            _ATTESTATION_FIELDS,
            "worker attestation",
            "malformed_response",
        )
        return cls(
            schema_version=_strict_string(payload["schema_version"], "attestation schema"),
            protocol_version=_strict_string(
                payload["protocol_version"],
                "attestation protocol",
            ),
            fixture_id=_strict_string(payload["fixture_id"], "attested fixture ID"),
            fixture_registry_digest=_strict_string(
                payload["fixture_registry_digest"],
                "fixture registry digest",
            ),
            fixture_source_digest=_strict_string(
                payload["fixture_source_digest"],
                "fixture source digest",
            ),
            validation_plan_id=_strict_string(
                payload["validation_plan_id"],
                "attested validation plan ID",
            ),
            validation_plan_digest=_strict_string(
                payload["validation_plan_digest"],
                "attested validation plan digest",
            ),
            source_revision=_strict_string(
                payload["source_revision"],
                "attested source revision",
            ),
            framework=_strict_string(payload["framework"], "framework"),
            framework_version=_strict_string(
                payload["framework_version"],
                "framework version",
            ),
            python_version=_strict_string(payload["python_version"], "Python version"),
            platform=_strict_string(payload["platform"], "platform"),
            environment_policy_installed=payload["environment_policy_installed"],
            environment_secret_probe_passed=payload[
                "environment_secret_probe_passed"
            ],
            filesystem_policy_installed=payload["filesystem_policy_installed"],
            network_policy_installed=payload["network_policy_installed"],
            process_policy_installed=payload["process_policy_installed"],
            timeout_enforced=payload["timeout_enforced"],
            cleanup_completed=payload["cleanup_completed"],
            resource_limits=_strict_tristate_object(
                payload["resource_limits"],
                "resource limits",
            ),
            io_policy_violations=_strict_string_sequence(
                payload["io_policy_violations"],
                "I/O policy violations",
            ),
            limitations=_strict_string_sequence(
                payload["limitations"],
                "attestation limitations",
            ),
        )


# Compatibility name for the pre-hardening public import.
WorkerCapabilityAttestation = WorkerAttestation


@dataclass(frozen=True)
class WorkerDiagnostics:
    """Bounded runtime-only diagnostics excluded from the semantic digest."""

    summary: str = ""
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    child_exit_code: int | None = None
    cancellation_reason: str = ""
    schema_version: str = WORKER_DIAGNOSTICS_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != WORKER_DIAGNOSTICS_SCHEMA_VERSION:
            raise WorkerProtocolError(
                "malformed_response",
                "unsupported worker diagnostics schema",
            )
        for field_name in ("summary", "stdout", "stderr", "cancellation_reason"):
            value = getattr(self, field_name)
            if (
                not isinstance(value, str)
                or len(value) > MAX_WORKER_DIAGNOSTIC_CHARS
                or _contains_invalid_unicode(value)
                or _contains_unsafe_control(value)
            ):
                raise WorkerProtocolError(
                    "malformed_response",
                    f"worker diagnostic {field_name} is invalid",
                )
        for field_name in ("stdout_truncated", "stderr_truncated"):
            if not isinstance(getattr(self, field_name), bool):
                raise WorkerProtocolError(
                    "malformed_response",
                    f"worker diagnostic {field_name} must be boolean",
                )
        if (
            self.child_exit_code is not None
            and (
                not isinstance(self.child_exit_code, int)
                or isinstance(self.child_exit_code, bool)
                or not -2**31 <= self.child_exit_code <= 2**31 - 1
            )
        ):
            raise WorkerProtocolError(
                "malformed_response",
                "worker child exit code is invalid",
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "summary": self.summary,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "child_exit_code": self.child_exit_code,
            "cancellation_reason": self.cancellation_reason,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerDiagnostics":
        _require_exact_fields(
            payload,
            _DIAGNOSTIC_FIELDS,
            "worker diagnostics",
            "malformed_response",
        )
        return cls(
            schema_version=_strict_string(payload["schema_version"], "diagnostics schema"),
            summary=_strict_string(payload["summary"], "diagnostic summary"),
            stdout=_strict_string(payload["stdout"], "diagnostic stdout"),
            stderr=_strict_string(payload["stderr"], "diagnostic stderr"),
            stdout_truncated=payload["stdout_truncated"],
            stderr_truncated=payload["stderr_truncated"],
            child_exit_code=payload["child_exit_code"],
            cancellation_reason=_strict_string(
                payload["cancellation_reason"],
                "cancellation reason",
            ),
        )


def unavailable_attestation(
    request: WorkerRequest,
    *,
    cleanup_completed: bool | None,
    timeout_enforced: bool | None = True,
) -> WorkerAttestation:
    """Build a conservative parent-side attestation for missing child evidence."""

    return WorkerAttestation(
        fixture_id=request.fixture_id,
        fixture_registry_digest="0" * 64,
        fixture_source_digest="0" * 64,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        source_revision=request.source_revision,
        framework="",
        framework_version="",
        python_version="",
        platform="",
        environment_policy_installed=None,
        environment_secret_probe_passed=None,
        filesystem_policy_installed=None,
        network_policy_installed=None,
        process_policy_installed=None,
        timeout_enforced=timeout_enforced,
        cleanup_completed=cleanup_completed,
        resource_limits={
            "cpu": None,
            "open_files": None,
            "file_size": None,
            "child_processes": None,
        },
        limitations=("child_attestation_unavailable",),
    )


@dataclass(frozen=True)
class WorkerResponse:
    """Strict, versioned evidence envelope returned by the worker."""

    correlation_id: str
    fixture_id: str
    validation_plan_id: str
    validation_plan_digest: str
    worker_status: str
    observations: tuple[WorkerObservation, ...] = ()
    baseline: bool | None = None
    limitations: tuple[str, ...] = ()
    errors: tuple[WorkerError, ...] = ()
    duration_ms: int = 0
    attestation: WorkerAttestation | None = None
    diagnostics: WorkerDiagnostics = field(default_factory=WorkerDiagnostics)
    semantic_digest: str = ""
    schema_version: str = WORKER_RESPONSE_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != WORKER_RESPONSE_SCHEMA_VERSION:
            raise WorkerProtocolError(
                "unsupported_protocol",
                "unsupported worker response schema",
            )
        _require_pattern(
            self.correlation_id,
            _CORRELATION_RE,
            code="malformed_response",
            message="correlation ID is invalid",
        )
        _require_pattern(
            self.fixture_id,
            _FIXTURE_ID_RE,
            code="malformed_response",
            message="fixture ID is invalid",
        )
        _require_pattern(
            self.validation_plan_id,
            _PLAN_ID_RE,
            code="malformed_response",
            message="validation plan ID is invalid",
        )
        _require_pattern(
            self.validation_plan_digest,
            _SHA256_RE,
            code="malformed_response",
            message="validation plan digest is invalid",
        )
        if self.worker_status not in WORKER_STATUSES:
            raise WorkerProtocolError(
                "malformed_response",
                "worker status is invalid",
            )
        observations = tuple(self.observations)
        if (
            len(observations) > MAX_WORKER_OBSERVATIONS
            or any(not isinstance(item, WorkerObservation) for item in observations)
        ):
            raise WorkerProtocolError(
                "malformed_response",
                "worker observations are invalid",
            )
        object.__setattr__(self, "observations", observations)
        if self.baseline is not True and self.baseline is not False:
            if self.baseline is not None:
                raise WorkerProtocolError(
                    "malformed_response",
                    "worker baseline is invalid",
                )
        if self.baseline != _baseline_verdict(observations):
            raise WorkerProtocolError(
                "malformed_response",
                "worker baseline does not match observations",
            )
        object.__setattr__(
            self,
            "limitations",
            _bounded_strings(self.limitations, code="malformed_response"),
        )
        errors = tuple(self.errors)
        if len(errors) > 8 or any(not isinstance(item, WorkerError) for item in errors):
            raise WorkerProtocolError(
                "malformed_response",
                "worker errors are invalid",
            )
        object.__setattr__(self, "errors", errors)
        if (
            not isinstance(self.duration_ms, int)
            or isinstance(self.duration_ms, bool)
            or not 0 <= self.duration_ms <= MAX_WORKER_TIMEOUT_MS + 10_000
        ):
            raise WorkerProtocolError(
                "malformed_response",
                "worker duration is invalid",
            )
        if not isinstance(self.attestation, WorkerAttestation):
            raise WorkerProtocolError(
                "malformed_response",
                "worker attestation is invalid",
            )
        if not isinstance(self.diagnostics, WorkerDiagnostics):
            raise WorkerProtocolError(
                "malformed_response",
                "worker diagnostics are invalid",
            )
        expected_digest = canonical_digest(self._semantic_payload())
        supplied_digest = clean_text(self.semantic_digest)
        if supplied_digest and supplied_digest != expected_digest:
            raise WorkerProtocolError(
                "malformed_response",
                "worker semantic digest mismatch",
            )
        object.__setattr__(self, "semantic_digest", expected_digest)

    @property
    def capabilities(self) -> WorkerAttestation:
        """Compatibility alias for the former v1 response attribute."""

        assert self.attestation is not None
        return self.attestation

    @property
    def evidence_digest(self) -> str:
        """Compatibility alias for the semantic digest."""

        return self.semantic_digest

    @property
    def oracle_counts(self) -> dict[str, int]:
        evaluated = sum(item.oracle_evaluated for item in self.observations)
        passed = sum(item.oracle_passed is True for item in self.observations)
        failed = sum(item.oracle_passed is False for item in self.observations)
        return {
            "evaluated": evaluated,
            "passed": passed,
            "failed": failed,
            "unevaluated": len(self.observations) - evaluated,
        }

    def _semantic_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "fixture_id": self.fixture_id,
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "worker_status": self.worker_status,
            "observations": [item.to_dict() for item in self.observations],
            "baseline": self.baseline,
            "oracles": self.oracle_counts,
            "limitations": list(self.limitations),
            "errors": [error.to_dict() for error in self.errors],
            "attestation": self.attestation.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._semantic_payload(),
            "correlation_id": self.correlation_id,
            "duration_ms": self.duration_ms,
            "diagnostics": self.diagnostics.to_dict(),
            "semantic_digest": self.semantic_digest,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerResponse":
        _require_exact_fields(
            payload,
            _RESPONSE_FIELDS,
            "worker response",
            "malformed_response",
        )
        _require_exact_fields(
            payload["oracles"],
            _ORACLE_FIELDS,
            "worker oracle counts",
            "malformed_response",
        )
        response = cls(
            schema_version=_strict_string(payload["schema_version"], "response schema"),
            correlation_id=_strict_string(payload["correlation_id"], "correlation ID"),
            fixture_id=_strict_string(payload["fixture_id"], "fixture ID"),
            validation_plan_id=_strict_string(
                payload["validation_plan_id"],
                "validation plan ID",
            ),
            validation_plan_digest=_strict_string(
                payload["validation_plan_digest"],
                "validation plan digest",
            ),
            worker_status=_strict_string(payload["worker_status"], "worker status"),
            observations=tuple(
                WorkerObservation.from_dict(item)
                for item in _strict_object_sequence(
                    payload["observations"],
                    "observations",
                )
            ),
            baseline=payload["baseline"],
            limitations=_strict_string_sequence(
                payload["limitations"],
                "limitations",
            ),
            errors=tuple(
                WorkerError.from_dict(item)
                for item in _strict_object_sequence(payload["errors"], "errors")
            ),
            duration_ms=payload["duration_ms"],
            attestation=WorkerAttestation.from_dict(payload["attestation"]),
            diagnostics=WorkerDiagnostics.from_dict(payload["diagnostics"]),
            semantic_digest=_strict_string(
                payload["semantic_digest"],
                "semantic digest",
            ),
        )
        if response.oracle_counts != dict(payload["oracles"]):
            raise WorkerProtocolError(
                "malformed_response",
                "worker oracle counts do not match observations",
            )
        if response.to_dict() != dict(payload):
            raise WorkerProtocolError(
                "malformed_response",
                "worker response is not canonical",
            )
        return response


def encode_worker_request(request: WorkerRequest) -> bytes:
    if not isinstance(request, WorkerRequest):
        raise WorkerProtocolError(
            "invalid_request",
            "worker request object is invalid",
        )
    return _encode_message(
        request.to_dict(),
        limit=MAX_WORKER_REQUEST_BYTES,
        kind="request",
    )


def decode_worker_request(message: bytes) -> WorkerRequest:
    payload = _decode_message(
        message,
        limit=MAX_WORKER_REQUEST_BYTES,
        kind="request",
    )
    return WorkerRequest.from_dict(payload)


def encode_worker_response(response: WorkerResponse) -> bytes:
    if not isinstance(response, WorkerResponse):
        raise WorkerProtocolError(
            "malformed_response",
            "worker response object is invalid",
        )
    return _encode_message(
        response.to_dict(),
        limit=MAX_WORKER_RESPONSE_BYTES,
        kind="response",
    )


def decode_worker_response(message: bytes) -> WorkerResponse:
    payload = _decode_message(
        message,
        limit=MAX_WORKER_RESPONSE_BYTES,
        kind="response",
    )
    return WorkerResponse.from_dict(payload)


def baseline_for_observations(
    observations: Sequence[WorkerObservation],
) -> bool | None:
    return _baseline_verdict(tuple(observations))


def _strict_test_parameters(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerProtocolError(
            "invalid_request",
            "worker test parameters must be a JSON object",
        )
    if set(value) - _TEST_PARAMETER_FIELDS:
        raise WorkerProtocolError(
            "invalid_request",
            "worker test parameters contain unsupported fields",
        )
    result: dict[str, Any] = {}
    if "include_symlink" in value:
        if not isinstance(value["include_symlink"], bool):
            raise WorkerProtocolError(
                "invalid_request",
                "include_symlink must be boolean",
            )
        result["include_symlink"] = value["include_symlink"]
    return result


def _baseline_verdict(
    observations: tuple[WorkerObservation, ...],
) -> bool | None:
    baseline = tuple(item for item in observations if item.baseline)
    if any(
        item.oracle_evaluated and item.oracle_passed is False
        for item in baseline
    ):
        return False
    if baseline and all(
        item.oracle_evaluated and item.oracle_passed is True
        for item in baseline
    ):
        return True
    return None


def _require_exact_fields(
    payload: Any,
    expected: set[str],
    kind: str,
    code: str,
) -> None:
    if not isinstance(payload, Mapping):
        raise WorkerProtocolError(code, f"{kind} must be a JSON object")
    if set(payload) != expected:
        raise WorkerProtocolError(
            code,
            f"{kind} fields do not match the protocol",
        )


def _require_pattern(
    value: Any,
    pattern: re.Pattern[str],
    *,
    code: str,
    message: str,
) -> str:
    if (
        not isinstance(value, str)
        or _contains_invalid_unicode(value)
        or not pattern.fullmatch(value)
    ):
        raise WorkerProtocolError(code, message)
    return value


def _require_tristate(value: Any, field_name: str) -> None:
    if value is not True and value is not False and value is not None:
        raise WorkerProtocolError(
            "malformed_response",
            f"{field_name} must be true, false, or null",
        )


def _strict_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise WorkerProtocolError(
            "malformed_response",
            f"{field_name} must be a string",
        )
    return value


def _strict_string_sequence(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise WorkerProtocolError(
            "malformed_response",
            f"{field_name} must be a list of strings",
        )
    return tuple(value)


def _strict_object_sequence(
    value: Any,
    field_name: str,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise WorkerProtocolError(
            "malformed_response",
            f"{field_name} must be a list of objects",
        )
    return tuple(value)


def _strict_tristate_object(value: Any, field_name: str) -> dict[str, bool | None]:
    if not isinstance(value, Mapping):
        raise WorkerProtocolError(
            "malformed_response",
            f"{field_name} must be an object",
        )
    result = dict(value)
    for item in result.values():
        _require_tristate(item, field_name)
    return result


def _json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerProtocolError(
            "malformed_response",
            "worker observation actual must be a JSON object",
        )
    try:
        encoded = _canonical_json_bytes(dict(value))
        decoded = _load_json_bytes(encoded, code="malformed_response")
    except (TypeError, ValueError, WorkerProtocolError) as exc:
        raise WorkerProtocolError(
            "malformed_response",
            "worker observation actual is not strict JSON",
        ) from exc
    if not isinstance(decoded, dict):
        raise WorkerProtocolError(
            "malformed_response",
            "worker observation actual must be a JSON object",
        )
    return decoded


def _bounded_strings(value: Any, *, code: str) -> tuple[str, ...]:
    result = unique_strings(value)
    if (
        len(result) > 32
        or any(
            len(item) > 512
            or _contains_invalid_unicode(item)
            or _contains_unsafe_control(item)
            for item in result
        )
    ):
        raise WorkerProtocolError(
            code,
            "worker string collection exceeds its bound",
        )
    return result


def _encode_message(
    payload: Mapping[str, Any],
    *,
    limit: int,
    kind: str,
) -> bytes:
    try:
        message = _canonical_json_bytes(dict(payload))
        _validate_json_shape(dict(payload), code=_kind_error_code(kind))
    except (TypeError, ValueError, WorkerProtocolError) as exc:
        if isinstance(exc, WorkerProtocolError):
            raise
        raise WorkerProtocolError(
            _kind_error_code(kind),
            f"worker {kind} is not strict JSON",
        ) from exc
    if len(message) > limit:
        code = "invalid_request" if kind == "request" else "response_too_large"
        raise WorkerProtocolError(
            code,
            f"worker {kind} exceeds the message size limit",
        )
    return message


def _decode_message(
    message: bytes,
    *,
    limit: int,
    kind: str,
) -> dict[str, Any]:
    code = _kind_error_code(kind)
    if not isinstance(message, bytes):
        raise WorkerProtocolError(code, f"worker {kind} must be bytes")
    if len(message) > limit:
        raise WorkerProtocolError(
            "invalid_request" if kind == "request" else "response_too_large",
            f"worker {kind} exceeds the message size limit",
        )
    payload = _load_json_bytes(message, code=code)
    if not isinstance(payload, dict):
        raise WorkerProtocolError(code, f"worker {kind} must be a JSON object")
    _validate_json_shape(payload, code=code)
    try:
        canonical = _canonical_json_bytes(payload)
    except (TypeError, ValueError) as exc:
        raise WorkerProtocolError(
            code,
            f"worker {kind} is not canonical JSON",
        ) from exc
    if canonical != message:
        raise WorkerProtocolError(
            code,
            f"worker {kind} is not canonical JSON",
        )
    return payload


def _load_json_bytes(message: bytes, *, code: str) -> Any:
    try:
        decoded = message.decode("utf-8", errors="strict")
        return json.loads(
            decoded,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise WorkerProtocolError(code, "worker message is not valid strict JSON") from exc


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_nonfinite(_value: str) -> None:
    raise ValueError("non-finite JSON number")


def _canonical_json_bytes(payload: Any) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _validate_json_shape(value: Any, *, code: str) -> None:
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 1)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
            raise WorkerProtocolError(code, "worker JSON structure exceeds its bound")
        if isinstance(current, str):
            if (
                len(current) > MAX_JSON_STRING_CHARS
                or _contains_invalid_unicode(current)
            ):
                raise WorkerProtocolError(code, "worker JSON string is invalid")
            continue
        if isinstance(current, Mapping):
            if len(current) > MAX_JSON_COLLECTION_LENGTH:
                raise WorkerProtocolError(
                    code,
                    "worker JSON object exceeds its field bound",
                )
            for key, item in current.items():
                if not isinstance(key, str):
                    raise WorkerProtocolError(code, "worker JSON key must be a string")
                stack.append((key, depth + 1))
                stack.append((item, depth + 1))
            continue
        if isinstance(current, (list, tuple)):
            if len(current) > MAX_JSON_COLLECTION_LENGTH:
                raise WorkerProtocolError(
                    code,
                    "worker JSON collection exceeds its length bound",
                )
            stack.extend((item, depth + 1) for item in current)
            continue
        if current is None or isinstance(current, (bool, int, float)):
            continue
        raise WorkerProtocolError(code, "worker JSON contains an unsupported value")


def _contains_invalid_unicode(value: str) -> bool:
    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


def _contains_unsafe_control(value: str) -> bool:
    return any(
        (
            ord(character) < 32
            and character not in "\n\t"
        )
        or 127 <= ord(character) < 160
        for character in value
    )


def _kind_error_code(kind: str) -> str:
    return "invalid_request" if kind == "request" else "malformed_response"


__all__ = [
    "MAX_JSON_COLLECTION_LENGTH",
    "MAX_JSON_DEPTH",
    "MAX_JSON_NODES",
    "MAX_JSON_STRING_CHARS",
    "MAX_WORKER_DIAGNOSTIC_CHARS",
    "MAX_WORKER_OBSERVATIONS",
    "MAX_WORKER_REQUEST_BYTES",
    "MAX_WORKER_RESPONSE_BYTES",
    "MAX_WORKER_TIMEOUT_MS",
    "MIN_WORKER_TIMEOUT_MS",
    "WORKER_ATTESTATION_SCHEMA_VERSION",
    "WORKER_DIAGNOSTICS_SCHEMA_VERSION",
    "WORKER_ERROR_CODES",
    "WORKER_REQUEST_SCHEMA_VERSION",
    "WORKER_RESPONSE_SCHEMA_VERSION",
    "WORKER_STATUSES",
    "WorkerAttestation",
    "WorkerCapabilityAttestation",
    "WorkerDiagnostics",
    "WorkerError",
    "WorkerObservation",
    "WorkerProtocolError",
    "WorkerRequest",
    "WorkerResponse",
    "baseline_for_observations",
    "decode_worker_request",
    "decode_worker_response",
    "encode_worker_request",
    "encode_worker_response",
    "unavailable_attestation",
]
