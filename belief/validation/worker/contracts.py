"""Strict JSON contracts for the isolated validation worker."""

from __future__ import annotations

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping, Sequence

from ..plan_models import canonical_digest, clean_text, unique_strings


WORKER_REQUEST_SCHEMA_VERSION = "belief.validation_worker_request.v1"
WORKER_RESPONSE_SCHEMA_VERSION = "belief.validation_worker_response.v1"

MAX_WORKER_REQUEST_BYTES = 16 * 1024
MAX_WORKER_RESPONSE_BYTES = 256 * 1024
MAX_WORKER_OBSERVATIONS = 32
MIN_WORKER_TIMEOUT_MS = 1
MAX_WORKER_TIMEOUT_MS = 30_000

WORKER_STATUSES = {
    "completed",
    "inconclusive",
    "unsupported",
    "invalid_request",
    "crashed",
    "timed_out",
}

_FIXTURE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{2,95}$")
_PLAN_ID_RE = re.compile(r"^vp_[0-9a-f]{16}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REVISION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+@-]{0,159}$")
_CORRELATION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,95}$")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

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
_CAPABILITY_FIELDS = {"status", "used", "blocked"}
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
    "capabilities",
    "evidence_digest",
}
_ORACLE_FIELDS = {"evaluated", "passed", "failed", "unevaluated"}


class WorkerProtocolError(ValueError):
    """Raised when a worker message violates its strict JSON contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


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
            code="invalid_fixture_id",
            message="fixture ID is invalid",
        )
        _require_pattern(
            self.validation_plan_id,
            _PLAN_ID_RE,
            code="invalid_plan_id",
            message="validation plan ID is invalid",
        )
        digest = _require_pattern(
            self.validation_plan_digest.lower(),
            _SHA256_RE,
            code="invalid_plan_digest",
            message="validation plan digest is invalid",
        )
        object.__setattr__(self, "validation_plan_digest", digest)
        _require_pattern(
            self.source_revision,
            _REVISION_RE,
            code="invalid_source_revision",
            message="source revision is invalid",
        )
        _require_pattern(
            self.correlation_id,
            _CORRELATION_RE,
            code="invalid_correlation_id",
            message="correlation ID is invalid",
        )
        if (
            not isinstance(self.timeout_ms, int)
            or isinstance(self.timeout_ms, bool)
            or not MIN_WORKER_TIMEOUT_MS
            <= self.timeout_ms
            <= MAX_WORKER_TIMEOUT_MS
        ):
            raise WorkerProtocolError(
                "invalid_timeout",
                "worker timeout is outside the allowed range",
            )
        parameters = _strict_test_parameters(self.test_parameters)
        object.__setattr__(self, "test_parameters", parameters)

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
        _require_exact_fields(payload, _REQUEST_FIELDS, "worker request")
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
                "noncanonical_request",
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
            if not value or len(value) > 512:
                raise WorkerProtocolError(
                    "invalid_observation",
                    f"worker observation {field_name} is invalid",
                )
            object.__setattr__(self, field_name, value)
        if not isinstance(self.baseline, bool):
            raise WorkerProtocolError(
                "invalid_observation",
                "worker observation baseline must be boolean",
            )
        if not isinstance(self.oracle_evaluated, bool):
            raise WorkerProtocolError(
                "invalid_observation",
                "worker observation oracle_evaluated must be boolean",
            )
        if self.oracle_passed not in {True, False, None}:
            raise WorkerProtocolError(
                "invalid_observation",
                "worker observation oracle_passed is invalid",
            )
        if self.oracle_passed is not None and not self.oracle_evaluated:
            raise WorkerProtocolError(
                "invalid_observation",
                "unevaluated worker oracle cannot have a verdict",
            )
        if (
            not isinstance(self.cost_units, int)
            or isinstance(self.cost_units, bool)
            or not 0 <= self.cost_units <= 100
        ):
            raise WorkerProtocolError(
                "invalid_observation",
                "worker observation cost is invalid",
            )
        object.__setattr__(self, "actual", _json_object(self.actual))
        object.__setattr__(self, "evidence", _bounded_strings(self.evidence))
        object.__setattr__(
            self,
            "limitations",
            _bounded_strings(self.limitations),
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
        _require_exact_fields(payload, _OBSERVATION_FIELDS, "worker observation")
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
            limitations=_strict_string_sequence(
                payload["limitations"],
                "limitations",
            ),
            cost_units=payload["cost_units"],
        )
        if observation.to_dict() != dict(payload):
            raise WorkerProtocolError(
                "noncanonical_response",
                "worker observation is not canonical",
            )
        return observation


@dataclass(frozen=True)
class WorkerError:
    """One normalized and stable worker error."""

    code: str
    message: str

    def __post_init__(self) -> None:
        _require_pattern(
            self.code,
            _ERROR_CODE_RE,
            code="invalid_error",
            message="worker error code is invalid",
        )
        message = clean_text(self.message)
        if not message or len(message) > 256:
            raise WorkerProtocolError(
                "invalid_error",
                "worker error message is invalid",
            )
        object.__setattr__(self, "message", message)

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerError":
        _require_exact_fields(payload, _ERROR_FIELDS, "worker error")
        return cls(
            code=_strict_string(payload["code"], "error code"),
            message=_strict_string(payload["message"], "error message"),
        )


@dataclass(frozen=True)
class WorkerCapabilityAttestation:
    """Bounded statement about guards and capabilities used by one run."""

    status: str
    used: tuple[str, ...] = ()
    blocked: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.status not in {"attested", "unavailable"}:
            raise WorkerProtocolError(
                "invalid_capabilities",
                "worker capability attestation status is invalid",
            )
        object.__setattr__(self, "used", _bounded_strings(self.used))
        object.__setattr__(self, "blocked", _bounded_strings(self.blocked))

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "used": list(self.used),
            "blocked": list(self.blocked),
        }

    @classmethod
    def from_dict(
        cls,
        payload: Mapping[str, Any],
    ) -> "WorkerCapabilityAttestation":
        _require_exact_fields(
            payload,
            _CAPABILITY_FIELDS,
            "worker capability attestation",
        )
        return cls(
            status=_strict_string(payload["status"], "capability status"),
            used=_strict_string_sequence(payload["used"], "capability used"),
            blocked=_strict_string_sequence(
                payload["blocked"],
                "capability blocked",
            ),
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
    capabilities: WorkerCapabilityAttestation = field(
        default_factory=lambda: WorkerCapabilityAttestation(
            status="unavailable"
        )
    )
    evidence_digest: str = ""
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
            code="invalid_correlation_id",
            message="correlation ID is invalid",
        )
        _require_pattern(
            self.fixture_id,
            _FIXTURE_ID_RE,
            code="invalid_fixture_id",
            message="fixture ID is invalid",
        )
        _require_pattern(
            self.validation_plan_id,
            _PLAN_ID_RE,
            code="invalid_plan_id",
            message="validation plan ID is invalid",
        )
        digest = _require_pattern(
            self.validation_plan_digest.lower(),
            _SHA256_RE,
            code="invalid_plan_digest",
            message="validation plan digest is invalid",
        )
        object.__setattr__(self, "validation_plan_digest", digest)
        if self.worker_status not in WORKER_STATUSES:
            raise WorkerProtocolError(
                "invalid_response",
                "worker status is invalid",
            )
        observations = tuple(self.observations)
        if (
            len(observations) > MAX_WORKER_OBSERVATIONS
            or any(
                not isinstance(item, WorkerObservation)
                for item in observations
            )
        ):
            raise WorkerProtocolError(
                "invalid_response",
                "worker observations are invalid",
            )
        object.__setattr__(self, "observations", observations)
        derived_baseline = _baseline_verdict(observations)
        if self.baseline not in {True, False, None}:
            raise WorkerProtocolError(
                "invalid_response",
                "worker baseline is invalid",
            )
        if self.baseline != derived_baseline:
            raise WorkerProtocolError(
                "invalid_response",
                "worker baseline does not match observations",
            )
        object.__setattr__(
            self,
            "limitations",
            _bounded_strings(self.limitations),
        )
        errors = tuple(self.errors)
        if len(errors) > 8 or any(
            not isinstance(item, WorkerError) for item in errors
        ):
            raise WorkerProtocolError(
                "invalid_response",
                "worker errors are invalid",
            )
        object.__setattr__(self, "errors", errors)
        if (
            not isinstance(self.duration_ms, int)
            or isinstance(self.duration_ms, bool)
            or not 0 <= self.duration_ms <= MAX_WORKER_TIMEOUT_MS + 5_000
        ):
            raise WorkerProtocolError(
                "invalid_response",
                "worker duration is invalid",
            )
        if not isinstance(
            self.capabilities,
            WorkerCapabilityAttestation,
        ):
            raise WorkerProtocolError(
                "invalid_response",
                "worker capability attestation is invalid",
            )
        expected_digest = canonical_digest(self._evidence_payload())
        supplied_digest = clean_text(self.evidence_digest).lower()
        if supplied_digest and supplied_digest != expected_digest:
            raise WorkerProtocolError(
                "invalid_response",
                "worker evidence digest mismatch",
            )
        object.__setattr__(self, "evidence_digest", expected_digest)

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

    def _evidence_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "correlation_id": self.correlation_id,
            "fixture_id": self.fixture_id,
            "validation_plan_id": self.validation_plan_id,
            "validation_plan_digest": self.validation_plan_digest,
            "worker_status": self.worker_status,
            "observations": [
                observation.to_dict()
                for observation in self.observations
            ],
            "baseline": self.baseline,
            "oracles": self.oracle_counts,
            "limitations": list(self.limitations),
            "errors": [error.to_dict() for error in self.errors],
            "capabilities": self.capabilities.to_dict(),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self._evidence_payload(),
            "duration_ms": self.duration_ms,
            "evidence_digest": self.evidence_digest,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "WorkerResponse":
        _require_exact_fields(payload, _RESPONSE_FIELDS, "worker response")
        _require_exact_fields(
            payload["oracles"],
            _ORACLE_FIELDS,
            "worker oracle counts",
        )
        response = cls(
            schema_version=_strict_string(
                payload["schema_version"],
                "response schema",
            ),
            correlation_id=_strict_string(
                payload["correlation_id"],
                "correlation ID",
            ),
            fixture_id=_strict_string(payload["fixture_id"], "fixture ID"),
            validation_plan_id=_strict_string(
                payload["validation_plan_id"],
                "validation plan ID",
            ),
            validation_plan_digest=_strict_string(
                payload["validation_plan_digest"],
                "validation plan digest",
            ),
            worker_status=_strict_string(
                payload["worker_status"],
                "worker status",
            ),
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
                for item in _strict_object_sequence(
                    payload["errors"],
                    "errors",
                )
            ),
            duration_ms=payload["duration_ms"],
            capabilities=WorkerCapabilityAttestation.from_dict(
                payload["capabilities"]
            ),
            evidence_digest=_strict_string(
                payload["evidence_digest"],
                "evidence digest",
            ),
        )
        if response.oracle_counts != dict(payload["oracles"]):
            raise WorkerProtocolError(
                "invalid_response",
                "worker oracle counts do not match observations",
            )
        if response.to_dict() != dict(payload):
            raise WorkerProtocolError(
                "noncanonical_response",
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
            "invalid_response",
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
            "invalid_test_parameters",
            "worker test parameters must be a JSON object",
        )
    if set(value) - _TEST_PARAMETER_FIELDS:
        raise WorkerProtocolError(
            "invalid_test_parameters",
            "worker test parameters contain unsupported fields",
        )
    result: dict[str, Any] = {}
    if "include_symlink" in value:
        if not isinstance(value["include_symlink"], bool):
            raise WorkerProtocolError(
                "invalid_test_parameters",
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
) -> None:
    if not isinstance(payload, Mapping):
        raise WorkerProtocolError(
            "invalid_message",
            f"{kind} must be a JSON object",
        )
    fields = set(payload)
    if fields != expected:
        raise WorkerProtocolError(
            "invalid_message",
            f"{kind} fields do not match the protocol",
        )


def _require_pattern(
    value: Any,
    pattern: re.Pattern[str],
    *,
    code: str,
    message: str,
) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise WorkerProtocolError(code, message)
    return value


def _strict_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise WorkerProtocolError(
            "invalid_message",
            f"{field_name} must be a string",
        )
    return value


def _strict_string_sequence(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in value
    ):
        raise WorkerProtocolError(
            "invalid_message",
            f"{field_name} must be a list of strings",
        )
    return tuple(value)


def _strict_object_sequence(
    value: Any,
    field_name: str,
) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, Mapping) for item in value
    ):
        raise WorkerProtocolError(
            "invalid_message",
            f"{field_name} must be a list of objects",
        )
    return tuple(value)


def _json_object(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise WorkerProtocolError(
            "invalid_observation",
            "worker observation actual must be a JSON object",
        )
    try:
        encoded = json.dumps(
            dict(value),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        decoded = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise WorkerProtocolError(
            "invalid_observation",
            "worker observation actual is not strict JSON",
        ) from exc
    if not isinstance(decoded, dict):
        raise WorkerProtocolError(
            "invalid_observation",
            "worker observation actual must be a JSON object",
        )
    return decoded


def _bounded_strings(value: Any) -> tuple[str, ...]:
    result = unique_strings(value)
    if len(result) > 32 or any(len(item) > 512 for item in result):
        raise WorkerProtocolError(
            "invalid_message",
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
        message = json.dumps(
            dict(payload),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise WorkerProtocolError(
            f"invalid_{kind}",
            f"worker {kind} is not strict JSON",
        ) from exc
    if len(message) > limit:
        raise WorkerProtocolError(
            "message_too_large",
            f"worker {kind} exceeds the message size limit",
        )
    return message


def _decode_message(
    message: bytes,
    *,
    limit: int,
    kind: str,
) -> dict[str, Any]:
    if not isinstance(message, bytes):
        raise WorkerProtocolError(
            f"invalid_{kind}",
            f"worker {kind} must be bytes",
        )
    if len(message) > limit:
        raise WorkerProtocolError(
            "message_too_large",
            f"worker {kind} exceeds the message size limit",
        )
    try:
        payload = json.loads(
            message.decode("utf-8"),
            parse_constant=lambda _value: (_ for _ in ()).throw(
                ValueError("non-finite JSON number")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise WorkerProtocolError(
            f"invalid_{kind}",
            f"worker {kind} is not valid strict JSON",
        ) from exc
    if not isinstance(payload, dict):
        raise WorkerProtocolError(
            f"invalid_{kind}",
            f"worker {kind} must be a JSON object",
        )
    return payload


__all__ = [
    "MAX_WORKER_OBSERVATIONS",
    "MAX_WORKER_REQUEST_BYTES",
    "MAX_WORKER_RESPONSE_BYTES",
    "MAX_WORKER_TIMEOUT_MS",
    "MIN_WORKER_TIMEOUT_MS",
    "WORKER_REQUEST_SCHEMA_VERSION",
    "WORKER_RESPONSE_SCHEMA_VERSION",
    "WORKER_STATUSES",
    "WorkerCapabilityAttestation",
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
]
