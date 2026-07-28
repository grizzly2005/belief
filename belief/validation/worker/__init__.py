"""Spawn-isolated execution for closed-registry local web fixtures."""

from .contracts import (
    MAX_WORKER_REQUEST_BYTES,
    MAX_WORKER_RESPONSE_BYTES,
    MAX_WORKER_TIMEOUT_MS,
    MIN_WORKER_TIMEOUT_MS,
    WORKER_REQUEST_SCHEMA_VERSION,
    WORKER_RESPONSE_SCHEMA_VERSION,
    WorkerCapabilityAttestation,
    WorkerError,
    WorkerObservation,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    decode_worker_request,
    decode_worker_response,
    encode_worker_request,
    encode_worker_response,
)
from .process import (
    ISOLATED_WEB_WORKER_ADAPTER,
    IsolatedWebValidationExecutor,
    build_isolated_web_context,
    run_isolated_web_validation_plan,
    run_worker_request,
)
from .registry import (
    registered_fixture_ids,
    registered_fixture_metadata,
)

__all__ = [
    "ISOLATED_WEB_WORKER_ADAPTER",
    "MAX_WORKER_REQUEST_BYTES",
    "MAX_WORKER_RESPONSE_BYTES",
    "MAX_WORKER_TIMEOUT_MS",
    "MIN_WORKER_TIMEOUT_MS",
    "WORKER_REQUEST_SCHEMA_VERSION",
    "WORKER_RESPONSE_SCHEMA_VERSION",
    "IsolatedWebValidationExecutor",
    "WorkerCapabilityAttestation",
    "WorkerError",
    "WorkerObservation",
    "WorkerProtocolError",
    "WorkerRequest",
    "WorkerResponse",
    "build_isolated_web_context",
    "decode_worker_request",
    "decode_worker_response",
    "encode_worker_request",
    "encode_worker_response",
    "registered_fixture_ids",
    "registered_fixture_metadata",
    "run_isolated_web_validation_plan",
    "run_worker_request",
]
