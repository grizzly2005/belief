"""Strict protocol and registry contracts for isolated web validation."""

from __future__ import annotations

import copy

import pytest

from belief.validation.worker.contracts import (
    MAX_WORKER_REQUEST_BYTES,
    WORKER_REQUEST_SCHEMA_VERSION,
    WorkerCapabilityAttestation,
    WorkerObservation,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    decode_worker_request,
    decode_worker_response,
    encode_worker_request,
    encode_worker_response,
)
from belief.validation.worker.registry import (
    registered_fixture_ids,
    registered_fixture_metadata,
)


pytestmark = pytest.mark.security


def _request(**overrides):
    values = {
        "fixture_id": "flask_path_traversal_protected_v1",
        "validation_plan_id": "vp_0123456789abcdef",
        "validation_plan_digest": "a" * 64,
        "source_revision": "fixture-source-v1",
        "test_parameters": {"include_symlink": True},
        "timeout_ms": 5_000,
        "correlation_id": "corr_contract",
    }
    values.update(overrides)
    return WorkerRequest(**values)


def _response(request: WorkerRequest) -> WorkerResponse:
    observations = (
        WorkerObservation(
            scenario="legitimate_path",
            stimulus="public.txt",
            oracle="functional_baseline",
            expected="The legitimate file is readable.",
            actual={"response_status": 200, "marker": "public"},
            baseline=True,
            oracle_evaluated=True,
            oracle_passed=True,
            evidence=("response_status:200",),
        ),
        WorkerObservation(
            scenario="parent_segment",
            stimulus="../outside/sentinel.txt",
            oracle="path_boundary_invariant",
            expected="The outside sentinel is not readable.",
            actual={"response_status": 403, "marker": "none"},
            baseline=False,
            oracle_evaluated=True,
            oracle_passed=True,
            evidence=("response_status:403",),
        ),
    )
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status="completed",
        observations=observations,
        baseline=True,
        duration_ms=12,
        capabilities=WorkerCapabilityAttestation(
            status="attested",
            used=("multiprocessing_spawn", "flask_test_client"),
            blocked=("network", "shell", "subprocess"),
        ),
    )


def test_request_round_trip_is_strict_canonical_json():
    request = _request()
    message = encode_worker_request(request)
    restored = decode_worker_request(message)

    assert restored == request
    assert restored.schema_version == WORKER_REQUEST_SCHEMA_VERSION
    assert len(message) <= MAX_WORKER_REQUEST_BYTES
    assert b"module" not in message
    assert b"callable" not in message
    assert b"command" not in message
    assert b"url" not in message
    assert b"port" not in message


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("module_path", "fixtures.path"),
        ("callable", "fixtures:run"),
        ("expression", "lambda: 1"),
        ("command", "python fixture.py"),
        ("url", "http://127.0.0.1/"),
        ("port", 8000),
        ("fixture_path", "fixtures/app.py"),
    ),
)
def test_request_rejects_every_unsupported_top_level_field(field, value):
    payload = _request().to_dict()
    payload[field] = value

    with pytest.raises(WorkerProtocolError, match="fields"):
        WorkerRequest.from_dict(payload)


@pytest.mark.parametrize(
    "parameters",
    (
        {"url": "http://127.0.0.1/"},
        {"port": 8000},
        {"fixture_path": "fixture.py"},
        {"module": "fixture"},
        {"include_symlink": "yes"},
    ),
)
def test_request_rejects_unbounded_or_unsafe_test_parameters(parameters):
    with pytest.raises(WorkerProtocolError):
        _request(test_parameters=parameters)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("validation_plan_id", "wrong"),
        ("validation_plan_digest", "g" * 64),
        ("source_revision", "../revision"),
        ("source_revision", r"C:\fixture"),
        ("timeout_ms", 0),
        ("timeout_ms", 30_001),
    ),
)
def test_request_rejects_invalid_binding_or_bounds(field, value):
    with pytest.raises(WorkerProtocolError):
        _request(**{field: value})


def test_request_rejects_oversized_payload_before_json_parsing():
    oversized = b"{" + (b"x" * MAX_WORKER_REQUEST_BYTES) + b"}"

    with pytest.raises(
        WorkerProtocolError,
        match="message size limit",
    ):
        decode_worker_request(oversized)


def test_response_round_trip_verifies_oracles_and_evidence_digest():
    request = _request()
    response = _response(request)
    restored = decode_worker_response(encode_worker_response(response))

    assert restored == response
    assert restored.baseline is True
    assert restored.oracle_counts == {
        "evaluated": 2,
        "passed": 2,
        "failed": 0,
        "unevaluated": 0,
    }
    assert len(restored.evidence_digest) == 64

    tampered = copy.deepcopy(restored.to_dict())
    tampered["oracles"]["failed"] = 1
    with pytest.raises(WorkerProtocolError, match="oracle counts"):
        WorkerResponse.from_dict(tampered)


def test_registry_has_only_the_eight_stable_fixture_ids():
    assert registered_fixture_ids() == (
        "fastapi_idor_protected_v1",
        "fastapi_idor_vulnerable_v1",
        "fastapi_path_traversal_protected_v1",
        "fastapi_path_traversal_vulnerable_v1",
        "flask_idor_protected_v1",
        "flask_idor_vulnerable_v1",
        "flask_path_traversal_protected_v1",
        "flask_path_traversal_vulnerable_v1",
    )


def test_registry_metadata_is_a_defensive_callable_free_snapshot():
    first = registered_fixture_metadata()
    first[0]["fixture_id"] = "tampered"
    second = registered_fixture_metadata()

    assert second[0]["fixture_id"] != "tampered"
    assert all("runner" not in item for item in second)
    assert all("callable" not in item for item in second)
