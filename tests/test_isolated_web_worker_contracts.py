"""Strict protocol and registry contracts for isolated web validation."""

from __future__ import annotations

import copy
import inspect
import json
from pathlib import Path

import pytest

from belief.validation.worker.contracts import (
    MAX_JSON_COLLECTION_LENGTH,
    MAX_JSON_DEPTH,
    MAX_JSON_STRING_CHARS,
    MAX_WORKER_REQUEST_BYTES,
    WORKER_REQUEST_SCHEMA_VERSION,
    WORKER_RESPONSE_SCHEMA_VERSION,
    WORKER_RESPONSE_V2_SCHEMA_VERSION,
    WorkerAttestation,
    WorkerDiagnostics,
    WorkerObservation,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    decode_worker_request,
    decode_worker_response,
    encode_worker_request,
    encode_worker_response,
)
from belief.validation.plan_models import canonical_digest
from belief.validation.worker.registry import (
    fixture_registry_digest,
    fixture_source_digest,
    fixture_source_documents,
    get_fixture_spec,
    load_fixture_runner,
    registered_fixture_ids,
    registered_fixture_metadata,
)


pytestmark = pytest.mark.security


def _request(**overrides):
    values = {
        "fixture_id": "fx_18a4e9_v1",
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
            oracle_role="functional_baseline",
            required_for_conclusion=True,
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
            oracle_role="primary_security",
            required_for_conclusion=True,
            oracle_evaluated=True,
            oracle_passed=True,
            evidence=("response_status:403",),
        ),
    )
    spec = get_fixture_spec(request.fixture_id)
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status="completed",
        observations=observations,
        baseline=True,
        duration_ms=12,
        attestation=WorkerAttestation(
            fixture_id=request.fixture_id,
            fixture_registry_digest=fixture_registry_digest(),
            fixture_source_digest=fixture_source_digest(spec),
            validation_plan_id=request.validation_plan_id,
            validation_plan_digest=request.validation_plan_digest,
            source_revision=request.source_revision,
            framework="flask",
            framework_version="3.1.3",
            python_version="3.12.0",
            platform="test-platform",
            environment_policy_installed=True,
            environment_secret_probe_passed=True,
            filesystem_policy_installed=True,
            network_policy_installed=True,
            process_policy_installed=True,
            timeout_enforced=True,
            cleanup_completed=True,
            resource_limits={
                "cpu": None,
                "open_files": None,
                "file_size": None,
                "child_processes": None,
            },
        ),
        diagnostics=WorkerDiagnostics(summary="bounded diagnostic"),
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
    assert len(restored.semantic_digest) == 64
    assert restored.semantic_digest == restored.evidence_digest
    assert len(restored.attestation_digest) == 64
    assert len(restored.response_digest) == 64

    tampered = copy.deepcopy(restored.to_dict())
    tampered["oracles"]["failed"] = 1
    with pytest.raises(WorkerProtocolError, match="oracle counts"):
        WorkerResponse.from_dict(tampered)


def test_registry_has_only_the_eight_stable_fixture_ids():
    assert registered_fixture_ids() == (
        "fx_01d7c2_v1",
        "fx_18a4e9_v1",
        "fx_2f6b10_v1",
        "fx_3c8d57_v1",
        "fx_47e1a3_v1",
        "fx_5b9c20_v1",
        "fx_6d04f8_v1",
        "fx_7a2e61_v1",
    )


def test_registry_metadata_is_a_defensive_callable_free_snapshot():
    first = registered_fixture_metadata()
    first[0]["fixture_id"] = "tampered"
    second = registered_fixture_metadata()

    assert second[0]["fixture_id"] != "tampered"
    assert all("runner" not in item for item in second)
    assert all("callable" not in item for item in second)
    assert all("expected_security_posture" not in item for item in second)
    assert all(len(item["fixture_source_digest"]) == 64 for item in second)


def test_opaque_fixture_sources_are_distinct_exact_and_label_free():
    digests = {}
    for fixture_id in registered_fixture_ids():
        spec = get_fixture_spec(fixture_id)
        documents = fixture_source_documents(spec)
        runner = load_fixture_runner(spec)
        implementation_name = f"web/fixtures/{spec.implementation_id}.py"
        runner_path = inspect.getsourcefile(runner)

        assert runner_path is not None
        assert Path(runner_path).name == f"{spec.implementation_id}.py"
        assert implementation_name in documents
        assert "worker/contracts.py" in documents
        assert f"web/{spec.framework}_adapter.py" in documents
        scanned_source = "\n".join(documents.values()).casefold()
        assert "vulnerable" not in scanned_source
        assert "protected" not in scanned_source
        assert documents[implementation_name] == (
            Path(runner_path)
            .read_text(encoding="utf-8")
            .replace("\r\n", "\n")
        )
        digests[fixture_id] = fixture_source_digest(spec)

    assert len(set(digests.values())) == len(digests)


def _canonical_bytes(payload):
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def test_request_rejects_duplicate_keys_and_noncanonical_json():
    canonical = encode_worker_request(_request())
    duplicate = canonical.replace(
        b'"timeout_ms":5000',
        b'"timeout_ms":5000,"timeout_ms":5000',
    )

    with pytest.raises(WorkerProtocolError) as duplicate_error:
        decode_worker_request(duplicate)
    assert duplicate_error.value.code == "invalid_request"

    with pytest.raises(WorkerProtocolError, match="canonical"):
        decode_worker_request(b" " + canonical)


@pytest.mark.parametrize("constant", (b"NaN", b"Infinity", b"-Infinity"))
def test_request_rejects_nonfinite_json_numbers(constant):
    message = encode_worker_request(_request()).replace(b"5000", constant, 1)

    with pytest.raises(WorkerProtocolError) as error:
        decode_worker_request(message)
    assert error.value.code == "invalid_request"


@pytest.mark.parametrize("timeout", (True, False, -1, 0, 30_001))
def test_request_rejects_boolean_negative_or_out_of_range_timeout(timeout):
    payload = _request().to_dict()
    payload["timeout_ms"] = timeout

    with pytest.raises(WorkerProtocolError):
        decode_worker_request(_canonical_bytes(payload))


def test_request_rejects_excessive_depth_collection_and_string_bounds():
    payload = _request().to_dict()
    nested = {}
    cursor = nested
    for _index in range(MAX_JSON_DEPTH + 1):
        cursor["x"] = {}
        cursor = cursor["x"]
    payload["unexpected"] = nested
    with pytest.raises(WorkerProtocolError, match="structure"):
        decode_worker_request(_canonical_bytes(payload))

    payload = _request().to_dict()
    payload["unexpected"] = list(range(MAX_JSON_COLLECTION_LENGTH + 1))
    with pytest.raises(WorkerProtocolError, match="collection"):
        decode_worker_request(_canonical_bytes(payload))

    payload = _request().to_dict()
    payload["unexpected"] = "x" * (MAX_JSON_STRING_CHARS + 1)
    with pytest.raises(WorkerProtocolError, match="string"):
        decode_worker_request(_canonical_bytes(payload))


def test_request_rejects_invalid_utf8_and_lone_surrogates():
    with pytest.raises(WorkerProtocolError):
        decode_worker_request(b"\xff")

    payload = _request().to_dict()
    payload["correlation_id"] = "\ud800"
    with pytest.raises(WorkerProtocolError):
        decode_worker_request(_canonical_bytes(payload))


def test_response_rejects_duplicate_keys_trailing_data_and_multiple_values():
    message = encode_worker_response(_response(_request()))
    duplicate = message.replace(
        b'"worker_status":"completed"',
        b'"worker_status":"completed","worker_status":"completed"',
    )
    for invalid in (duplicate, message + b"{}", message + b"\n"):
        with pytest.raises(WorkerProtocolError) as error:
            decode_worker_response(invalid)
        assert error.value.code == "malformed_response"


def test_semantic_digest_excludes_correlation_and_runtime_diagnostics():
    request = _request()
    first = _response(request)
    second = WorkerResponse(
        **{
            **first.__dict__,
            "correlation_id": "corr_other",
            "duration_ms": 999,
            "diagnostics": WorkerDiagnostics(
                summary="different runtime",
                child_exit_code=23,
            ),
            "evidence_digest": "",
            "attestation_digest": "",
            "response_digest": "",
            "semantic_digest": "",
        }
    )

    assert first.semantic_digest == second.semantic_digest
    assert first.attestation_digest == second.attestation_digest
    assert first.response_digest != second.response_digest


def test_v2_response_is_verified_then_migrated_and_never_rewritten_as_v2():
    current = _response(_request()).to_dict()
    legacy_observations = []
    for item in current["observations"]:
        legacy = dict(item)
        legacy.pop("oracle_role")
        legacy.pop("required_for_conclusion")
        legacy_observations.append(legacy)
    legacy_attestation = dict(current["attestation"])
    legacy_attestation["schema_version"] = (
        "belief.validation_worker_attestation.v2"
    )
    legacy_attestation["protocol_version"] = (
        WORKER_RESPONSE_V2_SCHEMA_VERSION
    )
    legacy = {
        key: value
        for key, value in current.items()
        if key not in {
            "evidence_digest",
            "attestation_digest",
            "response_digest",
        }
    }
    legacy["schema_version"] = WORKER_RESPONSE_V2_SCHEMA_VERSION
    legacy["observations"] = legacy_observations
    legacy["attestation"] = legacy_attestation
    legacy_semantic = {
        key: legacy[key]
        for key in (
            "schema_version",
            "fixture_id",
            "validation_plan_id",
            "validation_plan_digest",
            "worker_status",
            "observations",
            "baseline",
            "oracles",
            "limitations",
            "errors",
            "attestation",
        )
    }
    legacy["semantic_digest"] = canonical_digest(legacy_semantic)

    restored = decode_worker_response(_canonical_bytes(legacy))

    assert restored.schema_version == WORKER_RESPONSE_SCHEMA_VERSION
    assert restored.observations[0].oracle_role == "functional_baseline"
    assert restored.observations[1].oracle_role == "primary_security"
    assert (
        json.loads(encode_worker_response(restored))["schema_version"]
        == WORKER_RESPONSE_SCHEMA_VERSION
    )
