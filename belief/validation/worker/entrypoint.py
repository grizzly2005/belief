"""Trusted child execution imported only after bootstrap policy installation."""

from __future__ import annotations

import platform as platform_module
from contextlib import contextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Iterator

from .bootstrap import _minimal_environment_values, safe_platform_label
from .contracts import (
    WORKER_RESPONSE_SCHEMA_VERSION,
    WorkerAttestation,
    WorkerChildPolicyAttestation,
    WorkerDiagnostics,
    WorkerError,
    WorkerParentLifecycleAttestation,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    baseline_for_observations,
    decode_worker_request,
)
from .policies import (
    WorkerPolicyState,
    WorkerPolicyViolation,
    apply_resource_limits,
    filesystem_policy,
    preliminary_policy,
)
from .registry import (
    OptionalWebDependencyUnavailable,
    PreparedExecutionBundle,
    execution_bundle_identity,
    fixture_registry_digest,
    get_fixture_spec,
    load_fixture_runner,
    prepare_execution_bundle,
)


_ERROR_MESSAGES = {
    "invalid_request": "the worker request was rejected",
    "unsupported_protocol": "the worker protocol version is unsupported",
    "unknown_fixture": "the fixture ID is not registered",
    "binding_mismatch": "the worker response binding did not match its request",
    "dependency_unavailable": "the optional web framework is unavailable",
    "timeout": "the worker exceeded its hard timeout",
    "cancelled": "the worker request was cancelled",
    "child_crash": "the worker child exited without valid evidence",
    "malformed_response": "the worker returned a malformed response",
    "response_too_large": "the worker response exceeded its size bound",
    "policy_violation": "a fixture attempted a forbidden capability",
    "internal_error": "the registered fixture failed without conclusive evidence",
}


# Compatibility alias retained for callers of the original hardening branch.
WorkerCapabilityDenied = WorkerPolicyViolation


def execute_worker_message(
    raw_request: bytes,
    *,
    temporary_root: Path,
    cancellation_event: Any,
    state: WorkerPolicyState,
    execution_bundle_transport: Any,
) -> tuple[WorkerResponse, WorkerRequest | None]:
    """Decode, resolve, import, and execute one exact registered fixture."""

    try:
        request = decode_worker_request(raw_request)
    except WorkerProtocolError as exc:
        code = (
            "unsupported_protocol"
            if exc.code == "unsupported_protocol"
            else "invalid_request"
        )
        return bootstrap_failure_response(error_code=code, state=state), None

    spec = get_fixture_spec(request.fixture_id)
    if spec is None:
        return (
            _failure_response(
                request,
                status="unsupported",
                error_code="unknown_fixture",
                state=state,
            ),
            request,
        )
    if cancellation_event.is_set():
        return (
            _failure_response(
                request,
                status="cancelled",
                error_code="cancelled",
                state=state,
                cancellation_reason="parent cancellation requested",
            ),
            request,
        )

    try:
        bundle = PreparedExecutionBundle.from_transport(
            execution_bundle_transport
        )
    except (TypeError, ValueError):
        return (
            _failure_response(
                request,
                status="inconclusive",
                error_code="binding_mismatch",
                state=state,
                framework=spec.framework,
            ),
            request,
        )
    expected_identity = execution_bundle_identity(bundle)
    if any(
        getattr(request, field_name) != expected
        for field_name, expected in expected_identity.items()
    ):
        return (
            _failure_response(
                request,
                status="inconclusive",
                error_code="binding_mismatch",
                state=state,
                framework=spec.framework,
                bundle=bundle,
            ),
            request,
        )

    try:
        prepare_fixture = load_fixture_runner(spec, bundle)
    except OptionalWebDependencyUnavailable:
        return (
            _failure_response(
                request,
                status="unsupported",
                error_code="dependency_unavailable",
                state=state,
                framework=spec.framework,
                bundle=bundle,
                limitations=(f"dependency_unavailable:{spec.framework}",),
            ),
            request,
        )
    except Exception:
        return (
            _failure_response(
                request,
                status="inconclusive",
                error_code="internal_error",
                state=state,
                framework=spec.framework,
                bundle=bundle,
            ),
            request,
        )

    apply_resource_limits(state, timeout_ms=request.timeout_ms)
    try:
        with filesystem_policy(temporary_root, state):
            prepared_fixture = prepare_fixture(
                temporary_root,
                request.test_parameters,
            )
            fixture_result = (
                None
                if cancellation_event.is_set()
                else prepared_fixture()
            )
    except WorkerPolicyViolation:
        return (
            _failure_response(
                request,
                status="policy_violation",
                error_code="policy_violation",
                state=state,
                framework=spec.framework,
                bundle=bundle,
            ),
            request,
        )
    except Exception:
        return (
            _failure_response(
                request,
                status="inconclusive",
                error_code="internal_error",
                state=state,
                framework=spec.framework,
                bundle=bundle,
            ),
            request,
        )

    if cancellation_event.is_set() or fixture_result is None:
        return (
            _failure_response(
                request,
                status="cancelled",
                error_code="cancelled",
                state=state,
                framework=spec.framework,
                bundle=bundle,
                cancellation_reason="parent cancellation requested",
            ),
            request,
        )

    observations = fixture_result.observations
    limitations = tuple(dict.fromkeys(
        (
            *fixture_result.limitations,
            *(
                limitation
                for observation in observations
                for limitation in observation.limitations
            ),
        )
    ))
    attestation = _attestation(
        request,
        state=state,
        framework=spec.framework,
        bundle=bundle,
        limitations=limitations,
    )
    return (
        WorkerResponse(
            correlation_id=request.correlation_id,
            fixture_id=request.fixture_id,
            validation_plan_id=request.validation_plan_id,
            validation_plan_digest=request.validation_plan_digest,
            worker_status="completed",
            observations=observations,
            baseline=baseline_for_observations(observations),
            limitations=limitations,
            attestation=attestation,
        ),
        request,
    )


def bootstrap_failure_response(
    *,
    error_code: str,
    state: WorkerPolicyState,
    request: WorkerRequest | None = None,
) -> WorkerResponse:
    """Return a small normalized response when bootstrap cannot execute."""

    if request is None:
        request = WorkerRequest(
            fixture_id="invalid_request",
            validation_plan_id="vp_0000000000000000",
            validation_plan_digest="0" * 64,
            source_revision="invalid-request",
            fixture_registry_digest="0" * 64,
            fixture_source_digest="0" * 64,
            fixture_descriptor_digest="0" * 64,
            fixture_execution_bundle_digest="0" * 64,
            fixture_code_object_digest="0" * 64,
            correlation_id="invalid_request",
        )
    status = (
        "invalid_request"
        if error_code in {"invalid_request", "unsupported_protocol"}
        else "inconclusive"
    )
    return _failure_response(
        request,
        status=status,
        error_code=error_code,
        state=state,
    )


def _failure_response(
    request: WorkerRequest,
    *,
    status: str,
    error_code: str,
    state: WorkerPolicyState,
    framework: str = "",
    bundle: PreparedExecutionBundle | None = None,
    limitations: tuple[str, ...] = (),
    cancellation_reason: str = "",
) -> WorkerResponse:
    stable_limitations = tuple(dict.fromkeys((*limitations, error_code)))
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status=status,
        baseline=None,
        limitations=stable_limitations,
        errors=(
            WorkerError(
                code=error_code,
                message=_ERROR_MESSAGES[error_code],
            ),
        ),
        attestation=_attestation(
            request,
            state=state,
            framework=framework,
            bundle=bundle,
            limitations=stable_limitations,
        ),
        diagnostics=WorkerDiagnostics(
            summary=f"worker ended with {error_code}",
            cancellation_reason=cancellation_reason,
        ),
    )


def _attestation(
    request: WorkerRequest,
    *,
    state: WorkerPolicyState,
    framework: str,
    bundle: PreparedExecutionBundle | None = None,
    limitations: tuple[str, ...] = (),
) -> WorkerAttestation:
    spec = get_fixture_spec(request.fixture_id)
    registry_digest = fixture_registry_digest() if spec is not None else "0" * 64
    source_digest = bundle.source_digest if bundle is not None else "0" * 64
    return WorkerAttestation(
        protocol_version=WORKER_RESPONSE_SCHEMA_VERSION,
        fixture_id=request.fixture_id,
        fixture_registry_digest=registry_digest,
        fixture_source_digest=source_digest,
        fixture_descriptor_digest=(
            bundle.descriptor_digest
            if bundle is not None
            else "0" * 64
        ),
        fixture_execution_bundle_digest=(
            bundle.execution_bundle_digest
            if bundle is not None
            else "0" * 64
        ),
        fixture_code_object_digest=(
            bundle.code_object_digest
            if bundle is not None
            else "0" * 64
        ),
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        source_revision=request.source_revision,
        framework=framework,
        framework_version=_framework_version(framework),
        python_version=platform_module.python_version(),
        platform=safe_platform_label(),
        child_policy_attestation=WorkerChildPolicyAttestation(
            environment_policy_installed=state.environment_policy_installed,
            environment_secret_probe_passed=(
                state.environment_secret_probe_passed
            ),
            filesystem_policy_installed=state.filesystem_policy_installed,
            network_policy_installed=state.network_policy_installed,
            process_policy_installed=state.process_policy_installed,
            resource_limits=dict(state.resource_limits),
            io_policy_violations=tuple(state.io_policy_violations),
            limitations=tuple(state.limitations),
        ),
        parent_lifecycle_attestation=WorkerParentLifecycleAttestation(
            timeout_enforced=None,
            cleanup_completed=None,
        ),
        limitations=tuple(dict.fromkeys((*limitations, *state.limitations))),
    )


def _framework_version(framework: str) -> str:
    if not framework:
        return ""
    try:
        return version(framework)
    except PackageNotFoundError:
        return ""


@contextmanager
def capability_guard() -> Iterator[None]:
    """Compatibility context exposing the new preliminary policy."""

    state = WorkerPolicyState()
    with preliminary_policy(state):
        yield


def execute_registered_request(
    request: WorkerRequest,
    *,
    temporary_root: Path,
) -> WorkerResponse:
    """Compatibility helper for direct, non-resource-limited unit tests."""

    state = WorkerPolicyState(
        environment_policy_installed=True,
        environment_secret_probe_passed=True,
    )
    spec = get_fixture_spec(request.fixture_id)
    if spec is None:
        return _failure_response(
            request,
            status="unsupported",
            error_code="unknown_fixture",
            state=state,
        )
    bundle: PreparedExecutionBundle | None = None
    try:
        with preliminary_policy(state):
            bundle = PreparedExecutionBundle.from_transport(
                prepare_execution_bundle(spec).transport()
            )
            prepare_fixture = load_fixture_runner(spec, bundle)
            with filesystem_policy(temporary_root, state):
                prepared_fixture = prepare_fixture(
                    temporary_root,
                    request.test_parameters,
                )
                result = prepared_fixture()
    except OptionalWebDependencyUnavailable:
        return _failure_response(
            request,
            status="unsupported",
            error_code="dependency_unavailable",
            state=state,
            framework=spec.framework,
            bundle=bundle,
        )
    except WorkerPolicyViolation:
        return _failure_response(
            request,
            status="policy_violation",
            error_code="policy_violation",
            state=state,
            framework=spec.framework,
            bundle=bundle,
        )
    except Exception:
        return _failure_response(
            request,
            status="inconclusive",
            error_code="internal_error",
            state=state,
            framework=spec.framework,
            bundle=bundle,
        )
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status="completed",
        observations=result.observations,
        baseline=baseline_for_observations(result.observations),
        limitations=result.limitations,
        attestation=_attestation(
            request,
            state=state,
            framework=spec.framework,
            bundle=bundle,
            limitations=result.limitations,
        ),
    )


__all__ = [
    "WorkerCapabilityDenied",
    "_minimal_environment_values",
    "bootstrap_failure_response",
    "capability_guard",
    "execute_registered_request",
    "execute_worker_message",
]
