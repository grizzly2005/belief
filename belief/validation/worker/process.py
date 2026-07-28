"""Spawn-only parent controller and runner integration for web fixtures."""

from __future__ import annotations

import multiprocessing
import time
from collections.abc import Mapping
from typing import Any

from ..execution_models import (
    ValidationContractError,
    ValidationExecutionContext,
    ValidationExecutionSummary,
    ValidationObservation,
)
from ..executors.base import (
    LocalValidationExecutor,
    baseline_verdict,
    conclusive_safe_outcome,
    resolved_runtime_gaps,
    stable_limitations,
    validation_plan_digest,
)
from ..models import ValidationResult
from ..plan_models import ValidationPlan, canonical_digest
from .contracts import (
    MAX_WORKER_RESPONSE_BYTES,
    WorkerCapabilityAttestation,
    WorkerError,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    decode_worker_response,
    encode_worker_request,
)
from .entrypoint import worker_entrypoint
from .registry import get_fixture_spec


ISOLATED_WEB_WORKER_ADAPTER = "isolated_web_worker_v1"
_CONTEXT_CONFIG_FIELDS = {
    "correlation_id",
    "test_parameters",
    "timeout_ms",
}
_VALIDATION_TYPE = {
    "path_traversal_possible": "path_traversal",
    "idor_bola_possible": "idor_bola",
}
_PARENT_ERROR_MESSAGES = {
    "invalid_worker_response": "the worker returned an invalid response",
    "worker_crash": "the worker exited without valid evidence",
    "worker_start_failed": "the worker could not be started",
    "worker_timeout": "the worker exceeded its hard timeout",
}


def run_worker_request(request: WorkerRequest) -> WorkerResponse:
    """Execute one validated request in a hard-timeout spawn process."""

    message = encode_worker_request(request)
    context = _spawn_context()
    parent_connection, child_connection = context.Pipe(duplex=True)
    process = context.Process(
        target=worker_entrypoint,
        args=(child_connection,),
        name="belief-isolated-web-validation",
        daemon=True,
    )
    started = time.monotonic()
    try:
        process.start()
    except Exception:
        parent_connection.close()
        child_connection.close()
        return _parent_failure_response(
            request,
            status="crashed",
            error_code="worker_start_failed",
            duration_ms=_elapsed_ms(started),
        )
    child_connection.close()

    try:
        parent_connection.send_bytes(message)
    except (BrokenPipeError, EOFError, OSError):
        _terminate_process(process)
        parent_connection.close()
        return _parent_failure_response(
            request,
            status="crashed",
            error_code="worker_crash",
            duration_ms=_elapsed_ms(started),
        )

    deadline = started + (request.timeout_ms / 1_000)
    response_message: bytes | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            if parent_connection.poll(min(remaining, 0.05)):
                response_message = parent_connection.recv_bytes(
                    MAX_WORKER_RESPONSE_BYTES
                )
                break
        except (EOFError, OSError):
            break
        if process.exitcode is not None:
            break

    if response_message is None:
        remaining = max(0.0, deadline - time.monotonic())
        if process.is_alive() and remaining:
            process.join(timeout=remaining)
        if process.is_alive():
            _terminate_process(process)
            parent_connection.close()
            return _parent_failure_response(
                request,
                status="timed_out",
                error_code="worker_timeout",
                duration_ms=min(request.timeout_ms, _elapsed_ms(started)),
            )
        process.join(timeout=0.1)
        _close_process(process)
        parent_connection.close()
        return _parent_failure_response(
            request,
            status="crashed",
            error_code="worker_crash",
            duration_ms=_elapsed_ms(started),
        )

    process.join(timeout=0.5)
    exitcode = process.exitcode
    if process.is_alive():
        _terminate_process(process)
    _close_process(process)
    parent_connection.close()

    if response_message is None or exitcode not in {0, None}:
        return _parent_failure_response(
            request,
            status="crashed",
            error_code="worker_crash",
            duration_ms=_elapsed_ms(started),
        )
    try:
        response = decode_worker_response(response_message)
        _validate_response_binding(request, response)
    except WorkerProtocolError:
        return _parent_failure_response(
            request,
            status="inconclusive",
            error_code="invalid_worker_response",
            duration_ms=_elapsed_ms(started),
        )
    return response


def build_isolated_web_context(
    plan: ValidationPlan,
    *,
    fixture_id: str,
    source_revision: str,
    test_parameters: Mapping[str, Any] | None = None,
    timeout_ms: int = 5_000,
    correlation_id: str = "",
) -> ValidationExecutionContext:
    """Bind a canonical plan to one exact closed-registry fixture."""

    if not isinstance(plan, ValidationPlan):
        raise ValidationContractError(
            "isolated web validation requires a canonical ValidationPlan"
        )
    parameters = dict(test_parameters or {})
    correlation = correlation_id or (
        "corr_"
        + canonical_digest({
            "fixture_id": fixture_id,
            "plan_id": plan.plan_id,
            "source_revision": source_revision,
            "test_parameters": parameters,
            "timeout_ms": timeout_ms,
        })[:16]
    )
    request = WorkerRequest(
        fixture_id=fixture_id,
        validation_plan_id=plan.plan_id,
        validation_plan_digest=validation_plan_digest(plan),
        source_revision=source_revision,
        test_parameters=parameters,
        timeout_ms=timeout_ms,
        correlation_id=correlation,
    )
    return ValidationExecutionContext.for_plan(
        plan,
        fixture_id=request.fixture_id,
        adapter=ISOLATED_WEB_WORKER_ADAPTER,
        source_revision=request.source_revision,
        config={
            "correlation_id": request.correlation_id,
            "test_parameters": request.test_parameters,
            "timeout_ms": request.timeout_ms,
        },
    )


def run_isolated_web_validation_plan(
    plan: ValidationPlan,
    *,
    fixture_id: str,
    source_revision: str,
    test_parameters: Mapping[str, Any] | None = None,
    timeout_ms: int = 5_000,
    correlation_id: str = "",
) -> ValidationResult:
    """Run one registered web fixture through the existing BELIEF runner."""

    from ..runner import run_validation_plan

    context = build_isolated_web_context(
        plan,
        fixture_id=fixture_id,
        source_revision=source_revision,
        test_parameters=test_parameters,
        timeout_ms=timeout_ms,
        correlation_id=correlation_id,
    )
    executor = IsolatedWebValidationExecutor()
    return run_validation_plan(
        plan,
        context=context,
        executor_registry={plan.case_type: executor},
    )


class IsolatedWebValidationExecutor(LocalValidationExecutor):
    """Adapt a worker response into the existing execution summary."""

    validation_type = "isolated_web"
    case_types = frozenset(_VALIDATION_TYPE)

    def execute(
        self,
        plan: ValidationPlan,
        context: ValidationExecutionContext,
    ) -> ValidationExecutionSummary:
        plan_digest = validation_plan_digest(plan)
        validation_type = _VALIDATION_TYPE[plan.case_type]
        if context.adapter != ISOLATED_WEB_WORKER_ADAPTER:
            return _inconclusive_summary(
                plan,
                context,
                plan_digest=plan_digest,
                validation_type=validation_type,
                supported=False,
                limitation="invalid_worker_adapter",
            )
        spec = get_fixture_spec(context.fixture_id)
        if spec is not None and spec.case_type != plan.case_type:
            return _inconclusive_summary(
                plan,
                context,
                plan_digest=plan_digest,
                validation_type=validation_type,
                supported=False,
                limitation="fixture_case_type_mismatch",
            )
        options = _context_options(context.config)
        request = WorkerRequest(
            fixture_id=context.fixture_id,
            validation_plan_id=plan.plan_id,
            validation_plan_digest=plan_digest,
            source_revision=context.source_revision,
            test_parameters=options["test_parameters"],
            timeout_ms=options["timeout_ms"],
            correlation_id=options["correlation_id"],
        )
        response = run_worker_request(request)
        observations = tuple(
            ValidationObservation(
                validation_plan_id=plan.plan_id,
                subject_id=plan.subject_id,
                validation_type=validation_type,
                scenario=item.scenario,
                stimulus=item.stimulus,
                oracle=item.oracle,
                expected=item.expected,
                actual=item.actual,
                baseline=item.baseline,
                oracle_evaluated=item.oracle_evaluated,
                oracle_passed=item.oracle_passed,
                evidence=item.evidence,
                limitations=item.limitations,
                cost_units=item.cost_units,
            )
            for item in response.observations
        )
        baseline_passed = baseline_verdict(observations)
        executed = response.worker_status == "completed"
        security = tuple(
            observation
            for observation in observations
            if not observation.baseline
        )
        failed_security = tuple(
            observation
            for observation in security
            if observation.oracle_evaluated
            and observation.oracle_passed is False
        )
        mandatory_unevaluated = tuple(
            observation
            for observation in security
            if (
                observation.scenario != "symlink_boundary"
                and not observation.oracle_evaluated
            )
        )
        if executed and baseline_passed and failed_security:
            outcome = "bypassed"
        elif (
            executed
            and baseline_passed
            and security
            and not mandatory_unevaluated
        ):
            outcome = conclusive_safe_outcome(plan)
        else:
            outcome = "inconclusive"
        limitations = stable_limitations((
            *response.limitations,
            *(
                f"worker_error:{error.code}"
                for error in response.errors
            ),
            *(
                ()
                if response.worker_status == "completed"
                else (f"worker_status:{response.worker_status}",)
            ),
        ))
        unsupported_codes = {
            "optional_dependency_unavailable",
            "unknown_fixture",
        }
        supported = not any(
            error.code in unsupported_codes
            for error in response.errors
        )
        return ValidationExecutionSummary(
            validation_plan_id=plan.plan_id,
            validation_plan_digest=plan_digest,
            subject_id=plan.subject_id,
            validation_type=validation_type,
            source_revision=context.source_revision,
            fixture_id=context.fixture_id,
            fixture_digest=context.fixture_digest,
            adapter=context.adapter,
            supported=supported,
            executed=executed,
            outcome=outcome,
            baseline_passed=baseline_passed,
            observations=observations,
            resolved_evidence_gaps=resolved_runtime_gaps(
                plan,
                conclusive=outcome != "inconclusive",
            ),
            limitations=limitations,
            protected_regression=(
                outcome == "bypassed"
                and plan.case_status
                in {"protected", "false_positive_likely"}
            ),
        )


def _context_options(config: Mapping[str, Any]) -> dict[str, Any]:
    if set(config) != _CONTEXT_CONFIG_FIELDS:
        raise ValidationContractError(
            "isolated worker context fields are invalid"
        )
    try:
        request = WorkerRequest(
            fixture_id="validation_probe_fixture",
            validation_plan_id="vp_0000000000000000",
            validation_plan_digest="0" * 64,
            source_revision="validation-probe",
            test_parameters=config["test_parameters"],
            timeout_ms=config["timeout_ms"],
            correlation_id=config["correlation_id"],
        )
    except (KeyError, WorkerProtocolError) as exc:
        raise ValidationContractError(
            "isolated worker context options are invalid"
        ) from exc
    return {
        "correlation_id": request.correlation_id,
        "test_parameters": request.test_parameters,
        "timeout_ms": request.timeout_ms,
    }


def _validate_response_binding(
    request: WorkerRequest,
    response: WorkerResponse,
) -> None:
    expected = {
        "correlation_id": request.correlation_id,
        "fixture_id": request.fixture_id,
        "validation_plan_id": request.validation_plan_id,
        "validation_plan_digest": request.validation_plan_digest,
    }
    if any(
        getattr(response, field_name) != value
        for field_name, value in expected.items()
    ):
        raise WorkerProtocolError(
            "invalid_worker_response",
            "worker response binding mismatch",
        )


def _parent_failure_response(
    request: WorkerRequest,
    *,
    status: str,
    error_code: str,
    duration_ms: int,
) -> WorkerResponse:
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status=status,
        baseline=None,
        limitations=(error_code,),
        errors=(
            WorkerError(
                code=error_code,
                message=_PARENT_ERROR_MESSAGES[error_code],
            ),
        ),
        duration_ms=min(duration_ms, 35_000),
        capabilities=WorkerCapabilityAttestation(
            status="unavailable",
            used=("multiprocessing_spawn",),
        ),
    )


def _inconclusive_summary(
    plan: ValidationPlan,
    context: ValidationExecutionContext,
    *,
    plan_digest: str,
    validation_type: str,
    supported: bool,
    limitation: str,
) -> ValidationExecutionSummary:
    return ValidationExecutionSummary(
        validation_plan_id=plan.plan_id,
        validation_plan_digest=plan_digest,
        subject_id=plan.subject_id,
        validation_type=validation_type,
        source_revision=context.source_revision,
        fixture_id=context.fixture_id,
        fixture_digest=context.fixture_digest,
        adapter=context.adapter,
        supported=supported,
        executed=False,
        outcome="inconclusive",
        baseline_passed=None,
        limitations=(limitation,),
    )


def _spawn_context() -> multiprocessing.context.BaseContext:
    return multiprocessing.get_context("spawn")


def _terminate_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=1)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(timeout=1)
    _close_process(process)


def _close_process(process: multiprocessing.Process) -> None:
    try:
        process.close()
    except (ValueError, AttributeError):
        return


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


__all__ = [
    "ISOLATED_WEB_WORKER_ADAPTER",
    "IsolatedWebValidationExecutor",
    "build_isolated_web_context",
    "run_isolated_web_validation_plan",
    "run_worker_request",
]
