"""Spawn-only parent controller and runner integration for web fixtures."""

from __future__ import annotations

import multiprocessing
import os
import platform as platform_module
import re
import shutil
import tempfile
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
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
from .bootstrap import sanitize_diagnostic, worker_bootstrap
from .contracts import (
    MAX_WORKER_RESPONSE_BYTES,
    WorkerAttestation,
    WorkerDiagnostics,
    WorkerError,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    decode_worker_response,
    encode_worker_request,
)
from .registry import (
    fixture_registry_digest,
    fixture_source_digest,
    get_fixture_spec,
)


ISOLATED_WEB_WORKER_ADAPTER = "isolated_web_worker_v2"
_WORKER_ROOT_PREFIX = "belief-isolated-web-worker-"
_WORKER_ROOT_NAME_RE = re.compile(
    r"^belief-isolated-web-worker-[A-Za-z0-9_-]{4,64}$"
)
_OWNED_WORKER_ROOTS: set[str] = set()
_OWNED_WORKER_ROOTS_LOCK = threading.Lock()
_CANCEL_GRACE_SECONDS = 0.05
_POLL_INTERVAL_SECONDS = 0.02
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
    "binding_mismatch": "the worker response binding did not match its request",
    "cancelled": "the worker request was cancelled",
    "child_crash": "the worker child exited without valid evidence",
    "internal_error": "the worker controller could not complete execution",
    "malformed_response": "the worker returned a malformed response",
    "response_too_large": "the worker response exceeded its size bound",
    "timeout": "the worker exceeded its hard timeout",
}


class WorkerRunHandle:
    """One cancellable worker lifecycle with parent-owned cleanup state."""

    def __init__(self, request: WorkerRequest) -> None:
        if not isinstance(request, WorkerRequest):
            raise WorkerProtocolError(
                "invalid_request",
                "worker request object is invalid",
            )
        self.request = request
        self._message = encode_worker_request(request)
        self._context = _spawn_context()
        self._temporary_root = _create_worker_root()
        created_connections: list[Any] = []
        try:
            self._request_receive, self._request_send = self._context.Pipe(
                duplex=False
            )
            created_connections.extend((self._request_receive, self._request_send))
            self._response_receive, self._response_send = self._context.Pipe(
                duplex=False
            )
            created_connections.extend((self._response_receive, self._response_send))
            self._cancellation_event = self._context.Event()
            self._process = self._context.Process(
                target=worker_bootstrap,
                args=(
                    self._request_receive,
                    self._response_send,
                    str(self._temporary_root),
                    self._cancellation_event,
                ),
                name="belief-isolated-web-validation",
                daemon=True,
            )
        except Exception:
            for connection in created_connections:
                _close_connection(connection)
            _cleanup_worker_root(self._temporary_root)
            raise
        self._state_lock = threading.RLock()
        self._wait_lock = threading.Lock()
        self._process_lock = threading.Lock()
        self._started = False
        self._started_at = time.monotonic()
        self._done = False
        self._response: WorkerResponse | None = None
        self._cancellation_reason = ""

    @property
    def done(self) -> bool:
        with self._state_lock:
            return self._done

    @property
    def temporary_root(self) -> Path:
        """Expose the parent-owned root for lifecycle tests, not protocol output."""

        return self._temporary_root

    def start(self) -> "WorkerRunHandle":
        with self._state_lock:
            if self._done or self._started:
                return self
            if self._cancellation_event.is_set():
                self._response = self._finish_failure(
                    "cancelled",
                    status="cancelled",
                )
                return self
            self._started_at = time.monotonic()
            try:
                self._process.start()
            except Exception:
                self._response = self._finish_failure(
                    "child_crash",
                    status="crashed",
                )
                return self
            self._started = True
            _close_connection(self._request_receive)
            _close_connection(self._response_send)
            try:
                self._request_send.send_bytes(self._message)
            except (BrokenPipeError, EOFError, OSError):
                self._terminate()
                self._response = self._finish_failure(
                    "child_crash",
                    status="crashed",
                )
                return self
            finally:
                _close_connection(self._request_send)
        return self

    def cancel(self, reason: str = "") -> bool:
        """Request cooperative cancellation, then terminate an active child."""

        normalized = sanitize_diagnostic(reason, temporary_root=None)[:256]
        with self._state_lock:
            if self._done:
                return False
            self._cancellation_reason = normalized
            self._cancellation_event.set()
            started = self._started
        if started:
            with self._process_lock:
                self._process.join(timeout=_CANCEL_GRACE_SECONDS)
                if self._process.is_alive():
                    _terminate_process(self._process)
        return True

    def wait(self) -> WorkerResponse:
        """Wait for one response or a normalized terminal failure."""

        with self._wait_lock:
            return self._wait_once()

    def _wait_once(self) -> WorkerResponse:
        self.start()
        with self._state_lock:
            if self._response is not None:
                return self._response

        deadline = self._started_at + (self.request.timeout_ms / 1_000)
        response_message: bytes | None = None
        receive_error = ""
        while True:
            if self._cancellation_event.is_set():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                if self._response_receive.poll(
                    min(remaining, _POLL_INTERVAL_SECONDS)
                ):
                    try:
                        response_message = self._response_receive.recv_bytes(
                            MAX_WORKER_RESPONSE_BYTES
                        )
                    except OSError:
                        receive_error = "response_too_large"
                    except EOFError:
                        receive_error = "child_crash"
                    break
            except (OSError, ValueError):
                receive_error = "child_crash"
                break
            if self._process.exitcode is not None:
                break

        if self._cancellation_event.is_set():
            self._terminate()
            response = self._finish_failure("cancelled", status="cancelled")
        elif response_message is None and not receive_error:
            self._cancellation_event.set()
            with self._process_lock:
                self._process.join(timeout=_CANCEL_GRACE_SECONDS)
            if self._process.is_alive():
                self._terminate()
                response = self._finish_failure("timeout", status="timed_out")
            else:
                response = self._finish_failure("child_crash", status="crashed")
        elif receive_error:
            self._terminate()
            status = "inconclusive" if receive_error == "response_too_large" else "crashed"
            response = self._finish_failure(receive_error, status=status)
        else:
            response = self._consume_response(response_message, deadline=deadline)

        with self._state_lock:
            self._response = response
            return response

    def close(self) -> WorkerResponse:
        """Cancel if needed and synchronously release the complete lifecycle."""

        if not self.done:
            self.cancel("worker handle closed")
        return self.wait()

    def _consume_response(self, message: bytes, *, deadline: float) -> WorkerResponse:
        remaining = max(0.0, deadline - time.monotonic())
        with self._process_lock:
            self._process.join(timeout=remaining)
        if self._cancellation_event.is_set():
            self._terminate()
            return self._finish_failure("cancelled", status="cancelled")
        if self._process.is_alive():
            self._cancellation_event.set()
            self._terminate()
            return self._finish_failure("timeout", status="timed_out")
        exit_code = self._process.exitcode
        if exit_code != 0:
            return self._finish_failure("child_crash", status="crashed")
        if _has_additional_response(self._response_receive):
            return self._finish_failure(
                "malformed_response",
                status="inconclusive",
            )
        try:
            response = decode_worker_response(message)
            _validate_response_binding(self.request, response)
        except WorkerProtocolError as exc:
            code = (
                exc.code
                if exc.code in {"binding_mismatch", "response_too_large"}
                else "malformed_response"
            )
            return self._finish_failure(code, status="inconclusive")
        if self._cancellation_event.is_set():
            return self._finish_failure("cancelled", status="cancelled")
        return self._finish_response(response)

    def _terminate(self) -> None:
        if not self._started:
            return
        with self._process_lock:
            _terminate_process(self._process)

    def _finish_response(self, response: WorkerResponse) -> WorkerResponse:
        cleanup_completed, exit_code = self._release_resources()
        finalized = replace(
            response,
            attestation=replace(
                response.attestation,
                cleanup_completed=cleanup_completed,
            ),
            diagnostics=replace(
                response.diagnostics,
                child_exit_code=exit_code,
            ),
            semantic_digest="",
        )
        with self._state_lock:
            self._done = True
        return finalized

    def _finish_failure(self, error_code: str, *, status: str) -> WorkerResponse:
        cleanup_completed, exit_code = self._release_resources()
        response = _parent_failure_response(
            self.request,
            status=status,
            error_code=error_code,
            duration_ms=_elapsed_ms(self._started_at),
            cleanup_completed=cleanup_completed,
            child_exit_code=exit_code,
            cancellation_reason=self._cancellation_reason,
        )
        with self._state_lock:
            self._done = True
        return response

    def _release_resources(self) -> tuple[bool, int | None]:
        if self._started and self._process.is_alive():
            self._terminate()
        exit_code = self._process.exitcode if self._started else None
        for connection in (
            self._request_receive,
            self._request_send,
            self._response_receive,
            self._response_send,
        ):
            _close_connection(connection)
        if self._started:
            _close_process(self._process)
        cleanup_completed = _cleanup_worker_root(self._temporary_root)
        return cleanup_completed, exit_code


def start_worker_request(request: WorkerRequest) -> WorkerRunHandle:
    """Create a cancellable handle without starting it."""

    return WorkerRunHandle(request)


def run_worker_request(
    request: WorkerRequest,
    *,
    on_handle: Callable[[WorkerRunHandle], None] | None = None,
) -> WorkerResponse:
    """Execute one validated request in a hard-timeout spawn process."""

    try:
        handle = start_worker_request(request)
    except Exception:
        return _parent_failure_response(
            request,
            status="crashed",
            error_code="internal_error",
            duration_ms=0,
            cleanup_completed=None,
            child_exit_code=None,
        )
    if on_handle is not None:
        try:
            on_handle(handle)
        except Exception:
            handle.cancel("worker registration failed")
            return handle.wait()
    return handle.wait()


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
    on_handle: Callable[[WorkerRunHandle], None] | None = None,
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
    executor = IsolatedWebValidationExecutor(on_handle=on_handle)
    result = run_validation_plan(
        plan,
        context=context,
        executor_registry={plan.case_type: executor},
    )
    if executor.last_response is None:
        return result
    metadata = dict(result.metadata)
    metadata["isolated_worker"] = {
        "worker_status": executor.last_response.worker_status,
        "semantic_digest": executor.last_response.semantic_digest,
        "attestation": executor.last_response.attestation.to_dict(),
    }
    return replace(result, metadata=metadata)


class IsolatedWebValidationExecutor(LocalValidationExecutor):
    """Adapt a worker response into the existing execution summary."""

    validation_type = "isolated_web"
    case_types = frozenset(_VALIDATION_TYPE)

    def __init__(
        self,
        *,
        on_handle: Callable[[WorkerRunHandle], None] | None = None,
    ) -> None:
        self.on_handle = on_handle
        self.last_response: WorkerResponse | None = None

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
        response = run_worker_request(request, on_handle=self.on_handle)
        self.last_response = response
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
        security = tuple(item for item in observations if not item.baseline)
        failed_security = tuple(
            item
            for item in security
            if item.oracle_evaluated and item.oracle_passed is False
        )
        mandatory_unevaluated = tuple(
            item
            for item in security
            if item.scenario != "symlink_boundary" and not item.oracle_evaluated
        )
        if executed and baseline_passed and failed_security:
            outcome = "bypassed"
        elif executed and baseline_passed and security and not mandatory_unevaluated:
            outcome = conclusive_safe_outcome(plan)
        else:
            outcome = "inconclusive"
        limitations = stable_limitations((
            *response.limitations,
            *(f"worker_error:{error.code}" for error in response.errors),
            *(
                ()
                if response.worker_status == "completed"
                else (f"worker_status:{response.worker_status}",)
            ),
        ))
        unsupported_codes = {
            "dependency_unavailable",
            "unknown_fixture",
        }
        supported = not any(
            error.code in unsupported_codes for error in response.errors
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
                and plan.case_status in {"protected", "false_positive_likely"}
            ),
        )


def _context_options(config: Mapping[str, Any]) -> dict[str, Any]:
    if set(config) != _CONTEXT_CONFIG_FIELDS:
        raise ValidationContractError("isolated worker context fields are invalid")
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
            "binding_mismatch",
            "worker response envelope binding mismatch",
        )
    attestation_expected = {
        "fixture_id": request.fixture_id,
        "validation_plan_id": request.validation_plan_id,
        "validation_plan_digest": request.validation_plan_digest,
        "source_revision": request.source_revision,
    }
    if any(
        getattr(response.attestation, field_name) != value
        for field_name, value in attestation_expected.items()
    ):
        raise WorkerProtocolError(
            "binding_mismatch",
            "worker attestation binding mismatch",
        )
    spec = get_fixture_spec(request.fixture_id)
    if spec is None:
        return
    if (
        response.attestation.fixture_registry_digest != fixture_registry_digest()
        or response.attestation.fixture_source_digest != fixture_source_digest(spec)
        or response.attestation.framework != spec.framework
    ):
        raise WorkerProtocolError(
            "binding_mismatch",
            "worker fixture source binding mismatch",
        )


def _parent_failure_response(
    request: WorkerRequest,
    *,
    status: str,
    error_code: str,
    duration_ms: int,
    cleanup_completed: bool | None,
    child_exit_code: int | None,
    cancellation_reason: str = "",
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
        duration_ms=min(max(duration_ms, 0), 40_000),
        attestation=_parent_failure_attestation(
            request,
            cleanup_completed=cleanup_completed,
        ),
        diagnostics=WorkerDiagnostics(
            summary=f"parent controller ended with {error_code}",
            child_exit_code=child_exit_code,
            cancellation_reason=cancellation_reason,
        ),
    )


def _parent_failure_attestation(
    request: WorkerRequest,
    *,
    cleanup_completed: bool | None,
) -> WorkerAttestation:
    spec = get_fixture_spec(request.fixture_id)
    registry_digest = "0" * 64
    source_digest = "0" * 64
    framework = ""
    framework_version = ""
    if spec is not None:
        try:
            registry_digest = fixture_registry_digest()
            source_digest = fixture_source_digest(spec)
        except (OSError, UnicodeError, ValueError):
            pass
        framework = spec.framework
        try:
            framework_version = version(framework)
        except PackageNotFoundError:
            framework_version = ""
    return WorkerAttestation(
        fixture_id=request.fixture_id,
        fixture_registry_digest=registry_digest,
        fixture_source_digest=source_digest,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        source_revision=request.source_revision,
        framework=framework,
        framework_version=framework_version,
        python_version=platform_module.python_version(),
        platform=_platform_label(),
        environment_policy_installed=None,
        environment_secret_probe_passed=None,
        filesystem_policy_installed=None,
        network_policy_installed=None,
        process_policy_installed=None,
        timeout_enforced=True,
        cleanup_completed=cleanup_completed,
        resource_limits={
            "cpu": None,
            "open_files": None,
            "file_size": None,
            "child_processes": None,
        },
        limitations=("child_attestation_unavailable",),
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


def _create_worker_root() -> Path:
    created = Path(
        tempfile.mkdtemp(prefix=_WORKER_ROOT_PREFIX)
    ).resolve(strict=True)
    with _OWNED_WORKER_ROOTS_LOCK:
        _OWNED_WORKER_ROOTS.add(os.path.normcase(str(created)))
    return created


def _cleanup_worker_root(path: Path) -> bool:
    owned_key = os.path.normcase(str(path))
    try:
        temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
        temporary_parent_text = os.path.normcase(str(temporary_parent))
        candidate_text = os.path.normcase(os.path.abspath(path))
        if (
            os.path.commonpath([temporary_parent_text, candidate_text])
            != temporary_parent_text
        ):
            return False
        approved_path = Path(candidate_text)
        if approved_path.parent.resolve(strict=True) != temporary_parent:
            return False
        if _WORKER_ROOT_NAME_RE.fullmatch(approved_path.name) is None:
            return False
        with _OWNED_WORKER_ROOTS_LOCK:
            owned = owned_key in _OWNED_WORKER_ROOTS
        if not owned:
            return False
        if not approved_path.exists() and not approved_path.is_symlink():
            return True
        if approved_path.is_symlink():
            approved_path.unlink()
        else:
            if approved_path.resolve(strict=True) != approved_path:
                return False
            shutil.rmtree(approved_path)
        return not approved_path.exists()
    except (OSError, RuntimeError, ValueError):
        return False
    finally:
        with _OWNED_WORKER_ROOTS_LOCK:
            _OWNED_WORKER_ROOTS.discard(owned_key)


def _terminate_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(timeout=0.5)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(timeout=0.5)
    if process.is_alive():
        process.join(timeout=0.1)


def _close_process(process: multiprocessing.Process) -> None:
    try:
        process.close()
    except (ValueError, AttributeError):
        return


def _close_connection(connection: Any) -> None:
    try:
        connection.close()
    except (AttributeError, OSError):
        return


def _has_additional_response(connection: Any) -> bool:
    try:
        while connection.poll(0):
            try:
                connection.recv_bytes(MAX_WORKER_RESPONSE_BYTES)
            except EOFError:
                return False
            except OSError:
                return True
            else:
                return True
    except (OSError, ValueError):
        return False
    return False


def _platform_label() -> str:
    system = platform_module.system().lower() or "unknown"
    machine = platform_module.machine().lower() or "unknown"
    return f"{system}-{machine}".replace(" ", "_")


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.monotonic() - started) * 1_000))


__all__ = [
    "ISOLATED_WEB_WORKER_ADAPTER",
    "IsolatedWebValidationExecutor",
    "WorkerRunHandle",
    "build_isolated_web_context",
    "run_isolated_web_validation_plan",
    "run_worker_request",
    "start_worker_request",
]
