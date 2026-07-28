"""Fixed child-process entrypoint for registered web fixtures."""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import replace
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Iterator, Mapping

from .contracts import (
    MAX_WORKER_REQUEST_BYTES,
    WorkerCapabilityAttestation,
    WorkerError,
    WorkerProtocolError,
    WorkerRequest,
    WorkerResponse,
    baseline_for_observations,
    decode_worker_request,
    encode_worker_response,
)
from .registry import (
    OptionalWebDependencyUnavailable,
    get_fixture_spec,
)


_BLOCKED_CAPABILITIES = (
    "arbitrary_fixture_path",
    "caller_dynamic_import",
    "listener",
    "network",
    "shell",
    "subprocess",
)

_ERROR_MESSAGES = {
    "capability_denied": "a forbidden worker capability was requested",
    "fixture_execution_error": "the registered fixture failed deterministically",
    "invalid_request": "the worker request was rejected",
    "optional_dependency_unavailable": (
        "the optional web framework is unavailable"
    ),
    "unknown_fixture": "the fixture ID is not registered",
}


class WorkerCapabilityDenied(RuntimeError):
    """A guarded capability was attempted inside the worker."""

    def __init__(self, capability: str) -> None:
        super().__init__(f"worker capability denied: {capability}")
        self.capability = capability


def worker_entrypoint(connection: Connection) -> None:
    """Receive one bounded JSON request and return one bounded JSON response."""

    started = time.monotonic()
    try:
        raw_request = connection.recv_bytes(MAX_WORKER_REQUEST_BYTES)
        request = decode_worker_request(raw_request)
    except (EOFError, OSError, WorkerProtocolError):
        response = _invalid_request_response()
        _send_response(connection, response, started=started)
        connection.close()
        return

    try:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory(
            prefix="belief-isolated-web-worker-"
        ) as temporary:
            temporary_root = Path(temporary).resolve()
            _prepare_minimal_environment(temporary_root)
            try:
                os.chdir(temporary_root)
                with capability_guard():
                    response = execute_registered_request(
                        request,
                        temporary_root=temporary_root,
                    )
            finally:
                os.chdir(original_cwd)
    except WorkerCapabilityDenied:
        response = _failure_response(
            request,
            status="inconclusive",
            error_code="capability_denied",
            limitations=("forbidden_capability_attempted",),
            attested=True,
        )
    except Exception:
        response = _failure_response(
            request,
            status="inconclusive",
            error_code="fixture_execution_error",
            limitations=("fixture_execution_error",),
            attested=True,
        )
    _send_response(connection, response, started=started)
    connection.close()


def execute_registered_request(
    request: WorkerRequest,
    *,
    temporary_root: Path,
) -> WorkerResponse:
    """Run exactly one closed-registry fixture in the prepared child."""

    spec = get_fixture_spec(request.fixture_id)
    if spec is None:
        return _failure_response(
            request,
            status="unsupported",
            error_code="unknown_fixture",
            limitations=("unknown_fixture",),
            attested=True,
        )
    try:
        fixture_result = spec.runner(
            spec,
            temporary_root,
            request.test_parameters,
        )
    except OptionalWebDependencyUnavailable:
        return _failure_response(
            request,
            status="unsupported",
            error_code="optional_dependency_unavailable",
            limitations=(
                f"optional_dependency_unavailable:{spec.framework}",
            ),
            attested=True,
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
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status="completed",
        observations=observations,
        baseline=baseline_for_observations(observations),
        limitations=limitations,
        capabilities=_attestation(
            attested=True,
            framework_capability=fixture_result.capability_used,
        ),
    )


@contextmanager
def capability_guard() -> Iterator[None]:
    """Block ordinary network, listener, subprocess, and shell APIs.

    This is defense in depth for trusted built-in fixtures, not an operating
    system sandbox. The process still runs with the invoking user's authority.
    """

    def deny_network(*_args: Any, **_kwargs: Any) -> Any:
        raise WorkerCapabilityDenied("network")

    def deny_listener(*_args: Any, **_kwargs: Any) -> Any:
        raise WorkerCapabilityDenied("listener")

    def deny_subprocess(*_args: Any, **_kwargs: Any) -> Any:
        raise WorkerCapabilityDenied("subprocess")

    def deny_shell(*_args: Any, **_kwargs: Any) -> Any:
        raise WorkerCapabilityDenied("shell")

    patches: list[tuple[Any, str, Any]] = [
        (socket.socket, "connect", deny_network),
        (socket.socket, "connect_ex", deny_network),
        (socket.socket, "bind", deny_listener),
        (socket.socket, "listen", deny_listener),
        (socket.socket, "sendto", deny_network),
        (socket, "create_connection", deny_network),
        (socket, "getaddrinfo", deny_network),
        (subprocess, "Popen", deny_subprocess),
        (subprocess, "run", deny_subprocess),
        (subprocess, "call", deny_subprocess),
        (subprocess, "check_call", deny_subprocess),
        (subprocess, "check_output", deny_subprocess),
        (subprocess, "getoutput", deny_shell),
        (subprocess, "getstatusoutput", deny_shell),
        (os, "system", deny_shell),
        (os, "popen", deny_shell),
        (asyncio, "create_subprocess_exec", deny_subprocess),
        (asyncio, "create_subprocess_shell", deny_shell),
    ]
    if hasattr(socket.socket, "sendmsg"):
        patches.append((socket.socket, "sendmsg", deny_network))

    originals = [
        (owner, attribute, getattr(owner, attribute))
        for owner, attribute, _replacement in patches
    ]
    try:
        for owner, attribute, replacement in patches:
            setattr(owner, attribute, replacement)
        yield
    finally:
        for owner, attribute, original in reversed(originals):
            setattr(owner, attribute, original)


def _prepare_minimal_environment(temporary_root: Path) -> None:
    values = _minimal_environment_values(os.environ, temporary_root)
    os.environ.clear()
    os.environ.update(values)
    sys.dont_write_bytecode = True


def _minimal_environment_values(
    current: Mapping[str, str],
    temporary_root: Path,
) -> dict[str, str]:
    values = {
        "TMP": str(temporary_root),
        "TEMP": str(temporary_root),
        "TMPDIR": str(temporary_root),
        "BELIEF_VALIDATION_WORKER": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
    }
    for name in ("SYSTEMROOT", "WINDIR"):
        if current.get(name):
            values[name] = current[name]
    return values


def _failure_response(
    request: WorkerRequest,
    *,
    status: str,
    error_code: str,
    limitations: tuple[str, ...],
    attested: bool,
) -> WorkerResponse:
    return WorkerResponse(
        correlation_id=request.correlation_id,
        fixture_id=request.fixture_id,
        validation_plan_id=request.validation_plan_id,
        validation_plan_digest=request.validation_plan_digest,
        worker_status=status,
        baseline=None,
        limitations=limitations,
        errors=(
            WorkerError(
                code=error_code,
                message=_ERROR_MESSAGES[error_code],
            ),
        ),
        capabilities=_attestation(attested=attested),
    )


def _invalid_request_response() -> WorkerResponse:
    return WorkerResponse(
        correlation_id="invalid_request",
        fixture_id="invalid_request",
        validation_plan_id="vp_0000000000000000",
        validation_plan_digest="0" * 64,
        worker_status="invalid_request",
        baseline=None,
        limitations=("invalid_request",),
        errors=(
            WorkerError(
                code="invalid_request",
                message=_ERROR_MESSAGES["invalid_request"],
            ),
        ),
        capabilities=_attestation(attested=False),
    )


def _attestation(
    *,
    attested: bool,
    framework_capability: str = "",
) -> WorkerCapabilityAttestation:
    used = ["multiprocessing_spawn"]
    if attested:
        used.append("temporary_directory")
    if framework_capability:
        used.append(framework_capability)
    return WorkerCapabilityAttestation(
        status="attested" if attested else "unavailable",
        used=tuple(used),
        blocked=_BLOCKED_CAPABILITIES if attested else (),
    )


def _send_response(
    connection: Connection,
    response: WorkerResponse,
    *,
    started: float,
) -> None:
    duration_ms = min(
        int((time.monotonic() - started) * 1_000),
        35_000,
    )
    rendered = encode_worker_response(
        replace(response, duration_ms=duration_ms, evidence_digest="")
    )
    try:
        connection.send_bytes(rendered)
    except (BrokenPipeError, EOFError, OSError):
        return


__all__ = [
    "WorkerCapabilityDenied",
    "capability_guard",
    "execute_registered_request",
    "worker_entrypoint",
]
