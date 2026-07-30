"""Inert standard-library bootstrap for the spawned validation child.

This module intentionally imports no BELIEF, framework, adapter, or other
third-party module at import time. The spawned interpreter enters
``worker_bootstrap`` before any of those imports occur.
"""

from __future__ import annotations

import io
import os
import re
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping


_BOOTSTRAP_REQUEST_LIMIT = 16 * 1024
_DIAGNOSTIC_LIMIT = 4_096
_WORKER_ROOT_PREFIX = "belief-isolated-web-worker-"
_WORKER_CHILD_ROOT_NAME = "child"
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(token|secret|password|credential|api[_-]?key)"
    r"\s*([:=])\s*([^\s,;]+)"
)
_TOKEN_SHAPE_RE = re.compile(
    r"(?i)\b(?:sk|ghp|github_pat|hf|xox[baprs])[-_][A-Za-z0-9_-]{6,}\b"
)
_SENSITIVE_ENVIRONMENT_MARKERS = (
    "TOKEN",
    "SECRET",
    "PASSWORD",
    "CREDENTIAL",
    "API_KEY",
)


class _BoundedTextCapture(io.TextIOBase):
    """Text sink that retains only a small prefix without growing unbounded."""

    def __init__(self, limit: int = _DIAGNOSTIC_LIMIT) -> None:
        super().__init__()
        self._limit = limit
        self._parts: list[str] = []
        self._retained = 0
        self.truncated = False

    @property
    def encoding(self) -> str:
        return "utf-8"

    def writable(self) -> bool:
        return True

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            value = str(value)
        available = self._limit - self._retained
        if available > 0:
            retained = value[:available]
            self._parts.append(retained)
            self._retained += len(retained)
        if len(value) > max(available, 0):
            self.truncated = True
        return len(value)

    def flush(self) -> None:
        return None

    def getvalue(self) -> str:
        return "".join(self._parts)


def worker_bootstrap(
    request_connection: Any,
    response_connection: Any,
    temporary_root: str,
    cancellation_event: Any,
) -> None:
    """Prepare the child boundary, execute one request, and send one response."""

    started = time.monotonic()
    stdout_capture = _BoundedTextCapture()
    stderr_capture = _BoundedTextCapture()
    response = None
    state = None
    request = None
    root: Path | None = None
    try:
        root = _validated_worker_root(temporary_root)
        _prepare_worker_directories(root)
        os.chdir(root)
        _prepare_minimal_environment(root)
        _redirect_native_output_to_null()
        sys.stdout = stdout_capture
        sys.stderr = stderr_capture
        sys.dont_write_bytecode = True

        from .policies import WorkerPolicyState, preliminary_policy

        state = WorkerPolicyState(
            environment_policy_installed=True,
            environment_secret_probe_passed=not _sensitive_environment_present(
                os.environ
            ),
        )
        with preliminary_policy(state):
            from .contracts import MAX_WORKER_REQUEST_BYTES
            from .entrypoint import (
                bootstrap_failure_response,
                execute_worker_message,
            )

            if MAX_WORKER_REQUEST_BYTES != _BOOTSTRAP_REQUEST_LIMIT:
                raise RuntimeError("worker request limit mismatch")
            try:
                raw_request = request_connection.recv_bytes(_BOOTSTRAP_REQUEST_LIMIT)
            except (EOFError, OSError):
                response = bootstrap_failure_response(
                    error_code="invalid_request",
                    state=state,
                )
            else:
                response, request = execute_worker_message(
                    raw_request,
                    temporary_root=root,
                    cancellation_event=cancellation_event,
                    state=state,
                )
    except BaseException:
        if state is not None:
            try:
                from .entrypoint import bootstrap_failure_response

                response = bootstrap_failure_response(
                    error_code="internal_error",
                    request=request,
                    state=state,
                )
            except BaseException:
                response = None
    finally:
        try:
            request_connection.close()
        except (AttributeError, OSError):
            pass

    if response is not None and state is not None:
        _send_single_response(
            response_connection,
            response,
            state=state,
            root=root,
            stdout_capture=stdout_capture,
            stderr_capture=stderr_capture,
            started=started,
        )
    try:
        response_connection.close()
    except (AttributeError, OSError):
        pass


def _send_single_response(
    connection: Any,
    response: Any,
    *,
    state: Any,
    root: Path | None,
    stdout_capture: _BoundedTextCapture,
    stderr_capture: _BoundedTextCapture,
    started: float,
) -> None:
    from .contracts import (
        MAX_WORKER_TIMEOUT_MS,
        WorkerDiagnostics,
        WorkerError,
        WorkerProtocolError,
        encode_worker_response,
    )

    stdout = sanitize_diagnostic(stdout_capture.getvalue(), temporary_root=root)
    stderr = sanitize_diagnostic(stderr_capture.getvalue(), temporary_root=root)
    attestation = replace(
        response.attestation,
        environment_policy_installed=state.environment_policy_installed,
        environment_secret_probe_passed=state.environment_secret_probe_passed,
        filesystem_policy_installed=state.filesystem_policy_installed,
        network_policy_installed=state.network_policy_installed,
        process_policy_installed=state.process_policy_installed,
        timeout_enforced=state.timeout_enforced,
        resource_limits=dict(state.resource_limits),
        io_policy_violations=tuple(state.io_policy_violations),
        limitations=tuple(
            dict.fromkeys((*response.attestation.limitations, *state.limitations))
        ),
    )
    diagnostics = WorkerDiagnostics(
        summary=response.diagnostics.summary,
        stdout=stdout,
        stderr=stderr,
        stdout_truncated=stdout_capture.truncated,
        stderr_truncated=stderr_capture.truncated,
        cancellation_reason=response.diagnostics.cancellation_reason,
    )
    finalized = replace(
        response,
        duration_ms=min(
            max(0, int((time.monotonic() - started) * 1_000)),
            MAX_WORKER_TIMEOUT_MS + 10_000,
        ),
        attestation=attestation,
        diagnostics=diagnostics,
        evidence_digest="",
        attestation_digest="",
        response_digest="",
        semantic_digest="",
    )
    try:
        message = encode_worker_response(finalized)
    except WorkerProtocolError as exc:
        error_code = (
            "response_too_large"
            if exc.code == "response_too_large"
            else "internal_error"
        )
        fallback = replace(
            finalized,
            worker_status="inconclusive",
            observations=(),
            baseline=None,
            limitations=(error_code,),
            errors=(
                WorkerError(
                    code=error_code,
                    message=(
                        "the child response exceeded its protocol bound"
                        if error_code == "response_too_large"
                        else "the child response could not be serialized"
                    ),
                ),
            ),
            diagnostics=replace(
                diagnostics,
                summary="child response serialization failed",
            ),
            evidence_digest="",
            attestation_digest="",
            response_digest="",
            semantic_digest="",
        )
        try:
            message = encode_worker_response(fallback)
        except WorkerProtocolError:
            return
    try:
        connection.send_bytes(message)
    except (BrokenPipeError, EOFError, OSError):
        return


def _validated_worker_root(value: str) -> Path:
    if not isinstance(value, str) or "\x00" in value:
        raise ValueError("invalid worker root")
    candidate = Path(value)
    container = candidate.parent
    if (
        not candidate.is_absolute()
        or candidate.name != _WORKER_CHILD_ROOT_NAME
        or not container.name.startswith(_WORKER_ROOT_PREFIX)
        or candidate.is_symlink()
        or container.is_symlink()
    ):
        raise ValueError("invalid worker root")
    resolved = candidate.resolve(strict=True)
    resolved_container = container.resolve(strict=True)
    temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    if (
        not resolved.is_dir()
        or resolved.parent != resolved_container
        or resolved_container.parent != temporary_parent
    ):
        raise ValueError("invalid worker root")
    return resolved


def _prepare_worker_directories(root: Path) -> None:
    for name in ("home", "config", "cache", "appdata", "localappdata", "tmp"):
        (root / name).mkdir(mode=0o700, exist_ok=False)


def _prepare_minimal_environment(temporary_root: Path) -> None:
    values = _minimal_environment_values(os.environ, temporary_root)
    os.environ.clear()
    os.environ.update(values)


def _minimal_environment_values(
    current: Mapping[str, str],
    temporary_root: Path,
) -> dict[str, str]:
    """Return the complete allowlisted runtime environment for the fixture."""

    values = {
        "HOME": str(temporary_root / "home"),
        "USERPROFILE": str(temporary_root / "home"),
        "APPDATA": str(temporary_root / "appdata"),
        "LOCALAPPDATA": str(temporary_root / "localappdata"),
        "XDG_CONFIG_HOME": str(temporary_root / "config"),
        "XDG_CACHE_HOME": str(temporary_root / "cache"),
        "TMP": str(temporary_root / "tmp"),
        "TEMP": str(temporary_root / "tmp"),
        "TMPDIR": str(temporary_root / "tmp"),
        "BELIEF_VALIDATION_WORKER": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    for name in ("SYSTEMROOT", "WINDIR"):
        value = current.get(name)
        if (
            isinstance(value, str)
            and value
            and len(value) <= 1_024
            and "\x00" not in value
        ):
            values[name] = value
    return values


def _sensitive_environment_present(environment: Mapping[str, str]) -> bool:
    for name in environment:
        upper = name.upper()
        if any(marker in upper for marker in _SENSITIVE_ENVIRONMENT_MARKERS):
            return True
        if upper.startswith(
            (
                "AWS_",
                "AZURE_",
                "GOOGLE_",
                "GITHUB_",
                "GH_",
                "OPENAI_",
                "ANTHROPIC_",
                "HF_",
                "HUGGINGFACE_",
                "DOCKER_",
            )
        ):
            return True
    return False


def safe_platform_label() -> str:
    """Return a bounded runtime label without invoking a platform subprocess."""

    raw_platform = sys.platform.casefold()
    if raw_platform.startswith("win"):
        system = "windows"
    elif raw_platform.startswith("linux"):
        system = "linux"
    elif raw_platform.startswith("darwin"):
        system = "darwin"
    else:
        system = re.sub(r"[^a-z0-9]+", "_", raw_platform).strip("_")
        system = system[:32] or "unknown"
    pointer_width = "64bit" if sys.maxsize > 2**32 else "32bit"
    return f"{system}-{pointer_width}"


def _redirect_native_output_to_null() -> None:
    try:
        null_fd = os.open(os.devnull, os.O_WRONLY)
    except OSError:
        return
    try:
        for descriptor in (1, 2):
            try:
                os.dup2(null_fd, descriptor)
            except OSError:
                pass
    finally:
        try:
            os.close(null_fd)
        except OSError:
            pass


def sanitize_diagnostic(
    value: str,
    *,
    temporary_root: Path | None,
) -> str:
    """Normalize, redact, and bound developer diagnostics."""

    text = value.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_ESCAPE_RE.sub("", text)
    text = _SECRET_ASSIGNMENT_RE.sub(r"\1\2[REDACTED]", text)
    text = _TOKEN_SHAPE_RE.sub("[REDACTED_TOKEN]", text)
    if temporary_root is not None:
        text = re.sub(
            re.escape(str(temporary_root)),
            "<worker_root>",
            text,
            flags=re.IGNORECASE if os.name == "nt" else 0,
        )
    normalized: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character in "\n\t" or codepoint >= 160 or 32 <= codepoint < 127:
            normalized.append(character)
        else:
            normalized.append("?")
    return "".join(normalized)[:_DIAGNOSTIC_LIMIT]


__all__ = [
    "_BoundedTextCapture",
    "_minimal_environment_values",
    "safe_platform_label",
    "sanitize_diagnostic",
    "worker_bootstrap",
]
