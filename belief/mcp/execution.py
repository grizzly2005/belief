"""Thread-safe request cancellation shared by MCP transport and tools."""

from __future__ import annotations

import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, TypeVar

if TYPE_CHECKING:
    from belief.validation.worker import WorkerRunHandle

_T = TypeVar("_T")


class MCPRequestCancelled(RuntimeError):
    """Raised when a cancelled request attempts to publish mutable state."""


class MCPRequestExecution:
    """Track cancellation; only a bound validation worker is actively stopped.

    Non-worker tools may continue internally after cancellation. The stdio
    runtime suppresses their eventual response but does not claim to interrupt
    their computation.
    """

    def __init__(self, request_id: object) -> None:
        self.request_id = request_id
        self._lock = threading.Lock()
        self._cancelled = threading.Event()
        self._completed = False
        self._reason = ""
        self._worker: WorkerRunHandle | None = None

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    @property
    def completed(self) -> bool:
        with self._lock:
            return self._completed

    def register_worker(self, worker: WorkerRunHandle) -> None:
        """Bind the current worker or cancel it immediately after an early notice."""

        cancel_now = False
        reason = ""
        with self._lock:
            if self._completed or self._cancelled.is_set():
                cancel_now = True
                reason = self._reason
            else:
                self._worker = worker
        if cancel_now:
            worker.cancel(reason or "MCP request cancelled")

    def release_worker(self, worker: WorkerRunHandle) -> None:
        with self._lock:
            if self._worker is worker:
                self._worker = None

    def cancel(self, reason: str = "") -> bool:
        """Mark a request cancelled and terminate only its current worker."""

        worker = None
        with self._lock:
            if self._completed or self._cancelled.is_set():
                return False
            self._reason = _bounded_reason(reason)
            self._cancelled.set()
            worker = self._worker
        if worker is not None:
            worker.cancel(self._reason or "MCP request cancelled")
        return True

    def commit_if_active(self, callback: Callable[[], _T]) -> _T:
        """Linearize one state mutation and request completion against cancel.

        The callback runs while the request-state lock is held. Cancellation
        therefore either wins first (and no mutation occurs) or the mutation
        and completion win together, making every later cancellation too late.
        """

        with self._lock:
            if self._completed or self._cancelled.is_set():
                raise MCPRequestCancelled(
                    self._reason or "MCP request cancelled"
                )
            result = callback()
            self._completed = True
            self._worker = None
            return result

    def mark_completed(self) -> bool:
        """Seal the request and return whether a cancellation won the race."""

        with self._lock:
            self._completed = True
            self._worker = None
            return self._cancelled.is_set()


def _bounded_reason(value: object) -> str:
    if not isinstance(value, str):
        return ""
    sanitized = "".join(
        character
        for character in value
        if character in "\t " or ord(character) >= 32
    )
    return " ".join(sanitized.split())[:256]


__all__ = ["MCPRequestCancelled", "MCPRequestExecution"]
