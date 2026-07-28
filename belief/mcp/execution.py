"""Thread-safe request cancellation shared by MCP transport and tools."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from belief.validation.worker import WorkerRunHandle


class MCPRequestExecution:
    """One cancellable MCP request and its optional isolated-worker handle."""

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
        """Mark an active request cancelled and terminate its current worker."""

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


__all__ = ["MCPRequestExecution"]
