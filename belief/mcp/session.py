"""Per-session isolation for the BELIEF MCP dispatcher.

The stdio transport binds exactly one caller to one process, so a single
shared store was sufficient for it. Any transport that multiplexes several
callers over one :class:`~belief.mcp.server.BeliefMCPServer` needs more: run
identifiers are derived from analysed content, so two callers that scan the
same bytes produce the *same* ``run_id``. Without a session dimension one
caller would read, extend, and evict another caller's run.

Isolation here is structural rather than checked. Each session owns a separate
:class:`~belief.mcp.tools.BeliefMCPTools`, therefore a separate ``_RunStore``.
There is no shared mutable run state to forget a check on: a cross-session read
cannot resolve, because the other session's store is a different object.

Two reviewed bounds stay global rather than per session:

* the byte, run, and result capacities are *divided* by ``max_sessions``, so N
  sessions never exceed the single-process budget documented for one;
* the local validation semaphore is shared, so "one concurrent local
  validation" remains true for the process, not merely for each session.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable
from typing import Any

from .tools import BeliefMCPError, BeliefMCPTools
from .validation import (
    MCP_MAX_BYTES_PER_RUN,
    MCP_MAX_CONCURRENT_VALIDATIONS,
    MCP_MAX_RESULTS_PER_RUN,
    MCP_MAX_SESSIONS,
    MCP_MAX_STORED_RUNS,
    MCP_MAX_TOTAL_MEMORY_BYTES,
    MCP_MAX_TOTAL_RESULTS,
    MCP_MAX_TOTAL_STORE_BYTES,
)

DEFAULT_SESSION_ID = "default"

_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")

ToolsFactory = Callable[..., BeliefMCPTools]


def normalized_session_id(value: object) -> str:
    """Validate a caller-supplied session identifier.

    ``None`` selects the default session so that single-caller transports need
    no session vocabulary at all.
    """
    if value is None:
        return DEFAULT_SESSION_ID
    if not isinstance(value, str):
        raise BeliefMCPError("session id must be a string")
    if not _SESSION_ID.fullmatch(value):
        raise BeliefMCPError(
            "session id must be 1-64 characters from [A-Za-z0-9._:-] and "
            "start with a letter or digit"
        )
    return value


def session_capacity(max_sessions: int) -> dict[str, int]:
    """Split the reviewed global store budget across ``max_sessions``.

    A single session keeps the whole documented budget, which is what the stdio
    transport has always had.
    """
    if max_sessions < 1:
        raise ValueError("max_sessions must be at least 1")
    if max_sessions == 1:
        return {}
    store_bytes = MCP_MAX_TOTAL_STORE_BYTES // max_sessions
    # A single run may never be larger than the store that must hold it.
    bytes_per_run = min(MCP_MAX_BYTES_PER_RUN, store_bytes)
    return {
        "max_stored_runs": max(1, MCP_MAX_STORED_RUNS // max_sessions),
        "max_total_results": max(1, MCP_MAX_TOTAL_RESULTS // max_sessions),
        "max_results_per_run": max(
            1,
            min(
                MCP_MAX_RESULTS_PER_RUN,
                MCP_MAX_TOTAL_RESULTS // max_sessions,
            ),
        ),
        "max_bytes_per_run": bytes_per_run,
        "max_total_store_bytes": store_bytes,
        "max_total_memory_bytes": (
            MCP_MAX_TOTAL_MEMORY_BYTES // max_sessions
        ),
    }


class MCPSessionRegistry:
    """Owns one :class:`BeliefMCPTools` per caller session."""

    def __init__(
        self,
        factory: ToolsFactory,
        *,
        max_sessions: int = MCP_MAX_SESSIONS,
    ) -> None:
        if not 1 <= max_sessions <= MCP_MAX_SESSIONS:
            raise ValueError("max_sessions is outside the reviewed bound")
        self._factory = factory
        self._max_sessions = max_sessions
        self._capacity = session_capacity(max_sessions)
        self._validation_capacity = threading.BoundedSemaphore(
            MCP_MAX_CONCURRENT_VALIDATIONS
        )
        self._lock = threading.RLock()
        self._sessions: dict[str, BeliefMCPTools] = {}
        self._pinned = False
        # Build the default session eagerly so an invalid startup
        # configuration still fails at startup rather than at first tool call.
        self._sessions[DEFAULT_SESSION_ID] = self._build()

    @classmethod
    def pinned(cls, tools: BeliefMCPTools) -> MCPSessionRegistry:
        """Wrap one externally supplied tools instance as the only session.

        Used when a caller injects its own tools. A second session cannot be
        opened, because there is no factory able to build an isolated one, and
        silently sharing the injected instance would defeat the isolation this
        module exists to provide.
        """
        registry = cls.__new__(cls)
        registry._factory = None  # type: ignore[assignment]
        registry._max_sessions = 1
        registry._capacity = {}
        registry._validation_capacity = threading.BoundedSemaphore(
            MCP_MAX_CONCURRENT_VALIDATIONS
        )
        registry._lock = threading.RLock()
        registry._sessions = {DEFAULT_SESSION_ID: tools}
        registry._pinned = True
        return registry

    def _build(self) -> BeliefMCPTools:
        return self._factory(
            validation_capacity=self._validation_capacity,
            **self._capacity,
        )

    def resolve(self, session_id: object = None) -> BeliefMCPTools:
        """Return the tools instance owning ``session_id``, creating it once."""
        normalized = normalized_session_id(session_id)
        with self._lock:
            existing = self._sessions.get(normalized)
            if existing is not None:
                return existing
            if self._pinned:
                raise BeliefMCPError(
                    "this MCP dispatcher was built with an injected tools "
                    "instance and serves only the default session"
                )
            if len(self._sessions) >= self._max_sessions:
                raise BeliefMCPError(
                    "MCP session capacity reached; close an existing session "
                    f"before opening another (max {self._max_sessions})"
                )
            created = self._build()
            self._sessions[normalized] = created
            return created

    def close_session(self, session_id: object) -> bool:
        """Drop one session's retained state. The default session persists."""
        normalized = normalized_session_id(session_id)
        with self._lock:
            if normalized == DEFAULT_SESSION_ID:
                tools = self._sessions.get(normalized)
                if tools is not None:
                    tools.close()
                return False
            tools = self._sessions.pop(normalized, None)
        if tools is None:
            return False
        tools.close()
        return True

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions = {
                key: value
                for key, value in self._sessions.items()
                if key == DEFAULT_SESSION_ID
            }
        for tools in sessions:
            tools.close()

    def active_session_ids(self) -> list[str]:
        with self._lock:
            return sorted(self._sessions)

    def capacities(self) -> dict[str, Any]:
        with self._lock:
            active = len(self._sessions)
        return {
            "max_sessions": self._max_sessions,
            "active_sessions": active,
            "isolation": "per_session_store",
            "shared_validation_capacity": MCP_MAX_CONCURRENT_VALIDATIONS,
            "per_session_store_bounds": dict(self._capacity),
        }
