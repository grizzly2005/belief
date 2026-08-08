"""Dependency-free MCP stdio transport for BELIEF.

The transport implements the small JSON-RPC subset needed by MCP v0.2:
initialization, tool discovery/invocation, and resource discovery/reads.
All domain work is delegated to :mod:`belief.mcp.tools`.
"""

from __future__ import annotations

import json
import math
import os
import sys
import threading
from collections.abc import Mapping
from concurrent.futures import Future, ThreadPoolExecutor
from enum import Enum
from io import TextIOBase
from typing import Any

from .authorized_project import (
    AuthorizedProjectError,
    authorized_project_grant_from_environment,
)
from .contracts import (
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
    SERVER_INSTRUCTIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from .execution import MCPRequestExecution
from .session import (
    DEFAULT_SESSION_ID,
    MCPSessionRegistry,
)
from .tools import BeliefMCPError, BeliefMCPTools
from .validation import (
    MCP_MAX_IN_FLIGHT_REQUESTS,
    MCP_MAX_RESPONSE_BYTES,
)

_JSONRPC_VERSION = "2.0"
_MISSING = object()
_MAX_JSONRPC_LINE_CHARS = 1024 * 1024
_MAX_JSONRPC_LINE_BYTES = 1024 * 1024
_MAX_JSON_DEPTH = 12
_MAX_JSON_NODES = 4_096
_MAX_JSON_COLLECTION_LENGTH = 128
_MAX_JSON_STRING_LENGTH = 4_096
_MAX_REQUEST_ID_STRING_LENGTH = 256


class _MethodNotFound(LookupError):
    pass


class _DuplicateJSONKey(ValueError):
    pass


class MCPLifecycleState(str, Enum):
    NEW = "new"
    INITIALIZE_RESPONDED = "initialize_responded"
    READY = "ready"
    CLOSED = "closed"


class BeliefMCPServer:
    """MCP request dispatcher with transport-independent domain behavior."""

    def __init__(
        self,
        tools: BeliefMCPTools | None = None,
        *,
        max_sessions: int = 1,
    ) -> None:
        """Create a dispatcher.

        ``max_sessions`` defaults to 1: stdio binds one caller to one process,
        and a single session keeps the whole reviewed store budget. Only a
        transport that multiplexes several callers should raise it, and doing
        so divides that budget rather than multiplying it.
        """
        self._state_lock = threading.Lock()
        self._state = MCPLifecycleState.NEW
        if tools is not None:
            self._sessions = MCPSessionRegistry.pinned(tools)
            return
        try:
            grant = authorized_project_grant_from_environment(os.environ)
            publication_mode = os.environ.get(
                "BELIEF_MCP_PUBLICATION_MODE",
                "minimal",
            )
            allow_full_local_output = _strict_environment_flag(
                os.environ,
                "BELIEF_MCP_ALLOW_FULL_LOCAL_OUTPUT",
            )
            holdout_source_sha256_denylist = (
                _strict_digest_set_environment(
                    os.environ,
                    "BELIEF_MCP_HOLDOUT_SHA256_DENYLIST",
                )
            )
        except AuthorizedProjectError as exc:
            raise BeliefMCPError(
                "authorized project startup configuration is invalid"
            ) from exc
        except ValueError as exc:
            raise BeliefMCPError(
                "MCP publication startup configuration is invalid"
            ) from exc
        workspace_root = os.environ.get("BELIEF_MCP_WORKSPACE_ROOT")

        def build_session_tools(**capacity: Any) -> BeliefMCPTools:
            return BeliefMCPTools(
                workspace_root=workspace_root,
                authorized_project_grant=grant,
                publication_mode=publication_mode,
                allow_full_local_output=allow_full_local_output,
                holdout_source_sha256_denylist=(
                    holdout_source_sha256_denylist
                ),
                **capacity,
            )

        self._sessions = MCPSessionRegistry(
            build_session_tools,
            max_sessions=max_sessions,
        )

    @property
    def tools(self) -> BeliefMCPTools:
        """Tools owning the default session.

        Retained so single-session callers and the stdio transport keep the
        pre-session attribute access.
        """
        return self._sessions.resolve(DEFAULT_SESSION_ID)

    @property
    def sessions(self) -> MCPSessionRegistry:
        return self._sessions

    def handle(
        self,
        request: object,
        *,
        execution: MCPRequestExecution | None = None,
        session_id: object = None,
    ) -> dict[str, Any] | None:
        try:
            _validate_json_structure(request)
        except (RecursionError, ValueError):
            return _error(None, -32600, "Invalid Request")
        if not isinstance(request, dict):
            return _error(None, -32600, "Invalid Request")
        request_id = request.get("id", _MISSING)
        is_notification = request_id is _MISSING
        if not is_notification and _request_id_key(request_id) is None:
            return _error(None, -32600, "Invalid Request")
        if request.get("jsonrpc") != _JSONRPC_VERSION:
            return None if is_notification else _error(
                request_id, -32600, "Invalid Request"
            )
        method = request.get("method")
        if not isinstance(method, str) or not method:
            return None if is_notification else _error(
                request_id, -32600, "Invalid Request"
            )
        params = request.get("params", {})
        if not isinstance(params, dict):
            return None if is_notification else _error(
                request_id, -32602, "Invalid params"
            )

        if is_notification:
            self._handle_notification(method, params)
            return None
        lifecycle_error = self._request_lifecycle_error(method)
        if lifecycle_error is not None:
            return _error(request_id, -32002, lifecycle_error)
        try:
            result = self._dispatch(
                method,
                params,
                execution=execution,
                session_id=session_id,
            )
        except _MethodNotFound:
            return _error(request_id, -32601, "Method not found")
        except BeliefMCPError as exc:
            return _error(request_id, -32602, str(exc))
        except Exception:
            return _error(request_id, -32603, "Internal error")
        response = {
            "jsonrpc": _JSONRPC_VERSION,
            "id": request_id,
            "result": result,
        }
        if _serialized_json_size(response) > MCP_MAX_RESPONSE_BYTES:
            return _error(
                request_id,
                -32603,
                "Response exceeds server size bound",
            )
        return response

    def _dispatch(
        self,
        method: str,
        params: dict[str, Any],
        *,
        execution: MCPRequestExecution | None,
        session_id: object = None,
    ) -> dict[str, Any]:
        if method == "initialize":
            with self._state_lock:
                if self._state is not MCPLifecycleState.NEW:
                    raise BeliefMCPError("MCP initialize is only valid once")
                self._state = MCPLifecycleState.INITIALIZE_RESPONDED
            requested = params.get("protocolVersion")
            protocol = (
                requested
                if requested in SUPPORTED_PROTOCOL_VERSIONS
                else MCP_PROTOCOL_VERSION
            )
            return {
                "protocolVersion": protocol,
                "capabilities": {
                    "tools": {"listChanged": False},
                    "resources": {
                        "subscribe": False,
                        "listChanged": False,
                    },
                },
                "serverInfo": {
                    "name": MCP_SERVER_NAME,
                    "title": "BELIEF local AppSec evidence engine",
                    "version": MCP_SERVER_VERSION,
                    "description": (
                        "Fixture-bound local MCP facade over BELIEF services."
                    ),
                },
                "instructions": SERVER_INSTRUCTIONS,
            }
        if method == "ping":
            return {}
        # Tool and template definitions are static, so they never consume a
        # session slot. Everything below reaches session-owned state.
        if method == "tools/list":
            return {"tools": self.tools.list_tools()}
        if method == "resources/templates/list":
            return {
                "resourceTemplates": self.tools.list_resource_templates()
            }
        if method == "tools/call":
            return self._call_tool(
                params,
                execution=execution,
                tools=self._sessions.resolve(session_id),
            )
        if method == "resources/list":
            tools = self._sessions.resolve(session_id)
            return {"resources": tools.list_resources()}
        if method == "resources/read":
            return self._read_resource(
                params,
                tools=self._sessions.resolve(session_id),
            )
        raise _MethodNotFound(method)

    @property
    def lifecycle_state(self) -> MCPLifecycleState:
        with self._state_lock:
            return self._state

    def close(self) -> None:
        """Close the dispatcher and release process-local retained state."""

        with self._state_lock:
            if self._state is MCPLifecycleState.CLOSED:
                return
            self._state = MCPLifecycleState.CLOSED
        self._sessions.close_all()

    def _request_lifecycle_error(self, method: str) -> str | None:
        with self._state_lock:
            state = self._state
        if state is MCPLifecycleState.CLOSED:
            return "MCP server is closed"
        if method == "ping":
            return None
        if method == "initialize":
            return (
                None
                if state is MCPLifecycleState.NEW
                else "MCP initialize is only valid once"
            )
        if state is not MCPLifecycleState.READY:
            return (
                "MCP server is not ready; initialize and send "
                "notifications/initialized first"
            )
        return None

    def _handle_notification(
        self,
        method: str,
        params: Mapping[str, Any],
    ) -> None:
        del params
        if method != "notifications/initialized":
            return
        with self._state_lock:
            if self._state is MCPLifecycleState.INITIALIZE_RESPONDED:
                self._state = MCPLifecycleState.READY

    def _call_tool(
        self,
        params: Mapping[str, Any],
        *,
        execution: MCPRequestExecution | None,
        tools: BeliefMCPTools,
    ) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        publication = tools.publication_metadata(
            contains_untrusted_source_content=(
                tools.tool_contains_untrusted_source_content(name)
            )
        )
        try:
            payload = tools.call_tool(
                name,
                arguments,
                execution=execution,
            )
        except BeliefMCPError as exc:
            return {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
                "_meta": {"belief/publication": publication},
            }
        return {
            "content": [
                {
                    "type": "text",
                    "text": _json_text(payload),
                }
            ],
            "structuredContent": payload,
            "isError": False,
            "_meta": {"belief/publication": publication},
        }

    def _read_resource(
        self,
        params: Mapping[str, Any],
        *,
        tools: BeliefMCPTools,
    ) -> dict[str, Any]:
        if set(params) - {"uri", "_meta"}:
            raise BeliefMCPError("resources/read accepts only the uri parameter")
        if "uri" not in params:
            raise BeliefMCPError("resources/read requires uri")
        payload, mime_type = tools.read_resource(params["uri"])
        uri = params["uri"]
        contains_untrusted = (
            isinstance(uri, str) and uri.startswith("belief://runs/")
        )
        publication = tools.publication_metadata(
            contains_untrusted_source_content=contains_untrusted
        )
        return {
            "contents": [
                {
                    "uri": uri,
                    "mimeType": mime_type,
                    "text": _json_text(payload),
                    "_meta": {"belief/publication": publication},
                }
            ]
        }


class _StdioRuntime:
    """Bounded concurrent stdio runtime with best-effort cancellation."""

    def __init__(
        self,
        dispatcher: BeliefMCPServer,
        *,
        stdin: TextIOBase,
        stdout: TextIOBase,
    ) -> None:
        self._dispatcher = dispatcher
        self._stdin = stdin
        self._stdout = stdout
        self._executor = ThreadPoolExecutor(
            max_workers=MCP_MAX_IN_FLIGHT_REQUESTS,
            thread_name_prefix="belief-mcp-request",
        )
        self._capacity = threading.BoundedSemaphore(
            MCP_MAX_IN_FLIGHT_REQUESTS
        )
        self._active: dict[
            tuple[str, object],
            MCPRequestExecution,
        ] = {}
        self._active_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._closed = False

    def run(self) -> int:
        try:
            while True:
                raw_line = self._stdin.readline(
                    _MAX_JSONRPC_LINE_CHARS + 1
                )
                if raw_line == "":
                    break
                try:
                    raw_line_bytes = len(raw_line.encode("utf-8"))
                except UnicodeEncodeError:
                    self._write(_error(None, -32700, "Parse error"))
                    continue
                if (
                    len(raw_line) > _MAX_JSONRPC_LINE_CHARS
                    or raw_line_bytes > _MAX_JSONRPC_LINE_BYTES
                ):
                    self._discard_line_remainder(raw_line)
                    self._write(_error(None, -32700, "Parse error"))
                    continue
                if not raw_line.strip():
                    continue
                try:
                    request = _decode_request(raw_line)
                except (
                    json.JSONDecodeError,
                    UnicodeDecodeError,
                    _DuplicateJSONKey,
                    RecursionError,
                    UnicodeError,
                    ValueError,
                ):
                    self._write(_error(None, -32700, "Parse error"))
                    continue
                if self._handle_cancellation(request):
                    continue
                if _is_notification(request):
                    self._dispatcher.handle(request)
                    continue
                key = _request_key(request)
                if key is None:
                    response = self._dispatcher.handle(request)
                    if response is not None:
                        self._write(response)
                    continue
                if (
                    isinstance(request, dict)
                    and request.get("method") == "initialize"
                ):
                    response = self._dispatcher.handle(request)
                    if response is not None:
                        self._write(response)
                    continue
                self._submit(request, key)
        finally:
            self.shutdown()
        return 0

    def shutdown(self) -> None:
        if self._closed:
            return
        self._closed = True
        with self._active_lock:
            active = list(self._active.values())
        for execution in active:
            execution.cancel("MCP server shutdown")
        self._executor.shutdown(wait=True, cancel_futures=True)
        self._dispatcher.close()

    def _submit(
        self,
        request: dict[str, Any],
        key: tuple[str, object],
    ) -> None:
        request_id = request["id"]
        rejection: dict[str, Any] | None = None
        execution: MCPRequestExecution | None = None
        with self._active_lock:
            if key in self._active:
                rejection = _error(
                    request_id,
                    -32600,
                    "Duplicate active request id",
                )
            elif not self._capacity.acquire(blocking=False):
                rejection = _error(
                    request_id,
                    -32001,
                    "Server busy; retry after an in-flight request completes",
                )
            else:
                execution = MCPRequestExecution(request_id)
                self._active[key] = execution
        if rejection is not None:
            self._write(rejection)
            return
        if execution is None:
            self._write(_error(request_id, -32603, "Internal error"))
            return
        try:
            future = self._executor.submit(
                self._dispatcher.handle,
                request,
                execution=execution,
            )
        except Exception:
            with self._active_lock:
                self._active.pop(key, None)
                execution.mark_completed()
                self._capacity.release()
            self._write(_error(request_id, -32603, "Internal error"))
            return
        future.add_done_callback(
            lambda completed: self._complete(
                completed,
                key=key,
                execution=execution,
            )
        )

    def _complete(
        self,
        future: Future[dict[str, Any] | None],
        *,
        key: tuple[str, object],
        execution: MCPRequestExecution,
    ) -> None:
        try:
            response = future.result()
        except Exception:
            response = _error(
                execution.request_id,
                -32603,
                "Internal error",
            )
        with self._active_lock:
            current = self._active.get(key)
            if current is execution:
                self._active.pop(key, None)
            cancelled = execution.mark_completed()
            self._capacity.release()
        if not cancelled and response is not None:
            self._write(response)

    def _handle_cancellation(self, request: object) -> bool:
        if not isinstance(request, dict):
            return False
        if (
            request.get("jsonrpc") != _JSONRPC_VERSION
            or request.get("method") != "notifications/cancelled"
            or "id" in request
        ):
            return False
        params = request.get("params")
        if not isinstance(params, dict):
            return True
        if set(params) - {"requestId", "reason"}:
            return True
        key = _request_id_key(params.get("requestId", _MISSING))
        if key is None:
            return True
        reason = params.get("reason", "")
        if not isinstance(reason, str):
            reason = ""
        with self._active_lock:
            execution = self._active.get(key)
        if execution is not None:
            execution.cancel(reason)
        return True

    def _write(self, response: Mapping[str, Any]) -> None:
        try:
            rendered = json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (RecursionError, TypeError, ValueError):
            rendered = json.dumps(
                _error(None, -32603, "Internal error"),
                separators=(",", ":"),
            )
        try:
            rendered_size = len(rendered.encode("utf-8"))
        except UnicodeEncodeError:
            rendered = json.dumps(
                _error(None, -32603, "Internal error"),
                separators=(",", ":"),
            )
            rendered_size = len(rendered)
        if rendered_size > MCP_MAX_RESPONSE_BYTES:
            request_id = (
                response.get("id")
                if isinstance(response, Mapping)
                else None
            )
            rendered = json.dumps(
                _error(
                    request_id,
                    -32603,
                    "Response exceeds server size bound",
                ),
                separators=(",", ":"),
            )
        with self._write_lock:
            self._stdout.write(rendered + "\n")
            self._stdout.flush()

    def _discard_line_remainder(self, raw_line: str) -> None:
        if raw_line.endswith("\n"):
            return
        while True:
            remainder = self._stdin.readline(
                _MAX_JSONRPC_LINE_CHARS + 1
            )
            if remainder == "" or remainder.endswith("\n"):
                return


def serve_stdio(
    server: BeliefMCPServer | None = None,
    *,
    stdin: TextIOBase | None = None,
    stdout: TextIOBase | None = None,
) -> int:
    """Serve bounded newline-delimited MCP JSON-RPC until stdin reaches EOF."""

    runtime = _StdioRuntime(
        server or BeliefMCPServer(),
        stdin=stdin or sys.stdin,
        stdout=stdout or sys.stdout,
    )
    return runtime.run()


def _decode_request(raw_line: str) -> object:
    if (
        len(raw_line) > _MAX_JSONRPC_LINE_CHARS
        or len(raw_line.encode("utf-8")) > _MAX_JSONRPC_LINE_BYTES
    ):
        raise ValueError("JSON-RPC request exceeds byte bound")
    request = json.loads(
        raw_line,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_json_constant,
    )
    _validate_json_structure(request)
    return request


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number: {value}")


def _unique_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKey(key)
        result[key] = value
    return result


def _is_notification(request: object) -> bool:
    return isinstance(request, dict) and "id" not in request


def _request_key(
    request: object,
) -> tuple[str, object] | None:
    if (
        not isinstance(request, dict)
        or request.get("jsonrpc") != _JSONRPC_VERSION
        or not isinstance(request.get("method"), str)
        or not request.get("method")
        or "id" not in request
    ):
        return None
    return _request_id_key(request["id"])


def _request_id_key(value: object) -> tuple[str, object] | None:
    if value is None:
        return ("null", None)
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return ("integer", value)
    if isinstance(value, str):
        if len(value) > _MAX_REQUEST_ID_STRING_LENGTH:
            return None
        return ("string", value)
    return None


def _validate_json_structure(value: object) -> None:
    """Reject JSON-shaped data that exceeds the reviewed structural budget."""

    stack: list[tuple[object, int]] = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_JSON_NODES:
            raise ValueError("JSON node limit exceeded")
        if depth > _MAX_JSON_DEPTH:
            raise ValueError("JSON depth limit exceeded")
        if current is None or isinstance(current, (bool, int)):
            continue
        if isinstance(current, float):
            if not math.isfinite(current):
                raise ValueError("non-finite JSON number")
            continue
        if isinstance(current, str):
            if len(current) > _MAX_JSON_STRING_LENGTH:
                raise ValueError("JSON string limit exceeded")
            try:
                current.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("JSON string contains invalid Unicode") from exc
            continue
        if isinstance(current, list):
            if len(current) > _MAX_JSON_COLLECTION_LENGTH:
                raise ValueError("JSON collection limit exceeded")
            stack.extend((item, depth + 1) for item in reversed(current))
            continue
        if isinstance(current, dict):
            if len(current) > _MAX_JSON_COLLECTION_LENGTH:
                raise ValueError("JSON collection limit exceeded")
            for key, item in reversed(tuple(current.items())):
                if not isinstance(key, str):
                    raise ValueError("JSON object key must be a string")
                stack.append((item, depth + 1))
                stack.append((key, depth + 1))
            continue
        raise ValueError("value is not JSON compatible")


def _serialized_json_size(value: object) -> int:
    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (RecursionError, TypeError, ValueError):
        return MCP_MAX_RESPONSE_BYTES + 1
    try:
        return len(rendered.encode("utf-8"))
    except UnicodeEncodeError:
        return MCP_MAX_RESPONSE_BYTES + 1


def _strict_environment_flag(
    environment: Mapping[str, str],
    name: str,
) -> bool:
    value = environment.get(name)
    if value is None:
        return False
    normalized = value.strip().lower()
    if normalized == "true":
        return True
    if normalized == "false":
        return False
    raise ValueError(f"{name} must be exactly true or false")


def _strict_digest_set_environment(
    environment: Mapping[str, str],
    name: str,
) -> frozenset[str]:
    value = environment.get(name)
    if value is None or not value.strip():
        return frozenset()
    digests = frozenset(
        item.strip()
        for item in value.split(",")
        if item.strip()
    )
    for digest in digests:
        if (
            len(digest) != 64
            or any(
                character not in "0123456789abcdef"
                for character in digest
            )
        ):
            raise ValueError(
                f"{name} entries must be lowercase SHA-256 values"
            )
    return digests


def main() -> int:
    try:
        return serve_stdio()
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    except BeliefMCPError as exc:
        sys.stderr.write(f"BELIEF MCP startup error: {exc}\n")
        return 2


def _error(request_id: object, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": _JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _json_text(payload: Mapping[str, Any]) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BeliefMCPServer",
    "MCPLifecycleState",
    "main",
    "serve_stdio",
]
