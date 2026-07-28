"""Dependency-free MCP stdio transport for BELIEF.

The transport implements the small JSON-RPC subset needed by MCP v0.1:
initialization, tool discovery/invocation, and resource discovery/reads.
All domain work is delegated to :mod:`belief.mcp.tools`.
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import Any

from .contracts import (
    MCP_PROTOCOL_VERSION,
    MCP_SERVER_NAME,
    MCP_SERVER_VERSION,
    SERVER_INSTRUCTIONS,
    SUPPORTED_PROTOCOL_VERSIONS,
)
from .tools import BeliefMCPError, BeliefMCPTools

_JSONRPC_VERSION = "2.0"
_MISSING = object()


class _MethodNotFound(LookupError):
    pass


class BeliefMCPServer:
    """Synchronous MCP request dispatcher with no transport side effects."""

    def __init__(self, tools: BeliefMCPTools | None = None) -> None:
        self.tools = tools or BeliefMCPTools(
            workspace_root=os.environ.get("BELIEF_MCP_WORKSPACE_ROOT")
        )

    def handle(self, request: object) -> dict[str, Any] | None:
        if not isinstance(request, dict):
            return _error(None, -32600, "Invalid Request")
        request_id = request.get("id", _MISSING)
        is_notification = request_id is _MISSING
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
            return None
        try:
            result = self._dispatch(method, params)
        except _MethodNotFound:
            return _error(request_id, -32601, "Method not found")
        except BeliefMCPError as exc:
            return _error(request_id, -32602, str(exc))
        except Exception:
            return _error(request_id, -32603, "Internal error")
        return {
            "jsonrpc": _JSONRPC_VERSION,
            "id": request_id,
            "result": result,
        }

    def _dispatch(
        self,
        method: str,
        params: dict[str, Any],
    ) -> dict[str, Any]:
        if method == "initialize":
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
                        "Read-first MCP facade over BELIEF's existing local services."
                    ),
                },
                "instructions": SERVER_INSTRUCTIONS,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.tools.list_tools()}
        if method == "tools/call":
            return self._call_tool(params)
        if method == "resources/list":
            return {"resources": self.tools.list_resources()}
        if method == "resources/templates/list":
            return {
                "resourceTemplates": self.tools.list_resource_templates()
            }
        if method == "resources/read":
            return self._read_resource(params)
        raise _MethodNotFound(method)

    def _call_tool(self, params: Mapping[str, Any]) -> dict[str, Any]:
        name = params.get("name")
        arguments = params.get("arguments", {})
        try:
            payload = self.tools.call_tool(name, arguments)
        except BeliefMCPError as exc:
            return {
                "content": [{"type": "text", "text": str(exc)}],
                "isError": True,
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
        }

    def _read_resource(self, params: Mapping[str, Any]) -> dict[str, Any]:
        if set(params) - {"uri", "_meta"}:
            raise BeliefMCPError("resources/read accepts only the uri parameter")
        if "uri" not in params:
            raise BeliefMCPError("resources/read requires uri")
        payload, mime_type = self.tools.read_resource(params["uri"])
        return {
            "contents": [
                {
                    "uri": params["uri"],
                    "mimeType": mime_type,
                    "text": _json_text(payload),
                }
            ]
        }


def serve_stdio(server: BeliefMCPServer | None = None) -> int:
    """Serve newline-delimited MCP JSON-RPC until stdin reaches EOF."""

    dispatcher = server or BeliefMCPServer()
    for raw_line in sys.stdin:
        if not raw_line.strip():
            continue
        try:
            request = json.loads(raw_line)
        except (json.JSONDecodeError, UnicodeDecodeError):
            response = _error(None, -32700, "Parse error")
        else:
            response = dispatcher.handle(request)
        if response is None:
            continue
        sys.stdout.write(
            json.dumps(
                response,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        )
        sys.stdout.flush()
    return 0


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


__all__ = ["BeliefMCPServer", "main", "serve_stdio"]
