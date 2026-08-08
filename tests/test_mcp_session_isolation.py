"""Cross-session isolation contracts for the BELIEF MCP dispatcher.

Run identifiers are derived from analysed content, so two callers that scan
identical bytes obtain the same `run_id`. These tests pin the property that a
matching identifier is still not sufficient to reach another session's store.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from belief.mcp.server import BeliefMCPServer
from belief.mcp.session import (
    DEFAULT_SESSION_ID,
    MCPSessionRegistry,
    normalized_session_id,
    session_capacity,
)
from belief.mcp.tools import BeliefMCPError, BeliefMCPTools
from belief.mcp.validation import (
    MCP_MAX_SESSIONS,
    MCP_MAX_STORED_RUNS,
    MCP_MAX_TOTAL_MEMORY_BYTES,
    MCP_MAX_TOTAL_RESULTS,
    MCP_MAX_TOTAL_STORE_BYTES,
)

pytestmark = pytest.mark.security


def _write_vulnerable_app(root: Path, marker: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "app.py").write_text(
        f'''
from flask import Flask, request

app = Flask(__name__)

# {marker}
@app.get("/download")
def download():
    user_path = request.args["path"]
    return open(user_path).read()
'''.lstrip(),
        encoding="utf-8",
    )


def _ready_server(monkeypatch, root: Path, **kwargs) -> BeliefMCPServer:
    monkeypatch.setenv("BELIEF_MCP_WORKSPACE_ROOT", str(root))
    server = BeliefMCPServer(**kwargs)
    server.handle(
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
    )
    server.handle(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    return server


def _call(server, name, arguments, *, session_id=None, request_id=2):
    return server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        },
        session_id=session_id,
    )


def _read(server, uri, *, session_id=None, request_id=3):
    return server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "resources/read",
            "params": {"uri": uri},
        },
        session_id=session_id,
    )


def _scan(server, workspace: str, *, session_id=None) -> dict:
    response = _call(
        server,
        "belief_scan",
        {
            "workspace": workspace,
            "audit_mode": True,
            "reportability": True,
            "max_files": 20,
        },
        session_id=session_id,
    )
    assert response["result"]["isError"] is False, response
    return response["result"]["structuredContent"]


# --------------------------------------------------------------------------
# Identifier handling
# --------------------------------------------------------------------------


def test_absent_session_id_selects_the_default_session():
    assert normalized_session_id(None) == DEFAULT_SESSION_ID


@pytest.mark.parametrize(
    "value",
    ["", "-leading", "with space", "a" * 65, 7, b"agent", {"id": "a"}],
)
def test_malformed_session_ids_are_rejected(value):
    with pytest.raises(BeliefMCPError):
        normalized_session_id(value)


def test_well_formed_session_ids_are_accepted():
    for value in ("agent-1", "codex.session:42", "A", "0" * 64):
        assert normalized_session_id(value) == value


# --------------------------------------------------------------------------
# Store isolation
# --------------------------------------------------------------------------


def test_a_session_cannot_read_another_sessions_run(monkeypatch, tmp_path):
    _write_vulnerable_app(tmp_path / "alpha", "alpha")
    server = _ready_server(monkeypatch, tmp_path)

    summary = _scan(server, "alpha", session_id="agent-a")
    run_id = summary["run_id"]

    # The owning session reads its own run.
    owned = _read(server, f"belief://runs/{run_id}", session_id="agent-a")
    assert "error" not in owned, owned

    # A different session holding the exact identifier cannot.
    intruder = _read(server, f"belief://runs/{run_id}", session_id="agent-b")
    assert intruder["error"]["code"] == -32602
    assert run_id in intruder["error"]["message"]


def test_a_session_cannot_get_a_case_from_another_sessions_run(
    monkeypatch,
    tmp_path,
):
    _write_vulnerable_app(tmp_path / "alpha", "alpha")
    server = _ready_server(monkeypatch, tmp_path)

    summary = _scan(server, "alpha", session_id="agent-a")
    run_id = summary["run_id"]
    cases, _ = server.sessions.resolve("agent-a").read_resource(
        f"belief://runs/{run_id}/audit-cases"
    )
    case_id = cases["audit_cases"][0]["case_id"]

    response = _call(
        server,
        "belief_get_case",
        {"run_id": run_id, "case_id": case_id},
        session_id="agent-b",
    )

    assert response["result"]["isError"] is True


def test_identical_content_in_two_sessions_stays_separately_owned(
    monkeypatch,
    tmp_path,
):
    """Same bytes give the same run_id; the stores must still be distinct."""
    _write_vulnerable_app(tmp_path / "alpha", "shared")
    _write_vulnerable_app(tmp_path / "beta", "shared")
    server = _ready_server(monkeypatch, tmp_path)

    first = _scan(server, "alpha", session_id="agent-a")["run_id"]
    second = _scan(server, "alpha", session_id="agent-b")["run_id"]
    assert first == second

    # Dropping one session must not disturb the other.
    assert server.sessions.close_session("agent-b") is True
    still_there = _read(server, f"belief://runs/{first}", session_id="agent-a")
    assert "error" not in still_there, still_there


def test_resource_listings_are_scoped_to_the_calling_session(
    monkeypatch,
    tmp_path,
):
    _write_vulnerable_app(tmp_path / "alpha", "alpha")
    _write_vulnerable_app(tmp_path / "beta", "beta")
    server = _ready_server(monkeypatch, tmp_path)

    run_a = _scan(server, "alpha", session_id="agent-a")["run_id"]
    run_b = _scan(server, "beta", session_id="agent-b")["run_id"]
    assert run_a != run_b

    def _uris(session_id):
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "resources/list",
                "params": {},
            },
            session_id=session_id,
        )
        return {item["uri"] for item in response["result"]["resources"]}

    uris_a = _uris("agent-a")
    uris_b = _uris("agent-b")

    assert f"belief://runs/{run_a}" in uris_a
    assert f"belief://runs/{run_a}" not in uris_b
    assert f"belief://runs/{run_b}" in uris_b
    assert f"belief://runs/{run_b}" not in uris_a


def test_default_session_is_unchanged_when_no_session_id_is_given(
    monkeypatch,
    tmp_path,
):
    _write_vulnerable_app(tmp_path / "alpha", "alpha")
    server = _ready_server(monkeypatch, tmp_path)

    run_id = _scan(server, "alpha")["run_id"]

    assert "error" not in _read(server, f"belief://runs/{run_id}")
    assert server.sessions.active_session_ids() == [DEFAULT_SESSION_ID]


# --------------------------------------------------------------------------
# Capacity and lifecycle
# --------------------------------------------------------------------------


def test_session_capacity_is_enforced(monkeypatch, tmp_path):
    _write_vulnerable_app(tmp_path / "alpha", "alpha")
    server = _ready_server(monkeypatch, tmp_path, max_sessions=2)

    server.sessions.resolve("agent-a")
    with pytest.raises(BeliefMCPError, match="session capacity"):
        server.sessions.resolve("agent-b")

    # Freeing a slot makes room again.
    assert server.sessions.close_session("agent-a") is True
    server.sessions.resolve("agent-b")


def test_injected_tools_serve_only_the_default_session(tmp_path):
    server = BeliefMCPServer(BeliefMCPTools(workspace_root=tmp_path))

    assert server.sessions.resolve() is server.tools
    with pytest.raises(BeliefMCPError, match="only the default session"):
        server.sessions.resolve("agent-a")


def test_closing_the_server_clears_every_session(monkeypatch, tmp_path):
    _write_vulnerable_app(tmp_path / "alpha", "alpha")
    server = _ready_server(monkeypatch, tmp_path)

    run_id = _scan(server, "alpha", session_id="agent-a")["run_id"]
    tools = server.sessions.resolve("agent-a")
    server.close()

    with pytest.raises(BeliefMCPError):
        tools.read_resource(f"belief://runs/{run_id}")


def test_the_default_session_cannot_be_closed_away(monkeypatch, tmp_path):
    server = _ready_server(monkeypatch, tmp_path)

    assert server.sessions.close_session(DEFAULT_SESSION_ID) is False
    assert DEFAULT_SESSION_ID in server.sessions.active_session_ids()


def test_closing_an_unknown_session_is_not_an_error(monkeypatch, tmp_path):
    server = _ready_server(monkeypatch, tmp_path)

    assert server.sessions.close_session("never-opened") is False


# --------------------------------------------------------------------------
# Budget arithmetic
# --------------------------------------------------------------------------


def test_a_single_session_keeps_the_whole_documented_budget():
    assert session_capacity(1) == {}


@pytest.mark.parametrize("max_sessions", range(1, MCP_MAX_SESSIONS + 1))
def test_sessions_never_exceed_the_global_store_budget(max_sessions):
    """N isolated stores must not cost more than the reviewed single budget."""
    capacity = session_capacity(max_sessions)
    if not capacity:
        return

    assert (
        capacity["max_total_memory_bytes"] * max_sessions
        <= MCP_MAX_TOTAL_MEMORY_BYTES
    )
    assert (
        capacity["max_total_store_bytes"] * max_sessions
        <= MCP_MAX_TOTAL_STORE_BYTES
    )
    assert capacity["max_stored_runs"] * max_sessions <= MCP_MAX_STORED_RUNS
    assert (
        capacity["max_total_results"] * max_sessions <= MCP_MAX_TOTAL_RESULTS
    )
    # A run can never be larger than the store expected to hold it.
    assert capacity["max_bytes_per_run"] <= capacity["max_total_store_bytes"]


@pytest.mark.parametrize("max_sessions", range(1, MCP_MAX_SESSIONS + 1))
def test_every_supported_session_count_builds_a_usable_store(
    tmp_path,
    max_sessions,
):
    """The default session occupies one slot, so N-1 named ones remain."""
    registry = MCPSessionRegistry(
        lambda **capacity: BeliefMCPTools(
            workspace_root=tmp_path,
            **capacity,
        ),
        max_sessions=max_sessions,
    )

    for index in range(max_sessions - 1):
        registry.resolve(f"agent-{index}")

    assert len(registry.active_session_ids()) == max_sessions
    with pytest.raises(BeliefMCPError, match="session capacity"):
        registry.resolve("one-too-many")


def test_max_sessions_beyond_the_reviewed_bound_is_refused(tmp_path):
    with pytest.raises(ValueError, match="reviewed bound"):
        MCPSessionRegistry(
            lambda **capacity: BeliefMCPTools(workspace_root=tmp_path),
            max_sessions=MCP_MAX_SESSIONS + 1,
        )


def test_sessions_share_one_local_validation_capacity(tmp_path):
    registry = MCPSessionRegistry(
        lambda **capacity: BeliefMCPTools(
            workspace_root=tmp_path,
            **capacity,
        ),
        max_sessions=MCP_MAX_SESSIONS,
    )

    first = registry.resolve("agent-a")
    second = registry.resolve("agent-b")

    # Reaching into the private attribute is deliberate: the shared semaphore
    # is what keeps "one concurrent local validation" a process-wide bound.
    assert first is not second
    assert first._validation_capacity is second._validation_capacity


def test_capacities_report_the_isolation_model(tmp_path):
    registry = MCPSessionRegistry(
        lambda **capacity: BeliefMCPTools(
            workspace_root=tmp_path,
            **capacity,
        ),
        max_sessions=MCP_MAX_SESSIONS,
    )

    capacities = registry.capacities()

    assert capacities["isolation"] == "per_session_store"
    assert capacities["max_sessions"] == MCP_MAX_SESSIONS
    assert capacities["shared_validation_capacity"] == 1
