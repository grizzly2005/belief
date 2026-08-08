"""Contracts and safety boundaries for BELIEF's local MCP facade."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest

from belief.mcp.contracts import MCP_PROTOCOL_VERSION
from belief.mcp.server import (
    BeliefMCPServer,
    MCPLifecycleState,
    _decode_request,
    serve_stdio,
)
from belief.mcp.tools import BeliefMCPError, BeliefMCPTools
from belief.mcp.validation import MCP_MAX_RESPONSE_BYTES


pytestmark = pytest.mark.security


def _write_vulnerable_app(root: Path) -> Path:
    app = root / "app.py"
    app.write_text(
        '''
from flask import Flask, request

app = Flask(__name__)

@app.get("/download")
def download():
    user_path = request.args["path"]
    return open(user_path).read()
'''.lstrip(),
        encoding="utf-8",
    )
    return app


def _scan(
    service: BeliefMCPTools,
    workspace: str = ".",
) -> dict:
    return service.call_tool(
        "belief_scan",
        {
            "workspace": workspace,
            "audit_mode": True,
            "reportability": True,
            "max_files": 20,
        },
    )


def _first_case(service: BeliefMCPTools, run_id: str) -> dict:
    payload, mime_type = service.read_resource(
        f"belief://runs/{run_id}/audit-cases"
    )
    assert mime_type == "application/json"
    return payload["audit_cases"][0]


def test_mcp_tool_surface_is_closed_and_fixture_bound(tmp_path):
    service = BeliefMCPTools(workspace_root=tmp_path)

    tools = service.list_tools()
    names = {item["name"] for item in tools}

    assert names == {
        "belief_status",
        "belief_scan",
        "belief_get_case",
        "belief_explain_case",
        "belief_build_validation_plan",
        "belief_prepare_validation_fixture",
        "belief_prepare_authorized_project_pilot",
        "belief_validate_plan",
        "belief_compare_runs",
        "belief_run_local_benchmark",
    }
    assert "belief_execute_command" not in names
    annotations = {
        item["name"]: item["annotations"]
        for item in tools
    }
    assert annotations["belief_status"]["readOnlyHint"] is True
    assert annotations["belief_get_case"]["readOnlyHint"] is True
    assert annotations["belief_explain_case"]["readOnlyHint"] is True
    assert annotations["belief_compare_runs"]["readOnlyHint"] is True
    assert annotations["belief_scan"]["readOnlyHint"] is False
    assert annotations["belief_scan"]["openWorldHint"] is True
    for name in {
        "belief_build_validation_plan",
        "belief_prepare_validation_fixture",
        "belief_prepare_authorized_project_pilot",
        "belief_validate_plan",
        "belief_run_local_benchmark",
    }:
        assert annotations[name]["readOnlyHint"] is False
    assert (
        annotations["belief_prepare_authorized_project_pilot"][
            "openWorldHint"
        ]
        is True
    )
    assert all(item["annotations"]["destructiveHint"] is False for item in tools)
    for name in {
        "belief_scan",
        "belief_build_validation_plan",
        "belief_prepare_validation_fixture",
        "belief_prepare_authorized_project_pilot",
        "belief_validate_plan",
    }:
        assert annotations[name]["idempotentHint"] is False
    for name in {
        "belief_status",
        "belief_get_case",
        "belief_explain_case",
        "belief_compare_runs",
        "belief_run_local_benchmark",
    }:
        assert annotations[name]["idempotentHint"] is True
    assert all(item["execution"]["taskSupport"] == "forbidden" for item in tools)
    assert all(item["inputSchema"]["additionalProperties"] is False for item in tools)


def test_status_capabilities_and_schema_resources_are_explicit(tmp_path):
    service = BeliefMCPTools(workspace_root=tmp_path)

    status = service.call_tool("belief_status", {})
    capabilities, _ = service.read_resource("belief://capabilities")
    plan_schema, mime_type = service.read_resource(
        "belief://schemas/validation-plan"
    )

    assert status["protocol_version"] == MCP_PROTOCOL_VERSION
    assert status["live_network_target_allowed"] is False
    assert status["worker_process_spawn"] is True
    assert status["target_process_spawn"] is False
    assert status["allowlisted_framework_imports"] is True
    assert status["caller_controlled_imports"] is False
    assert status["temporary_fixture_writes"] is True
    assert status["target_workspace_writes"] is False
    assert status["active_cancellation_scope"] == (
        "all_request_state_commits_and_dynamic_worker_termination"
    )
    assert status["state_commit_cancellation_safe"] is True
    assert status["publication"]["mode"] == "minimal"
    assert status["dynamic_execution_enabled"] is True
    assert status["dynamic_execution_scope"] == (
        "registered_transparent_fixture_only"
    )
    assert status["holdout_access_enabled"] is False
    assert status["confirmed_vulnerability_verdict_enabled"] is False
    assert capabilities["storage"]["writes_artifacts_to_disk"] is False
    assert capabilities["storage"]["retains_source_text"] is False
    assert capabilities["storage"]["retains_full_analysis"] is False
    assert capabilities["boundaries"]["susvibes_holdout"] is False
    assert capabilities["boundaries"]["target_workspace_writes"] is False
    assert capabilities["boundaries"]["worker_process_spawn"] is True
    assert capabilities["boundaries"]["target_process_spawn"] is False
    assert capabilities["boundaries"]["allowlisted_framework_imports"] is True
    assert capabilities["boundaries"]["caller_controlled_imports"] is False
    assert capabilities["boundaries"]["dynamic_execution"] is True
    assert mime_type == "application/schema+json"
    assert plan_schema["properties"]["schema_version"]["const"] == (
        "belief.validation_plan.v2"
    )


def test_scan_case_explanation_and_plan_use_existing_services(tmp_path):
    _write_vulnerable_app(tmp_path)
    service = BeliefMCPTools(workspace_root=tmp_path)

    scan = _scan(service)
    run_id = scan["run_id"]
    case = _first_case(service, run_id)
    case_id = case["case_id"]

    fetched = service.call_tool(
        "belief_get_case", {"run_id": run_id, "case_id": case_id}
    )
    explanation = service.call_tool(
        "belief_explain_case", {"run_id": run_id, "case_id": case_id}
    )
    plan = service.call_tool(
        "belief_build_validation_plan",
        {"run_id": run_id, "case_id": case_id},
    )
    plans, _ = service.read_resource(
        f"belief://runs/{run_id}/validation-plans"
    )
    results, _ = service.read_resource(
        f"belief://runs/{run_id}/validation-results"
    )

    assert scan["summary"]["audit_case_count"] >= 1
    assert fetched == case
    assert explanation["source"]
    assert explanation["sink"]
    assert explanation["path"]
    assert "does not confirm" in explanation["interpretation_boundary"]
    assert plan["subject_id"] == case_id
    assert plan["schema_version"] == "belief.validation_plan.v2"
    assert plan["safety"]["network_mode"] == "forbidden"
    assert plan["safety"]["destructive_actions_allowed"] is False
    assert plans["validation_plans"] == [plan]
    assert plans["execution_enabled"] is False
    assert results["validation_results"] == []
    assert results["execution_enabled"] is False


def test_semantically_identical_scan_reuses_deterministic_run(tmp_path):
    _write_vulnerable_app(tmp_path)
    service = BeliefMCPTools(workspace_root=tmp_path)

    first = _scan(service)
    second = _scan(service)

    assert first["run_id"] == second["run_id"]
    assert first["summary"] == second["summary"]


def test_scan_rejects_escape_non_python_file_and_unknown_arguments(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    _write_vulnerable_app(root)
    outside = tmp_path / "outside.py"
    outside.write_text("value = 1\n", encoding="utf-8")
    data = root / "data.json"
    data.write_text("{}\n", encoding="utf-8")
    service = BeliefMCPTools(workspace_root=root)

    with pytest.raises(BeliefMCPError, match="inside"):
        _scan(service, "../outside.py")
    with pytest.raises(BeliefMCPError, match="Python"):
        _scan(service, "data.json")
    with pytest.raises(BeliefMCPError, match="unsupported argument"):
        service.call_tool(
            "belief_scan",
            {"workspace": ".", "command": "whoami"},
        )
    with pytest.raises(BeliefMCPError, match="audit_mode=true"):
        service.call_tool(
            "belief_scan",
            {"workspace": ".", "audit_mode": False},
        )


def test_scan_never_opens_susvibes_directory(
    monkeypatch,
    tmp_path,
):
    _write_vulnerable_app(tmp_path)
    holdout = tmp_path / "benchmark_susvibes"
    holdout.mkdir()
    (holdout / "secret.py").write_text(
        "raise RuntimeError('must never be opened')\n",
        encoding="utf-8",
    )
    original_open = Path.open
    original_read_text = Path.read_text

    def guarded_open(path, *args, **kwargs):
        if "benchmark_susvibes" in {
            part.casefold() for part in path.parts
        }:
            raise AssertionError("MCP opened a SusVibes artifact")
        return original_open(path, *args, **kwargs)

    def guarded_read_text(path, *args, **kwargs):
        if "benchmark_susvibes" in {
            part.casefold() for part in path.parts
        }:
            raise AssertionError("MCP read a SusVibes artifact")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    service = BeliefMCPTools(workspace_root=tmp_path)

    scan = _scan(service)

    assert scan["boundaries"]["susvibes_artifacts_opened"] is False
    with pytest.raises(BeliefMCPError, match="reserved"):
        _scan(service, "benchmark_susvibes")
    with pytest.raises(BeliefMCPError, match="reserved holdout"):
        BeliefMCPTools(workspace_root=holdout)


def test_mcp_digest_denylist_blocks_renamed_synthetic_source(tmp_path):
    source = b"def hidden(value):\n    return eval(value)\n"
    target = tmp_path / "ordinary.py"
    target.write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()
    service = BeliefMCPTools(
        workspace_root=tmp_path,
        holdout_source_sha256_denylist=frozenset({digest}),
    )

    scan = _scan(service)

    assert scan["summary"]["audit_case_count"] == 0
    assert any(
        item["code"] == "reserved_source_digest_abstained"
        for item in scan["diagnostics"]
    )
    assert (
        service.status()["holdout_source_digest_denylist_count"]
        == 1
    )


def test_scan_and_plan_do_not_use_network_or_processes(
    monkeypatch,
    tmp_path,
):
    _write_vulnerable_app(tmp_path)

    def reject(*_args, **_kwargs):
        raise AssertionError("MCP attempted network or process execution")

    monkeypatch.setattr(socket.socket, "connect", reject)
    monkeypatch.setattr(subprocess, "Popen", reject)
    monkeypatch.setattr(subprocess, "run", reject)
    service = BeliefMCPTools(workspace_root=tmp_path)

    scan = _scan(service)
    case = _first_case(service, scan["run_id"])
    plan = service.call_tool(
        "belief_build_validation_plan",
        {"run_id": scan["run_id"], "case_id": case["case_id"]},
    )

    assert plan["safety"]["network_mode"] == "forbidden"
    assert plan["safety"]["destructive_actions_allowed"] is False


def test_compare_runs_reports_resolved_static_candidate(tmp_path):
    app = _write_vulnerable_app(tmp_path)
    service = BeliefMCPTools(workspace_root=tmp_path)
    before = _scan(service)
    app.write_text(
        "def health():\n    return {'status': 'ok'}\n",
        encoding="utf-8",
    )
    after = _scan(service)

    comparison = service.call_tool(
        "belief_compare_runs",
        {
            "before_run_id": before["run_id"],
            "after_run_id": after["run_id"],
        },
    )

    assert comparison["counts"]["before"] >= 1
    assert comparison["counts"]["after"] == 0
    assert comparison["counts"]["resolved"] >= 1
    assert comparison["validation_execution_available"] is False
    assert comparison["validation_regressions"] == []
    assert "static AuditCase status" in comparison["verdict_interpretation"]
    assert "does not prove" in comparison["interpretation_boundary"]


def test_compare_runs_rejects_different_resolved_targets(tmp_path):
    left = tmp_path / "left"
    right = tmp_path / "right"
    left.mkdir()
    right.mkdir()
    _write_vulnerable_app(left)
    _write_vulnerable_app(right)
    service = BeliefMCPTools(workspace_root=tmp_path)
    before = _scan(service, "left")
    after = _scan(service, "right")

    with pytest.raises(BeliefMCPError, match="same resolved target"):
        service.call_tool(
            "belief_compare_runs",
            {
                "before_run_id": before["run_id"],
                "after_run_id": after["run_id"],
            },
        )


def test_local_benchmark_is_allowlisted_and_attests_holdout_boundary(
    monkeypatch,
    tmp_path,
):
    original_read_text = Path.read_text

    def guarded_read_text(path, *args, **kwargs):
        if "benchmark_susvibes" in {
            part.casefold() for part in path.parts
        }:
            raise AssertionError("benchmark opened a SusVibes artifact")
        return original_read_text(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded_read_text)
    service = BeliefMCPTools(workspace_root=tmp_path)

    result = service.call_tool(
        "belief_run_local_benchmark",
        {"benchmark": "local_validation_v2"},
    )

    assert result["corpus"]["case_count"] == 8
    assert result["boundaries"]["susvibes_artifacts_opened"] is False
    assert result["boundaries"]["network_used"] is False
    assert result["semantic_stability"]["identical_repeated_execution"] is True
    with pytest.raises(BeliefMCPError, match="only the transparent"):
        service.call_tool(
            "belief_run_local_benchmark",
            {"benchmark": "susvibes"},
        )


def test_protocol_dispatches_initialize_tools_resources_and_tool_errors(
    tmp_path,
):
    service = BeliefMCPTools(workspace_root=tmp_path)
    server = BeliefMCPServer(service)

    premature = server.handle(
        {"jsonrpc": "2.0", "id": 0, "method": "tools/list"}
    )
    initialized = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
        }
    )
    before_ready = server.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    )
    assert server.handle(
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
    ) is None
    listed = server.handle(
        {"jsonrpc": "2.0", "id": 6, "method": "tools/list"}
    )
    status = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "belief_status", "arguments": {}},
        }
    )
    bad_call = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "belief_scan",
                "arguments": {"workspace": "../escape"},
            },
        }
    )
    unknown = server.handle(
        {"jsonrpc": "2.0", "id": 5, "method": "unknown/method"}
    )

    assert premature["error"]["code"] == -32002
    assert initialized["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert initialized["result"]["capabilities"]["tools"]["listChanged"] is False
    assert before_ready["error"]["code"] == -32002
    assert server.lifecycle_state is MCPLifecycleState.READY
    assert listed["result"]["tools"]
    assert status["result"]["isError"] is False
    assert (
        status["result"]["structuredContent"]["live_network_target_allowed"]
        is False
    )
    assert json.loads(status["result"]["content"][0]["text"]) == (
        status["result"]["structuredContent"]
    )
    assert status["result"]["_meta"]["belief/publication"]["mode"] == "minimal"
    assert bad_call["result"]["isError"] is True
    assert unknown["error"]["code"] == -32601


def test_protocol_ignores_notifications_and_returns_standard_errors(tmp_path):
    server = BeliefMCPServer(BeliefMCPTools(workspace_root=tmp_path))

    assert server.handle(
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        }
    ) is None
    invalid = server.handle({"jsonrpc": "1.0", "id": 1, "method": "ping"})
    bad_params = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/read",
            "params": [],
        }
    )

    assert invalid["error"]["code"] == -32600
    assert bad_params["error"]["code"] == -32602


def test_protocol_rejects_repeat_initialize_and_operations_after_close(
    tmp_path,
):
    server = BeliefMCPServer(BeliefMCPTools(workspace_root=tmp_path))
    first = server.handle({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
    })
    repeated = server.handle({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "initialize",
        "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
    })

    assert first["result"]
    assert repeated["error"]["code"] == -32002
    assert server.lifecycle_state is MCPLifecycleState.INITIALIZE_RESPONDED
    server.close()
    assert server.lifecycle_state is MCPLifecycleState.CLOSED
    closed = server.handle(
        {"jsonrpc": "2.0", "id": 3, "method": "ping"}
    )
    assert closed["error"]["code"] == -32002


def test_real_stdio_server_emits_only_newline_delimited_json():
    project_root = Path(__file__).resolve().parents[1]
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        },
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    completed = subprocess.run(
        [sys.executable, "-m", "belief.mcp.server"],
        cwd=project_root,
        input="\n".join(json.dumps(item) for item in requests) + "\n",
        capture_output=True,
        text=True,
        timeout=20,
    )

    lines = completed.stdout.splitlines()
    payloads = [json.loads(line) for line in lines]

    assert completed.returncode == 0
    assert completed.stderr == ""
    assert len(payloads) == 2
    assert payloads[0]["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert payloads[1]["result"]["tools"]


@pytest.mark.parametrize(
    "payload",
    (
        {"value": "x" * 4_097},
        {"value": list(range(129))},
        {"value": [[0] * 128 for _index in range(33)]},
    ),
)
def test_json_decoder_rejects_string_collection_and_node_excess(payload):
    with pytest.raises(ValueError):
        _decode_request(json.dumps(payload))


def test_json_decoder_and_stdio_reject_excessive_depth_without_crashing(
    tmp_path,
):
    excessive = "[" * 2_000 + "0" + "]" * 2_000
    with pytest.raises((RecursionError, ValueError)):
        _decode_request(excessive)

    stdin = StringIO(
        excessive
        + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
        + "\n"
    )
    stdout = StringIO()
    server = BeliefMCPServer(BeliefMCPTools(workspace_root=tmp_path))

    assert serve_stdio(server, stdin=stdin, stdout=stdout) == 0
    responses = [
        json.loads(line)
        for line in stdout.getvalue().splitlines()
    ]
    assert responses[0]["error"]["code"] == -32700
    assert responses[1]["id"] == 1
    assert responses[1]["result"] == {}


def test_json_request_byte_bound_counts_utf8_bytes():
    payload = {"value": ["😀" * 4_096 for _index in range(128)]}

    with pytest.raises(ValueError, match="byte bound"):
        _decode_request(
            json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        )


def test_request_id_and_response_bytes_are_bounded(monkeypatch, tmp_path):
    service = BeliefMCPTools(workspace_root=tmp_path)
    server = BeliefMCPServer(service)
    invalid_id = server.handle({
        "jsonrpc": "2.0",
        "id": "x" * 257,
        "method": "ping",
    })
    assert invalid_id["error"]["code"] == -32600
    server.handle({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
    })
    server.handle({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {},
    })

    monkeypatch.setattr(
        service,
        "call_tool",
        lambda *_args, **_kwargs: {"blob": "x" * MCP_MAX_RESPONSE_BYTES},
    )
    oversized = server.handle({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "tools/call",
        "params": {"name": "belief_status", "arguments": {}},
    })
    assert oversized["error"]["code"] == -32603
    assert "size bound" in oversized["error"]["message"]
