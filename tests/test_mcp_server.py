"""Contracts and safety boundaries for BELIEF's local MCP facade."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from belief.mcp.contracts import MCP_PROTOCOL_VERSION
from belief.mcp.server import BeliefMCPServer
from belief.mcp.tools import BeliefMCPError, BeliefMCPTools


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
    validate = next(
        item for item in tools if item["name"] == "belief_validate_plan"
    )
    read_tools = [
        item for item in tools if item["name"] != "belief_validate_plan"
    ]
    assert all(
        item["annotations"]["readOnlyHint"] is True
        for item in read_tools
    )
    assert validate["annotations"] == {
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
    assert all(item["annotations"]["destructiveHint"] is False for item in tools)
    assert all(item["annotations"]["openWorldHint"] is False for item in tools)
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
    assert status["network_enabled"] is False
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
    assert capabilities["boundaries"]["target_writes"] is False
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

    initialized = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": MCP_PROTOCOL_VERSION},
        }
    )
    listed = server.handle(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
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

    assert initialized["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert initialized["result"]["capabilities"]["tools"]["listChanged"] is False
    assert listed["result"]["tools"]
    assert status["result"]["isError"] is False
    assert status["result"]["structuredContent"]["network_enabled"] is False
    assert json.loads(status["result"]["content"][0]["text"]) == (
        status["result"]["structuredContent"]
    )
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
