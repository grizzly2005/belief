"""Contracts for the reusable, offline static-analysis pipeline."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from belief.audit_case import audit_case_from_dataflow_path
from belief.dataflow import analyze_source_dataflow
from belief.static_analysis_pipeline import (
    StaticAnalysisOptions,
    analyze_static_target,
)


pytestmark = pytest.mark.security


def _write_vulnerable_flask_app(root: Path) -> Path:
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


def _full_options() -> StaticAnalysisOptions:
    return StaticAnalysisOptions(
        audit_mode=True,
        include_hypotheses=True,
        include_dataflow=True,
        include_routes=True,
        include_guarantees=True,
        reportability=True,
        selected_categories=frozenset({"security", "taint"}),
    )


def test_common_pipeline_extracts_structured_static_results(tmp_path):
    _write_vulnerable_flask_app(tmp_path)

    result = analyze_static_target(tmp_path, _full_options())

    assert result.files_scanned == 1
    assert result.findings
    assert any(path.sink_category == "path" for path in result.dataflow_paths)
    assert any(case.case_type == "path_traversal_possible" for case in result.audit_cases)
    assert any(route.route == "/download" for route in result.routes)
    assert isinstance(result.diagnostics, tuple)


def test_single_file_route_paths_preserve_cli_compatibility(tmp_path):
    app = _write_vulnerable_flask_app(tmp_path)

    result = analyze_static_target(
        app,
        replace(_full_options(), legacy_single_file_path_projection=True),
    )

    assert [route.file for route in result.routes] == ["app.py"]


def test_common_pipeline_is_semantically_deterministic(tmp_path):
    _write_vulnerable_flask_app(tmp_path)

    first = analyze_static_target(tmp_path, _full_options()).to_dict()
    second = analyze_static_target(tmp_path, _full_options()).to_dict()

    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_cmd_scan_and_common_pipeline_are_functionally_equivalent(tmp_path):
    _write_vulnerable_flask_app(tmp_path)
    output = tmp_path / "cli.json"
    project_root = Path(__file__).resolve().parents[1]

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "scan",
            str(tmp_path),
            "--audit-mode",
            "--routes",
            "--reportability",
            "--show-dataflow",
            "--json-output",
            str(output),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    cli_payload = json.loads(output.read_text(encoding="utf-8"))
    options = StaticAnalysisOptions(
        audit_mode=True,
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        show_dataflow=True,
        include_audit_cases=True,
        include_routes=True,
        reportability=True,
        selected_categories=frozenset({"security", "taint"}),
    )
    service_result = analyze_static_target(tmp_path, options)

    assert cli_payload["audit_cases"] == [
        case.to_dict() for case in service_result.audit_cases
    ]
    assert cli_payload["dataflow"]["paths"] == [
        path.to_dict() for path in service_result.dataflow_paths
    ]
    assert cli_payload["routes"] == [route.to_dict() for route in service_result.routes]


def test_common_pipeline_requires_no_network(monkeypatch, tmp_path):
    _write_vulnerable_flask_app(tmp_path)

    def reject_network(*_args, **_kwargs):
        raise AssertionError("static analysis attempted a network connection")

    monkeypatch.setattr(socket.socket, "connect", reject_network)

    result = analyze_static_target(tmp_path, _full_options())

    assert result.files_scanned == 1


def test_common_pipeline_surfaces_dataflow_truncation_diagnostics(tmp_path):
    _write_vulnerable_flask_app(tmp_path)
    options = StaticAnalysisOptions(
        include_dataflow=True,
        max_dataflow_nodes=0,
        selected_categories=frozenset({"security", "taint"}),
    )

    result = analyze_static_target(tmp_path, options)

    assert "analysis_truncated_max_nodes" in {
        diagnostic.code for diagnostic in result.diagnostics
    }
    assert result.dataflow_paths == ()


def test_audit_case_preserves_versioned_structured_dataflow():
    source = '''
from flask import request

def download():
    user_path = request.args["path"]
    return open(user_path).read()
'''.lstrip()
    summary = analyze_source_dataflow(source, "app.py")
    path = next(item for item in summary.paths if item.sink_category == "path")

    payload = audit_case_from_dataflow_path(path).to_dict()
    evidence = payload["structured_dataflow"]

    assert evidence["schema_version"] == "belief.dataflow_evidence.v1"
    assert evidence["source"] == {
        "file": "app.py",
        "line": path.source_line,
        "column": path.source.column,
        "symbol": path.source.expression,
    }
    assert evidence["sink"]["file"] == "app.py"
    assert evidence["sink"]["line"] == path.sink_line
    assert evidence["sink"]["symbol"] == path.sink.expression
    assert evidence["function_context"] == "download"
    assert evidence["ordered_nodes"]
    assert evidence["ordered_edges"]
    assert "guard_applicability" in evidence
    assert "rejection_reason" in evidence
    assert "truncation_reason" in evidence
    # The legacy projection remains available for downstream consumers.
    assert payload["source"] == path.source.expression
    assert payload["sink"] == path.sink.expression
    assert payload["dataflow_path"] == [node.expression for node in path.nodes]
