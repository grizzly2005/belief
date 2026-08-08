"""Contracts for the reusable, offline static-analysis pipeline."""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

import belief.static_analysis_pipeline as pipeline_module
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


def test_reserved_source_digest_is_not_parsed_or_analyzed(tmp_path):
    source = (
        b"# renamed reserved material\n"
        b"import os\n"
        b"def hidden(value):\n"
        b"    return eval(value)\n"
    )
    target = tmp_path / "ordinary_name.py"
    target.write_bytes(source)
    digest = hashlib.sha256(source).hexdigest()

    result = analyze_static_target(
        target,
        StaticAnalysisOptions(
            audit_mode=True,
            denied_source_sha256=frozenset({digest}),
        ),
    ).to_dict()

    document = result["source_snapshot"]["files"][0]
    codes = {item["code"] for item in result["diagnostics"]}
    assert document["sha256"] == digest
    assert document["decode_status"] == "reserved_digest_blocked"
    assert document["parse_status"] == "not_parsed"
    assert result["files"] == []
    assert result["findings"] == []
    assert result["audit_cases"] == []
    assert "reserved_source_digest_abstained" in codes
    assert result["coverage"]["scan_complete"] is False
    assert result["coverage"]["project_conclusion_allowed"] is False
    assert source.decode("utf-8") not in json.dumps(result)


def test_reserved_source_digest_configuration_is_strict(tmp_path):
    target = tmp_path / "ordinary.py"
    target.write_text("value = 1\n", encoding="utf-8")

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        analyze_static_target(
            target,
            StaticAnalysisOptions(
                denied_source_sha256=frozenset({"NOT-A-DIGEST"}),
            ),
        )


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


def test_changed_source_with_identical_findings_gets_new_analysis_identity(
    tmp_path,
):
    source = tmp_path / "quiet.py"
    options = StaticAnalysisOptions(
        selected_categories=frozenset({"security"}),
    )
    source.write_text("VALUE = 1\n", encoding="utf-8")
    first = analyze_static_target(tmp_path, options).to_dict()
    source.write_text("VALUE = 2\n", encoding="utf-8")
    second = analyze_static_target(tmp_path, options).to_dict()

    assert first["findings"] == second["findings"] == []
    assert (
        first["analysis_identity"]["source_snapshot_id"]
        != second["analysis_identity"]["source_snapshot_id"]
    )
    assert (
        first["analysis_identity"]["analysis_id"]
        != second["analysis_identity"]["analysis_id"]
    )


def test_analysis_uses_captured_bytes_if_file_changes_after_snapshot(
    monkeypatch,
    tmp_path,
):
    app = tmp_path / "app.py"
    app.write_text(
        'from flask import Flask\n'
        'app = Flask(__name__)\n'
        '@app.get("/captured")\n'
        'def captured():\n'
        '    return "captured"\n',
        encoding="utf-8",
    )
    real_builder = pipeline_module.build_source_snapshot

    def capture_then_change(*args, **kwargs):
        snapshot = real_builder(*args, **kwargs)
        app.write_text(
            'from flask import Flask\n'
            'app = Flask(__name__)\n'
            '@app.get("/changed")\n'
            'def changed():\n'
            '    return "changed"\n',
            encoding="utf-8",
        )
        return snapshot

    monkeypatch.setattr(
        pipeline_module,
        "build_source_snapshot",
        capture_then_change,
    )
    result = analyze_static_target(
        tmp_path,
        StaticAnalysisOptions(include_routes=True),
    )

    assert [route.route for route in result.routes] == ["/captured"]
    assert "/changed" in app.read_text(encoding="utf-8")
    assert result.source_snapshot_manifest["files"][0]["sha256"] != (
        hashlib.sha256(app.read_bytes()).hexdigest()
    )


def test_invalid_pep263_source_abstains_without_replacement(tmp_path):
    source = tmp_path / "invalid.py"
    source.write_bytes(b"value = '" + bytes((0xFF,)) + b"'\n")

    result = analyze_static_target(tmp_path).to_dict()

    assert result["files"] == []
    assert result["coverage"]["scan_complete"] is False
    assert result["coverage"]["project_conclusion_allowed"] is False
    assert result["source_snapshot"]["files"][0]["decode_status"] == (
        "invalid_encoding"
    )
    assert "source_decode_abstained" in {
        item["code"] for item in result["diagnostics"]
    }


def test_pep263_encoding_cookie_is_decoded_strictly(tmp_path):
    source = tmp_path / "latin1.py"
    source.write_bytes(
        b"# -*- coding: latin-1 -*-\nvalue = '\xe9'\n"
    )

    result = analyze_static_target(tmp_path).to_dict()

    assert result["files"] == ["latin1.py"]
    assert result["source_snapshot"]["files"][0]["encoding"] == "iso-8859-1"
    assert result["source_snapshot"]["files"][0]["decode_status"] == (
        "decoded_from_encoding_cookie"
    )


def test_scan_coverage_reports_max_files_truncation(tmp_path):
    for index in range(3):
        (tmp_path / f"module_{index}.py").write_text(
            f"VALUE = {index}\n",
            encoding="utf-8",
        )

    result = analyze_static_target(
        tmp_path,
        StaticAnalysisOptions(
            max_files=2,
            selected_categories=frozenset({"security"}),
        ),
    ).to_dict()
    coverage = result["coverage"]

    assert coverage["discovered_files"] == 3
    assert coverage["eligible_files"] == 3
    assert coverage["scanned_files"] == 2
    assert coverage["truncated_files"] == ["module_2.py"]
    assert coverage["scan_complete"] is False
    assert coverage["project_conclusion_allowed"] is False


def test_huge_single_python_file_is_rejected_before_read(tmp_path):
    source = tmp_path / "huge.py"
    source.write_bytes(b"#" * 1024)

    result = analyze_static_target(
        tmp_path,
        StaticAnalysisOptions(max_file_bytes=64),
    ).to_dict()
    coverage = result["coverage"]

    assert result["files"] == []
    assert coverage["failed_files"] == ["huge.py"]
    assert coverage["excluded_files_by_reason"]["file_too_large"] == 1
    assert coverage["excluded_files"][0]["content_read"] is False
    assert coverage["scan_complete"] is False


def test_junction_classified_subtree_is_not_enumerated(
    monkeypatch,
    tmp_path,
):
    linked = tmp_path / "linked"
    linked.mkdir()
    (linked / "escape.py").write_text(
        "raise AssertionError('must not be scanned')\n",
        encoding="utf-8",
    )
    (tmp_path / "safe.py").write_text("SAFE = True\n", encoding="utf-8")
    original = getattr(Path, "is_junction", None)

    def classify(path):
        if path.name == "linked":
            return True
        return original(path) if callable(original) else False

    monkeypatch.setattr(Path, "is_junction", classify, raising=False)
    result = analyze_static_target(tmp_path).to_dict()

    assert result["files"] == ["safe.py"]
    assert result["coverage"]["inventory_complete"] is False
    assert result["coverage"]["excluded_subtrees"] == [{
        "logical_path": "linked",
        "reason": "link_or_junction_subtree",
        "enumerated": "false",
    }]
