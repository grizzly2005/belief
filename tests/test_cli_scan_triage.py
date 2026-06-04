"""CLI triage coverage for `belief scan`."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path

from belief.cli import ScanRecord, _dedupe_scan_records
from belief.models import Finding


def _write_project(tmp_path: Path, source: str) -> Path:
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return project


def _run_scan(project: Path, *args: str) -> subprocess.CompletedProcess[str]:
    project_root = Path(__file__).resolve().parents[1]
    return subprocess.run(
        [sys.executable, "-m", "belief", "scan", str(project), *args],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_scan_help_lists_triage_options():
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, "-m", "belief", "scan", "--help"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0
    for option in [
        "--only",
        "--min-confidence",
        "--top",
        "--hide-structural",
        "--json-output",
        "--hypotheses",
        "--show-proofs",
        "--only-hypotheses",
        "--sarif-output",
        "--audit-markdown",
        "--include-protected-in-report",
        "--dedup-audit-cases",
        "--routes",
        "--show-routes",
        "--routes-json",
    ]:
        assert option in result.stdout


def test_scan_json_output_filters_security_and_taint(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def run(user_input):
            eval(user_input)
        """,
    )
    output = tmp_path / "scan.json"

    result = _run_scan(
        project,
        "--only",
        "security,taint",
        "--min-confidence",
        "0.8",
        "--top",
        "5",
        "--json-output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    assert "Filtered findings:" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert payload["schema_version"] == "belief.scan.filtered.v1"
    assert payload["filters"]["only"] == ["security", "taint"]
    assert payload["filters"]["min_confidence"] == 0.8
    assert payload["filters"]["top"] == 5
    assert payload["counts"]["total_after_filter"] == len(payload["findings"])
    assert payload["counts"]["by_category_after_filter"]["structural"] == 0
    assert {finding["category"] for finding in payload["findings"]} <= {"security", "taint"}
    assert all(finding["confidence"] >= 0.8 for finding in payload["findings"])


def test_only_cycles_without_include_cycles_does_not_crash(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()
        """,
    )
    output = tmp_path / "cycles.json"

    result = _run_scan(project, "--only", "cycles", "--json-output", str(output))

    assert result.returncode == 0, result.stderr
    assert "Cycle analysis not enabled" in result.stdout
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["filters"]["only"] == ["cycles"]
    assert payload["counts"]["total_after_filter"] == 0
    assert payload["findings"] == []


def test_include_cycles_json_output_exports_cycle_findings(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()
        """,
    )
    output = tmp_path / "cycles.json"

    result = _run_scan(
        project,
        "--only",
        "cycles",
        "--include-cycles",
        "--max-cycles",
        "10",
        "--json-output",
        str(output),
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["counts"]["by_category_after_filter"]["cycles"] == 1
    assert payload["findings"][0]["category"] == "cycles"
    assert payload["findings"][0]["rule_id"] == "CALL_GRAPH_CYCLE"


def test_audit_mode_with_routes_exports_route_context(tmp_path):
    project = _write_project(
        tmp_path,
        """
        from flask import Flask, request
        app = Flask(__name__)

        @app.get("/download")
        def download():
            path = request.args["path"]
            return open(path).read()
        """,
    )
    output = tmp_path / "audit.json"

    result = _run_scan(
        project,
        "--audit-mode",
        "--routes",
        "--json-output",
        str(output),
        "--top",
        "5",
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(output.read_text(encoding="utf-8"))
    contexts = [
        case.get("route_context")
        for case in payload["audit_cases"]
        if case.get("route_context")
    ]
    assert contexts
    assert contexts[0]["framework"] == "flask"
    assert contexts[0]["route"] == "/download"
    assert contexts[0]["methods"] == ["GET"]
    assert "route:" in result.stdout


def test_console_dedupe_uses_dedup_key_when_available():
    first = ScanRecord(
        "security",
        Finding(file="app.py", line=7, rule_id="R1", dedup_key="same", description="A"),
    )
    second = ScanRecord(
        "security",
        Finding(file="app.py", line=7, rule_id="R1", dedup_key="same", description="B"),
    )

    assert _dedupe_scan_records([first, second]) == [first]
