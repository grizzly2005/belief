"""Optional pipeline integration for call-graph cycle findings."""

from __future__ import annotations

import subprocess
import sys
import textwrap
from pathlib import Path

from belief.config import BeliefConfig
from belief.models import AnalysisReport
from belief.pipeline import ParsePhase, Pipeline, ReportPhase


def _write_project(tmp_path: Path, source: str) -> Path:
    (tmp_path / "app.py").write_text(textwrap.dedent(source), encoding="utf-8")
    return tmp_path


def _run_parse_report(project: Path, config: BeliefConfig | None = None):
    state = Pipeline([ParsePhase(), ReportPhase()]).run(
        str(project),
        config=config,
        project_name="cycle-fixture",
    )
    assert state.report is not None
    return state.report


def _cycle_findings(report: AnalysisReport):
    return [finding for finding in report.findings if finding.rule_id == "CALL_GRAPH_CYCLE"]


def test_pipeline_default_does_not_emit_cycle_findings(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()
        """,
    )

    report = _run_parse_report(project)

    assert _cycle_findings(report) == []
    assert "cycle_analysis" not in report.run_metadata


def test_pipeline_include_cycles_emits_info_finding(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()
        """,
    )
    config = BeliefConfig(providers=[], include_cycles=True, max_cycles=100)

    report = _run_parse_report(project, config=config)
    findings = _cycle_findings(report)

    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert findings[0].dedup_key.startswith("cycle-")
    assert findings[0].fingerprint
    assert findings[0].metadata == {
        "cycle_id": findings[0].dedup_key,
        "nodes": ["app.a", "app.b"],
        "length": 2,
        "entry_node": "app.a",
    }
    assert report.run_metadata["cycle_analysis"] == {
        "enabled": True,
        "count": 1,
        "max_cycles": 100,
        "truncated": False,
    }


def test_pipeline_max_cycles_limits_output_and_metadata(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()

        def c():
            return d()

        def d():
            return c()
        """,
    )
    config = BeliefConfig(providers=[], include_cycles=True, max_cycles=1)

    report = _run_parse_report(project, config=config)

    assert len(_cycle_findings(report)) == 1
    assert report.run_metadata["cycle_analysis"] == {
        "enabled": True,
        "count": 1,
        "max_cycles": 1,
        "truncated": True,
    }


def test_cycle_finding_json_report_is_stable(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()
        """,
    )
    config = BeliefConfig(providers=[], include_cycles=True, max_cycles=100)
    report = _run_parse_report(project, config=config)

    first = report.to_dict()
    second = report.to_dict()
    cycle_finding = [
        finding for finding in first["findings"]
        if finding["rule_id"] == "CALL_GRAPH_CYCLE"
    ][0]

    assert first["findings"] == second["findings"]
    assert cycle_finding["dedup_key"] == cycle_finding["metadata"]["cycle_id"]
    assert cycle_finding["fingerprint"]
    assert cycle_finding["metadata"]["nodes"] == ["app.a", "app.b"]

    path = tmp_path / "report.json"
    report.save(str(path))
    loaded = AnalysisReport.load(str(path))
    loaded_cycle = _cycle_findings(loaded)[0]

    assert loaded_cycle.dedup_key == cycle_finding["dedup_key"]
    assert loaded_cycle.fingerprint == cycle_finding["fingerprint"]


def test_scan_help_lists_cycle_options():
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [sys.executable, "-m", "belief", "scan", "--help"],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0
    assert "--include-cycles" in result.stdout
    assert "--max-cycles" in result.stdout


def test_scan_cli_include_cycles_runs_on_local_fixture(tmp_path):
    project = _write_project(
        tmp_path,
        """
        def a():
            return b()

        def b():
            return a()
        """,
    )
    project_root = Path(__file__).resolve().parents[1]

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "scan",
            str(project),
            "--include-cycles",
            "--max-cycles",
            "1",
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0
    assert "Cycles:" in result.stdout
    assert "Cycle limit:" in result.stdout
    assert "truncated=false" in result.stdout
