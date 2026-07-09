import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.orchestration.executor import execute_run_plan
from belief.orchestration.planner import build_run_plan


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_APP = ROOT / "tests" / "fixtures" / "sample_app"
SCOPE = ROOT / "tests" / "fixtures" / "scope" / "local_safe_scope.json"


def test_executor_rejects_unregistered_command_without_running_it(tmp_path):
    script = tmp_path / "fake_tool.py"
    marker = tmp_path / "should-not-exist.txt"
    script.write_text(f"from pathlib import Path\nPath({str(marker)!r}).write_text('ran')\n", encoding="utf-8")
    plan = {
        "schema_version": "belief.run_plan.v1",
        "target_profile": {"target": str(tmp_path)},
        "output_layout": {
            "root": (tmp_path / "run").as_posix(),
            "raw": (tmp_path / "run" / "raw").as_posix(),
            "normalized": (tmp_path / "run" / "normalized").as_posix(),
            "audit": (tmp_path / "run" / "audit").as_posix(),
            "reports": (tmp_path / "run" / "reports").as_posix(),
            "logs": (tmp_path / "run" / "logs").as_posix(),
            "metadata": (tmp_path / "run" / "metadata").as_posix(),
            "cache": (tmp_path / "run" / "cache").as_posix(),
        },
        "commands": [{
            "tool_id": "fake",
            "argv": [sys.executable, str(script)],
            "cwd": str(tmp_path),
            "raw_output": (tmp_path / "run" / "raw" / "fake.json").as_posix(),
            "normalized_output": None,
            "timeout_seconds": 10,
            "requires_network": False,
            "requires_dynamic": False,
            "allowed_by_scope": True,
            "tool_status": "installed"
        }],
        "skipped_tools": [],
        "safety_decisions": [],
    }
    plan_path = tmp_path / "run" / "metadata" / "run-plan.json"
    plan_path.parent.mkdir(parents=True)
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    summary = execute_run_plan(plan_path)

    assert summary["completed"] == []
    assert len(summary["skipped"]) == 1
    assert "capability registry" in summary["skipped"][0]["reason"]
    assert marker.exists() is False


def test_execute_plan_cli_handles_skipped_plan(tmp_path):
    plan = {
        "schema_version": "belief.run_plan.v1",
        "target_profile": {"target": str(tmp_path)},
        "output_layout": {"root": (tmp_path / "run").as_posix(), "metadata": (tmp_path / "run" / "metadata").as_posix(), "logs": (tmp_path / "run" / "logs").as_posix()},
        "commands": [{"tool_id": "missing", "argv": [], "allowed_by_scope": False, "tool_status": "missing", "skip_reason": "missing"}],
        "skipped_tools": [{"tool_id": "missing", "reason": "missing"}],
        "safety_decisions": [],
    }
    plan_path = tmp_path / "run" / "metadata" / "run-plan.json"
    plan_path.parent.mkdir(parents=True)
    plan_path.write_text(json.dumps(plan), encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "-m", "belief", "execute-plan", str(plan_path)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["skipped"] == 1


def test_executor_skips_tampered_timeout_before_subprocess(tmp_path):
    payload = build_run_plan(
        str(SAMPLE_APP),
        scope_file=str(SCOPE),
        output_dir=str(tmp_path / "run"),
    ).to_dict()
    belief_command = next(command for command in payload["commands"] if command["tool_id"] == "belief")
    belief_command["timeout_seconds"] = 0
    payload["commands"] = [belief_command]
    plan_path = tmp_path / "run" / "metadata" / "run-plan.json"
    plan_path.parent.mkdir(parents=True)
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    summary = execute_run_plan(plan_path)

    assert summary["completed"] == []
    assert summary["skipped"][0]["reason"].startswith("command timeout")


def test_executor_rejects_tampered_embedded_scope(tmp_path):
    payload = build_run_plan(
        str(SAMPLE_APP),
        scope_file=str(SCOPE),
        output_dir=str(tmp_path / "run"),
    ).to_dict()
    payload["scope_summary"]["redaction"]["authorization"] = False
    plan_path = tmp_path / "run" / "metadata" / "run-plan.json"
    plan_path.parent.mkdir(parents=True)
    plan_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="redaction.authorization"):
        execute_run_plan(plan_path)
