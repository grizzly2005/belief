import json
import subprocess
import sys

from belief.orchestration.executor import execute_run_plan


def test_executor_runs_fake_tool_and_records_summary(tmp_path):
    script = tmp_path / "fake_tool.py"
    script.write_text("print('ok')\n", encoding="utf-8")
    plan = {
        "schema_version": "belief.run_plan.v1",
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

    assert len(summary["completed"]) == 1
    assert summary["failed"] == []


def test_execute_plan_cli_handles_skipped_plan(tmp_path):
    plan = {
        "schema_version": "belief.run_plan.v1",
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
