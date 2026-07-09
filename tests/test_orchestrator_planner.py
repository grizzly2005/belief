import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.orchestration.planner import build_run_plan


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_APP = ROOT / "tests" / "fixtures" / "sample_app"
SCOPE = ROOT / "tests" / "fixtures" / "scope" / "local_safe_scope.json"


def test_planner_builds_safe_local_plan(tmp_path):
    plan = build_run_plan(
        str(SAMPLE_APP),
        profile_id="local-safe",
        flags="auto",
        scope_file=str(SCOPE),
        output_dir=str(tmp_path / "run"),
    )

    payload = plan.to_dict()
    assert payload["schema_version"] == "belief.run_plan.v1"
    assert payload["target_profile"]["target_type"] == "python_repo"
    assert any(command["tool_id"] == "belief" for command in payload["commands"])
    assert all(command["allowed_by_scope"] for command in payload["commands"])
    assert all(Path(command["argv"][4]).is_absolute() for command in payload["commands"] if command["tool_id"] == "belief")


def test_plan_cli_writes_json(tmp_path):
    output = tmp_path / "run" / "metadata" / "run-plan.json"
    result = subprocess.run(
        [
            sys.executable, "-m", "belief", "plan", str(SAMPLE_APP),
            "--profile", "local-safe",
            "--flags", "auto",
            "--scope", str(SCOPE),
            "--output-dir", str(tmp_path / "run"),
            "--json-output", str(output),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text(encoding="utf-8"))["schema_version"] == "belief.run_plan.v1"


def test_planner_rejects_unbounded_timeout(tmp_path):
    with pytest.raises(ValueError, match="timeout"):
        build_run_plan(
            str(SAMPLE_APP),
            scope_file=str(SCOPE),
            output_dir=str(tmp_path / "run"),
            timeout_seconds=0,
        )
