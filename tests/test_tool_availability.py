import json
import subprocess
import sys

from belief.tools.availability import availability_for_profile


def test_availability_never_requires_external_tools():
    payload = availability_for_profile("local-safe")
    statuses = {row["status"] for row in payload["tools"]}

    assert "installed" in statuses
    assert statuses <= {"installed", "missing", "import_only", "container_required", "not_supported_yet", "disabled_by_scope"}


def test_availability_cli_writes_json(tmp_path):
    output = tmp_path / "availability.json"
    result = subprocess.run(
        [sys.executable, "-m", "belief", "tools", "availability", "--profile", "local-safe", "--json-output", str(output)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text(encoding="utf-8"))["profile"]["profile_id"] == "local-safe"
