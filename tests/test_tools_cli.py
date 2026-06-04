import json
import subprocess
import sys


def _run(*args):
    return subprocess.run(
        [sys.executable, "-m", "belief", *args],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )


def test_tools_list_cli_works():
    result = _run("tools", "list")
    assert result.returncode == 0
    assert "semgrep" in result.stdout
    assert "zap" in result.stdout


def test_tools_info_cli_works():
    result = _run("tools", "info", "semgrep")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["tool_id"] == "semgrep"
    assert payload["risk"]["safe_default"] is True


def test_tools_check_cli_works_without_external_tools():
    result = _run("tools", "check")
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert any(item["tool_id"] == "codeql" for item in payload)


def test_tools_import_semgrep_cli_works(tmp_path):
    path = tmp_path / "semgrep.json"
    path.write_text(json.dumps({"results": []}), encoding="utf-8")
    result = _run("tools", "import", "semgrep", "--file", str(path))
    assert result.returncode == 0
    payload = json.loads(result.stdout)
    assert payload["tool_id"] == "semgrep"
    assert payload["findings"] == []
