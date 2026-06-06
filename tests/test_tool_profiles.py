import json
import subprocess
import sys

from belief.tools.profiles import load_tool_profile, load_tool_profiles


def test_profiles_load():
    profiles = load_tool_profiles()

    assert {"local-safe", "appsec-local", "bug-bounty-passive", "authorized-dynamic"} <= set(profiles)
    assert "belief" in load_tool_profile("local-safe").tools


def test_profile_cli_list_and_show():
    listed = subprocess.run(
        [sys.executable, "-m", "belief", "tools", "profile", "list"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    shown = subprocess.run(
        [sys.executable, "-m", "belief", "tools", "profile", "show", "local-safe"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert listed.returncode == 0, listed.stderr
    assert shown.returncode == 0, shown.stderr
    assert json.loads(shown.stdout)["profile_id"] == "local-safe"
