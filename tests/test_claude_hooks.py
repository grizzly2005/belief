"""Contracts for BELIEF Claude Code Stop and PreToolUse hooks."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from belief.claude_hooks import (
    build_claude_hook_settings,
    handle_pre_tool_hook,
    handle_stop_hook,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]

SAFE_SOURCE = """\
import os

def read_asset(root, name):
    path = os.path.abspath(os.path.join(root, name))
    if os.path.commonpath([root, path]) != root:
        raise ValueError("outside root")
    return open(path).read()
"""

VULNERABLE_SOURCE = """\
import os

def read_asset(root, name):
    path = os.path.join(root, name)
    return open(path).read()
"""


def _git(repository: Path, *arguments: str) -> None:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_EMAIL": "hook@example.invalid",
            "GIT_AUTHOR_NAME": "BELIEF hook",
            "GIT_COMMITTER_EMAIL": "hook@example.invalid",
            "GIT_COMMITTER_NAME": "BELIEF hook",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr


def _workspace(tmp_path: Path) -> tuple[Path, Path]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    _git(workspace, "init", "--quiet")
    target = workspace / "assets.py"
    target.write_text(
        "def read_asset(root, name):\n    raise NotImplementedError\n",
        encoding="utf-8",
    )
    _git(workspace, "add", "assets.py")
    _git(workspace, "commit", "--quiet", "-m", "baseline")
    return workspace, target


def _stop_event(workspace: Path) -> dict:
    return {
        "hook_event_name": "Stop",
        "session_id": "session-123",
        "cwd": str(workspace),
        "stop_hook_active": False,
    }


def test_hook_settings_cover_stop_and_patch_recovery_tools():
    settings = build_claude_hook_settings(
        "/opt/belief/scripts/belief_claude_hook.py"
    )

    assert set(settings["hooks"]) == {"PreToolUse", "Stop"}
    policy = settings["hooks"]["PreToolUse"][0]
    stop = settings["hooks"]["Stop"][0]["hooks"][0]
    assert policy["matcher"] == "Bash|WebFetch|WebSearch"
    assert stop["type"] == "command"
    assert (
        stop["command"]
        == "python3 /opt/belief/scripts/belief_claude_hook.py"
    )
    assert stop["timeout"] == 60


def test_hook_settings_can_preserve_policy_without_belief_feedback():
    settings = build_claude_hook_settings(
        "/opt/belief/scripts/belief_claude_hook.py",
        include_stop_hook=False,
    )

    assert set(settings["hooks"]) == {"PreToolUse"}
    policy = settings["hooks"]["PreToolUse"][0]
    assert policy["matcher"] == "Bash|WebFetch|WebSearch"
    assert policy["hooks"][0]["type"] == "command"


def test_stop_hook_blocks_once_and_supplies_repair_feedback(tmp_path):
    workspace, target = _workspace(tmp_path)
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
    state_dir = tmp_path / "state"
    report_dir = tmp_path / "reports"

    decision = handle_stop_hook(
        _stop_event(workspace),
        state_dir=state_dir,
        report_dir=report_dir,
    )

    assert decision["decision"] == "block"
    assert "missing security guarantee" in decision["reason"]
    state = json.loads(
        (state_dir / "session-123.json").read_text(encoding="utf-8")
    )
    assert state["block_count"] == 1
    assert Path(state["last_report"]).is_file()


def test_stop_hook_allows_repaired_candidate(tmp_path):
    workspace, target = _workspace(tmp_path)
    state_dir = tmp_path / "state"
    report_dir = tmp_path / "reports"
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
    first = handle_stop_hook(
        _stop_event(workspace),
        state_dir=state_dir,
        report_dir=report_dir,
    )
    assert first["decision"] == "block"
    target.write_text(SAFE_SOURCE, encoding="utf-8")

    second = handle_stop_hook(
        {**_stop_event(workspace), "stop_hook_active": True},
        state_dir=state_dir,
        report_dir=report_dir,
    )

    assert second == {}
    state = json.loads(
        (state_dir / "session-123.json").read_text(encoding="utf-8")
    )
    assert state["status"] == "passed"


def test_stop_hook_does_not_loop_on_unchanged_patch(tmp_path):
    workspace, target = _workspace(tmp_path)
    state_dir = tmp_path / "state"
    report_dir = tmp_path / "reports"
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
    first = handle_stop_hook(
        _stop_event(workspace),
        max_blocks=3,
        state_dir=state_dir,
        report_dir=report_dir,
    )
    assert first["decision"] == "block"

    second = handle_stop_hook(
        {**_stop_event(workspace), "stop_hook_active": True},
        max_blocks=3,
        state_dir=state_dir,
        report_dir=report_dir,
    )

    assert "decision" not in second
    assert "bounded Stop-hook repair budget" in second["systemMessage"]


@pytest.mark.parametrize(
    "tool_name,command",
    [
        ("WebFetch", ""),
        ("WebSearch", ""),
        ("Bash", "git show HEAD~1:app.py"),
        ("Bash", "git log --oneline"),
        ("Bash", "curl https://github.com/example/project"),
        ("Bash", "cat .git/objects/ab/cdef"),
    ],
)
def test_pre_tool_hook_blocks_patch_recovery(tool_name, command):
    decision = handle_pre_tool_hook({
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": {"command": command},
    })

    output = decision["hookSpecificOutput"]
    assert output["permissionDecision"] == "deny"
    assert "anti-cheating" in output["permissionDecisionReason"]


@pytest.mark.parametrize(
    "command",
    [
        "python -m pytest -q",
        "git diff -- app.py",
        "grep -R \"parse_header\" .",
    ],
)
def test_pre_tool_hook_allows_local_development_commands(command):
    assert handle_pre_tool_hook({
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }) == {}


def test_hook_state_must_not_contaminate_candidate_workspace(tmp_path):
    workspace, target = _workspace(tmp_path)
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")

    with pytest.raises(ValueError, match="outside"):
        handle_stop_hook(
            _stop_event(workspace),
            state_dir=workspace / ".belief-state",
            report_dir=tmp_path / "reports",
        )


def test_hook_entrypoint_emits_json_only(tmp_path):
    workspace, target = _workspace(tmp_path)
    target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
    event = _stop_event(workspace)
    env = dict(os.environ)
    env.update(
        {
            "BELIEF_HOOK_STATE_DIR": str(tmp_path / "state"),
            "BELIEF_HOOK_REPORT_DIR": str(tmp_path / "reports"),
        }
    )

    completed = subprocess.run(
        [sys.executable, "scripts/belief_claude_hook.py"],
        cwd=ROOT,
        input=json.dumps(event),
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0
    assert completed.stderr == ""
    decision = json.loads(completed.stdout)
    assert decision["decision"] == "block"
