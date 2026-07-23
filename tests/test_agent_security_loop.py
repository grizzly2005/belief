"""Contracts for the bounded BELIEF agent security feedback loop."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from belief.agent_security_loop import run_agent_security_loop


pytestmark = pytest.mark.security


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
            "GIT_AUTHOR_EMAIL": "agent-loop@example.invalid",
            "GIT_AUTHOR_NAME": "BELIEF agent loop",
            "GIT_COMMITTER_EMAIL": "agent-loop@example.invalid",
            "GIT_COMMITTER_NAME": "BELIEF agent loop",
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


def _repository(tmp_path: Path) -> tuple[Path, Path]:
    repository = tmp_path / "agent-workspace"
    repository.mkdir()
    _git(repository, "init", "--quiet")
    target = repository / "assets.py"
    target.write_text(
        "def read_asset(root, name):\n    raise NotImplementedError\n",
        encoding="utf-8",
    )
    _git(repository, "add", "assets.py")
    _git(repository, "commit", "--quiet", "-m", "masked baseline")
    return repository, target


def test_security_loop_repairs_candidate_in_same_attempt(tmp_path):
    repository, target = _repository(tmp_path)
    prompts: list[str] = []

    def run_turn(prompt: str, round_index: int):
        prompts.append(prompt)
        target.write_text(
            VULNERABLE_SOURCE if round_index == 0 else SAFE_SOURCE,
            encoding="utf-8",
        )
        return {
            "success": True,
            "return_code": 0,
            "stdout": f"round {round_index}",
            "execution_time": 2.0 + round_index,
        }

    payload = run_agent_security_loop(
        repository,
        "Implement asset loading",
        run_turn,
        max_review_rounds=1,
    )

    assert payload["schema_version"] == "belief.agent_security_loop.v1"
    assert payload["status"] == "completed"
    assert payload["stop_reason"] == "security_review_passed"
    assert payload["turn_count"] == 2
    assert payload["review_round_count"] == 1
    assert payload["reviews"][0]["status"] == "review_required"
    assert payload["reviews"][1]["status"] == "passed"
    assert "oracle-free security review" in prompts[1]
    assert "hidden tests" in prompts[1]
    assert "os.path.commonpath" in payload["final_patch"]


def test_security_loop_respects_zero_repair_budget(tmp_path):
    repository, target = _repository(tmp_path)

    def run_turn(_prompt: str, _round_index: int):
        target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
        return {"success": True, "return_code": 0}

    payload = run_agent_security_loop(
        repository,
        "Implement asset loading",
        run_turn,
        max_review_rounds=0,
    )

    assert payload["status"] == "needs_review"
    assert payload["stop_reason"] == "review_round_limit"
    assert payload["turn_count"] == 1
    assert payload["final_review_status"] == "review_required"


def test_security_loop_stops_when_repair_does_not_change_patch(tmp_path):
    repository, target = _repository(tmp_path)

    def run_turn(_prompt: str, _round_index: int):
        target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
        return {"success": True, "return_code": 0}

    payload = run_agent_security_loop(
        repository,
        "Implement asset loading",
        run_turn,
        max_review_rounds=3,
    )

    assert payload["status"] == "needs_review"
    assert payload["stop_reason"] == "no_patch_change"
    assert payload["turn_count"] == 2


def test_security_loop_rejects_unbounded_review_rounds(tmp_path):
    repository, _target = _repository(tmp_path)

    with pytest.raises(ValueError, match="between 0 and 3"):
        run_agent_security_loop(
            repository,
            "Implement asset loading",
            lambda _prompt, _round: {},
            max_review_rounds=4,
        )


def test_security_loop_digest_excludes_runtime_and_transcript_noise(tmp_path):
    repository, target = _repository(tmp_path)
    invocation = 0

    def run_turn(_prompt: str, _round_index: int):
        nonlocal invocation
        invocation += 1
        target.write_text(VULNERABLE_SOURCE, encoding="utf-8")
        return {
            "success": True,
            "return_code": 0,
            "stdout": f"nondeterministic transcript {invocation}",
            "stderr": f"diagnostic {invocation}",
            "execution_time": float(invocation),
        }

    first_clock = iter((10.0, 11.0))
    second_clock = iter((30.0, 39.0))
    first = run_agent_security_loop(
        repository,
        "Implement asset loading",
        run_turn,
        max_review_rounds=0,
        clock=lambda: next(first_clock),
    )
    second = run_agent_security_loop(
        repository,
        "Implement asset loading",
        run_turn,
        max_review_rounds=0,
        clock=lambda: next(second_clock),
    )

    assert first["duration_seconds"] == 1.0
    assert second["duration_seconds"] == 9.0
    assert first["deterministic_digest"] == second["deterministic_digest"]
