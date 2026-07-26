"""Claude Code hook adapters for BELIEF's oracle-free patch reviewer."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import tempfile
from pathlib import Path
from typing import Any, Callable, Mapping

from .patch_review import review_candidate_patch


_BLOCKED_BASH_PATTERNS = (
    re.compile(
        r"(?:^|[;&|]\s*)git\s+"
        r"(?:log|show|rev-list|fetch|pull|clone|remote)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\b(?:curl|wget|gh)\b", re.IGNORECASE),
    re.compile(
        r"(?:github\.com|raw\.githubusercontent\.com)",
        re.IGNORECASE,
    ),
    re.compile(r"\.git[/\\](?:objects|logs|refs)\b", re.IGNORECASE),
)


def build_claude_hook_settings(
    hook_script: str | Path,
    *,
    python_command: str = "python3",
    stop_timeout_seconds: int = 60,
    policy_timeout_seconds: int = 10,
    include_stop_hook: bool = True,
) -> dict[str, Any]:
    """Build portable Claude settings for policy and optional BELIEF feedback."""

    if not 1 <= stop_timeout_seconds <= 600:
        raise ValueError("stop_timeout_seconds must be between 1 and 600")
    if not 1 <= policy_timeout_seconds <= 60:
        raise ValueError("policy_timeout_seconds must be between 1 and 60")
    command = shlex.join([
        str(python_command),
        str(hook_script),
    ])
    hooks: dict[str, Any] = {
        "PreToolUse": [
            {
                "matcher": "Bash|WebFetch|WebSearch",
                "hooks": [
                    {
                        "type": "command",
                        "command": command,
                        "timeout": policy_timeout_seconds,
                    }
                ],
            }
        ],
    }
    if include_stop_hook:
        hooks["Stop"] = [
            {
                "hooks": [
                    {
                        "type": "command",
                        "command": command,
                        "timeout": stop_timeout_seconds,
                    }
                ]
            }
        ]
    return {"hooks": hooks}


def handle_claude_hook(
    event: Mapping[str, Any],
    *,
    max_stop_blocks: int = 1,
    state_dir: str | Path | None = None,
    report_dir: str | Path | None = None,
    reviewer: Callable[..., dict[str, Any]] = review_candidate_patch,
) -> dict[str, Any]:
    """Dispatch a Claude Code hook event to the relevant BELIEF policy."""

    event_name = str(event.get("hook_event_name") or "")
    if event_name == "Stop":
        return handle_stop_hook(
            event,
            max_blocks=max_stop_blocks,
            state_dir=state_dir,
            report_dir=report_dir,
            reviewer=reviewer,
        )
    if event_name == "PreToolUse":
        return handle_pre_tool_hook(event)
    return {}


def handle_stop_hook(
    event: Mapping[str, Any],
    *,
    max_blocks: int = 1,
    state_dir: str | Path | None = None,
    report_dir: str | Path | None = None,
    reviewer: Callable[..., dict[str, Any]] = review_candidate_patch,
) -> dict[str, Any]:
    """Review the current diff and block Stop while one bounded repair is due."""

    if not 0 <= max_blocks <= 3:
        raise ValueError("max_blocks must be between 0 and 3")
    workspace = Path(str(event.get("cwd") or "")).resolve()
    if not workspace.is_dir():
        raise ValueError(f"Claude hook cwd is not a directory: {workspace}")
    session_id = str(event.get("session_id") or "unknown")
    session_key = _session_key(session_id)
    state_root = Path(
        state_dir
        or Path(tempfile.gettempdir()) / "belief-claude-hook-state"
    ).resolve()
    report_root = Path(
        report_dir
        or Path(tempfile.gettempdir()) / "belief-claude-hook-reports"
    ).resolve()
    _require_outside_workspace(state_root, workspace, "state_dir")
    _require_outside_workspace(report_root, workspace, "report_dir")

    state_path = state_root / f"{session_key}.json"
    state = _load_state(state_path)
    review = reviewer(workspace)
    patch_sha = str(review.get("patch_sha256") or "")
    block_count = int(state.get("block_count", 0) or 0)

    report_path = (
        report_root
        / session_key
        / f"review-{block_count:02d}.json"
    )
    _write_json(report_path, review)

    if review.get("status") == "passed":
        _write_json(state_path, {
            "block_count": block_count,
            "last_patch_sha256": patch_sha,
            "status": "passed",
            "last_report": str(report_path),
        })
        return {}

    same_patch = bool(
        patch_sha
        and patch_sha == str(state.get("last_patch_sha256") or "")
    )
    if block_count >= max_blocks or same_patch:
        _write_json(state_path, {
            "block_count": block_count,
            "last_patch_sha256": patch_sha,
            "status": (
                "stalled" if same_patch else "block_limit_reached"
            ),
            "last_report": str(report_path),
        })
        return {
            "systemMessage": (
                "BELIEF still reports an actionable candidate-patch risk, "
                "but the bounded Stop-hook repair budget is exhausted. "
                f"Review artifact: {report_path}"
            )
        }

    feedback = str(review.get("feedback") or "").strip()
    block_count += 1
    _write_json(state_path, {
        "block_count": block_count,
        "last_patch_sha256": patch_sha,
        "status": "blocked_for_repair",
        "last_report": str(report_path),
    })
    return {
        "decision": "block",
        "reason": feedback[:8_000],
    }


def handle_pre_tool_hook(event: Mapping[str, Any]) -> dict[str, Any]:
    """Deny obvious benchmark patch-recovery tools while allowing local work."""

    tool_name = str(event.get("tool_name") or "")
    if tool_name in {"WebFetch", "WebSearch"}:
        return _deny_tool(
            "Web lookup is disabled by the BELIEF anti-cheating policy "
            "for this benchmark attempt. Reason from the sanitized local "
            "workspace only."
        )
    if tool_name != "Bash":
        return {}
    tool_input = event.get("tool_input")
    command = ""
    if isinstance(tool_input, Mapping):
        command = str(tool_input.get("command") or "")
    for pattern in _BLOCKED_BASH_PATTERNS:
        if pattern.search(command):
            return _deny_tool(
                "Command blocked by BELIEF anti-cheating policy: do not "
                "inspect Git history or use network patch-recovery tools. "
                "Local tests, source inspection, and `git diff` of your "
                "current worktree remain allowed."
            )
    return {}


def _deny_tool(reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }


def _session_key(session_id: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.-]+", "-", session_id).strip(".-")
    if cleaned and len(cleaned) <= 96:
        return cleaned
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]


def _load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _require_outside_workspace(
    path: Path,
    workspace: Path,
    label: str,
) -> None:
    try:
        path.relative_to(workspace)
    except ValueError:
        return
    raise ValueError(
        f"{label} must be outside the candidate workspace: {path}"
    )


__all__ = [
    "build_claude_hook_settings",
    "handle_claude_hook",
    "handle_pre_tool_hook",
    "handle_stop_hook",
]
