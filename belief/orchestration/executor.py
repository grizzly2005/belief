"""Safe executor skeleton for BELIEF run plans."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from .models import EXECUTION_SUMMARY_SCHEMA_VERSION
from .output_layout import ensure_output_layout


def execute_run_plan(plan_path: str | Path) -> dict[str, Any]:
    plan_file = Path(plan_path)
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    layout = plan.get("output_layout") or {}
    ensure_output_layout(layout.get("root") or plan_file.parent.parent)

    completed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    raw_outputs: list[str] = []
    normalized_outputs: list[str] = []

    for command in plan.get("commands", []):
        if not _can_execute(command):
            skipped.append({
                "tool_id": command.get("tool_id"),
                "reason": command.get("skip_reason") or "not allowed or unavailable",
            })
            continue
        result = _run_command(command, layout)
        if result["returncode"] == 0:
            completed.append(result)
        else:
            failed.append(result)
        if command.get("raw_output"):
            raw_outputs.append(command["raw_output"])
        if command.get("normalized_output"):
            normalized_outputs.append(command["normalized_output"])

    unavailable = list(plan.get("skipped_tools", []))
    summary = {
        "schema_version": EXECUTION_SUMMARY_SCHEMA_VERSION,
        "plan": plan_file.as_posix(),
        "completed": completed,
        "skipped": skipped,
        "failed": failed,
        "unavailable": unavailable,
        "raw_outputs": sorted(set(raw_outputs)),
        "normalized_outputs": sorted(set(normalized_outputs)),
        "safety_decisions": plan.get("safety_decisions", []),
    }
    metadata_dir = Path((layout or {}).get("metadata") or plan_file.parent)
    metadata_dir.mkdir(parents=True, exist_ok=True)
    (metadata_dir / "execution-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def _can_execute(command: dict[str, Any]) -> bool:
    return (
        bool(command.get("allowed_by_scope"))
        and command.get("tool_status") == "installed"
        and isinstance(command.get("argv"), list)
        and bool(command.get("argv"))
    )


def _run_command(command: dict[str, Any], layout: dict[str, str]) -> dict[str, Any]:
    logs_dir = Path(layout.get("logs") or Path(command.get("raw_output", ".")).parent)
    logs_dir.mkdir(parents=True, exist_ok=True)
    tool_id = str(command.get("tool_id") or "unknown")
    try:
        completed = subprocess.run(
            [str(item) for item in command["argv"]],
            shell=False,
            cwd=str(command.get("cwd") or Path.cwd()),
            timeout=int(command.get("timeout_seconds") or 180),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={
                **os.environ,
                "PYTHONUTF8": "1",
                "PYTHONIOENCODING": "utf-8",
            },
        )
        stdout = completed.stdout or ""
        stderr = _redact(completed.stderr or "")
        returncode = int(completed.returncode)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = "timeout expired"
        returncode = 124
    (logs_dir / f"{tool_id}.stdout.log").write_text(_redact(stdout), encoding="utf-8")
    (logs_dir / f"{tool_id}.stderr.log").write_text(_redact(stderr), encoding="utf-8")
    raw_output = command.get("raw_output")
    if raw_output and stdout and not Path(raw_output).exists():
        raw_path = Path(raw_output)
        raw_path.parent.mkdir(parents=True, exist_ok=True)
        raw_path.write_text(_redact(stdout), encoding="utf-8")
    return {
        "tool_id": tool_id,
        "returncode": returncode,
        "stdout_log": (logs_dir / f"{tool_id}.stdout.log").as_posix(),
        "stderr_log": (logs_dir / f"{tool_id}.stderr.log").as_posix(),
    }


def _redact(text: str) -> str:
    import re

    patterns = [
        re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer|basic)\s+[^\s,;]+"),
        re.compile(r"(?i)(cookie\s*[:=]\s*)[^;\n]+"),
        re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
    ]
    for pattern in patterns:
        text = pattern.sub(r"\1[REDACTED]", text)
    return text


__all__ = ["execute_run_plan"]
