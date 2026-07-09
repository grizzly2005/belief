"""Safe executor skeleton for BELIEF run plans."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from belief.scope import ScopePolicy, allow_tool, validate_scope
from belief.tools.availability import check_tool_availability
from belief.tools.capabilities import ToolCapability, load_builtin_capabilities

from .models import EXECUTION_SUMMARY_SCHEMA_VERSION, RUN_PLAN_SCHEMA_VERSION
from .output_layout import ensure_output_layout


MAX_EXECUTION_TIMEOUT_SECONDS = 3600


def execute_run_plan(plan_path: str | Path) -> dict[str, Any]:
    plan_file = Path(plan_path)
    plan = json.loads(plan_file.read_text(encoding="utf-8"))
    _validate_plan_shape(plan)
    layout = plan.get("output_layout") or {}
    ensure_output_layout(layout.get("root") or plan_file.parent.parent)

    completed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    raw_outputs: list[str] = []
    normalized_outputs: list[str] = []
    capabilities = load_builtin_capabilities()
    scope = _scope_from_plan(plan)

    for command in plan.get("commands", []):
        reason = _command_skip_reason(command, plan, layout, capabilities, scope)
        if reason:
            skipped.append({
                "tool_id": command.get("tool_id"),
                "reason": reason,
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


def _validate_plan_shape(plan: Any) -> None:
    if not isinstance(plan, dict):
        raise ValueError("run plan must be a JSON object")
    if plan.get("schema_version") != RUN_PLAN_SCHEMA_VERSION:
        raise ValueError("unsupported or missing run plan schema_version")
    if not isinstance(plan.get("target_profile"), dict):
        raise ValueError("run plan is missing target_profile")
    if not isinstance(plan.get("output_layout"), dict):
        raise ValueError("run plan is missing output_layout")
    if not isinstance(plan.get("commands"), list):
        raise ValueError("run plan commands must be a list")


def _scope_from_plan(plan: dict[str, Any]) -> ScopePolicy | None:
    raw = plan.get("scope_summary")
    if not isinstance(raw, dict) or not raw.get("present"):
        return None
    scope = ScopePolicy.from_dict(raw)
    validate_scope(scope)
    return scope


def _command_skip_reason(
    command: Any,
    plan: dict[str, Any],
    layout: dict[str, Any],
    capabilities: dict[str, ToolCapability],
    scope: ScopePolicy | None,
) -> str | None:
    if not isinstance(command, dict):
        return "invalid command entry"
    tool_id = str(command.get("tool_id") or "")
    capability = capabilities.get(tool_id)
    if capability is None:
        return "tool is not in the BELIEF capability registry"
    if not bool(command.get("allowed_by_scope")):
        return command.get("skip_reason") or "not allowed by plan scope"
    if capability.requires_network or capability.requires_dynamic:
        return "network and dynamic tool execution is disabled in executor v1"
    decision = allow_tool(scope, capability, str(plan["target_profile"].get("target") or ""))
    if not decision.allowed:
        return decision.reason
    availability = check_tool_availability(capability, scope, str(plan["target_profile"].get("target") or ""))
    if availability.status != "installed":
        return availability.reason
    if command.get("tool_status") != "installed":
        return "tool is not marked installed in plan"
    try:
        timeout = int(command.get("timeout_seconds"))
    except (TypeError, ValueError):
        return "command timeout is invalid"
    if not 1 <= timeout <= MAX_EXECUTION_TIMEOUT_SECONDS:
        return f"command timeout must be between 1 and {MAX_EXECUTION_TIMEOUT_SECONDS} seconds"
    if not _command_matches_capability(command, plan, layout, capability):
        return "command does not match the generated capability template"
    return None


def _command_matches_capability(
    command: dict[str, Any],
    plan: dict[str, Any],
    layout: dict[str, Any],
    capability: ToolCapability,
) -> bool:
    argv = command.get("argv")
    target = _command_target(str(plan["target_profile"].get("target") or ""))
    raw_output = str(command.get("raw_output") or "")
    if not isinstance(argv, list) or not argv or not target or not raw_output:
        return False
    if not _path_is_within(raw_output, layout.get("raw")):
        return False
    expected_cwd = _expected_cwd(target)
    if Path(str(command.get("cwd") or "")).resolve(strict=False) != expected_cwd:
        return False
    if capability.tool_id == "belief":
        expected = [sys.executable, "-m", "belief", "scan", target, "--json-output", raw_output]
        if isinstance(plan.get("audit_step"), dict) and plan["audit_step"].get("reportability") is True:
            expected.append("--reportability")
    else:
        expected = [
            item.replace("{target}", target).replace("{raw_output}", raw_output)
            for item in capability.run_command_template
        ]
    return [str(item) for item in argv] == expected


def _path_is_within(path: str, root: Any) -> bool:
    if not root:
        return False
    try:
        Path(path).resolve(strict=False).relative_to(Path(str(root)).resolve(strict=False))
        return True
    except ValueError:
        return False


def _expected_cwd(target: str) -> Path:
    path = Path(target)
    return (path if path.is_dir() else path.parent).resolve(strict=False) if path.exists() else Path.cwd().resolve()


def _command_target(target: str) -> str:
    path = Path(target)
    return str(path.resolve()) if path.exists() else target


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
