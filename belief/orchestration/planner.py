"""Run planner v1 for safe BELIEF orchestration."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from belief.scope import ScopePolicy, allow_tool, load_scope
from belief.targeting import classify_target
from belief.tools.availability import check_tool_availability
from belief.tools.capabilities import ToolCapability, load_builtin_capabilities
from belief.tools.profiles import load_tool_profile

from .models import RunCommand, RunPlan
from .output_layout import build_output_layout


MAX_PLAN_TIMEOUT_SECONDS = 3600


def build_run_plan(
    target: str,
    *,
    profile_id: str = "local-safe",
    flags: str = "auto",
    scope_file: str | None = None,
    output_dir: str = "out/run",
    timeout_seconds: int | None = None,
    budget: str = "balanced",
    reportability: bool = False,
) -> RunPlan:
    if timeout_seconds is not None and not 1 <= int(timeout_seconds) <= MAX_PLAN_TIMEOUT_SECONDS:
        raise ValueError(f"timeout must be between 1 and {MAX_PLAN_TIMEOUT_SECONDS} seconds")
    target_profile = classify_target(target)
    scope = load_scope(scope_file) if scope_file else None
    profile = load_tool_profile(profile_id)
    capabilities = load_builtin_capabilities()
    layout = build_output_layout(output_dir)
    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    commands: list[RunCommand] = []
    import_steps: list[dict[str, Any]] = []
    decisions: list[dict[str, Any]] = []

    for tool_id in profile.tools:
        capability = capabilities.get(tool_id)
        if capability is None:
            skipped.append({"tool_id": tool_id, "reason": "capability missing"})
            continue
        if not _relevant(capability, target_profile.to_dict(), flags):
            skipped.append({"tool_id": tool_id, "reason": "not relevant for target/profile flags"})
            continue
        decision = allow_tool(scope, capability, target)
        availability = check_tool_availability(capability, scope, target)
        decisions.append(decision.to_dict())

        if capability.can_import_only and not capability.can_run_local:
            import_steps.append({
                "tool_id": capability.tool_id,
                "status": availability.status,
                "import_format": capability.import_format,
                "reason": "import-only tool; provide an existing output file to import",
            })
            skipped.append({"tool_id": capability.tool_id, "reason": availability.reason, "status": availability.status})
            continue

        if not decision.allowed or availability.status != "installed":
            skipped.append({"tool_id": capability.tool_id, "reason": availability.reason, "status": availability.status})
            continue

        command = _command_for_tool(capability, target, layout, timeout_seconds, reportability=reportability)
        commands.append(command)
        selected.append({"tool_id": capability.tool_id, "status": availability.status, "category": capability.category})

    return RunPlan(
        target_profile=target_profile.to_dict(),
        scope_summary=_scope_summary(scope),
        selected_tools=tuple(selected),
        skipped_tools=tuple(sorted(skipped, key=lambda item: str(item.get("tool_id")))),
        commands=tuple(commands),
        import_steps=tuple(import_steps),
        merge_step={"enabled": True, "mode": "best_effort_normalized_merge"},
        audit_step={
            "enabled": True,
            "mode": "local_scan_when_applicable",
            "reportability": bool(reportability),
        },
        report_steps=({"format": "json"}, {"format": "markdown"}),
        output_layout=layout,
        safety_decisions=tuple(decisions),
        limitations=(
            "External tools are optional and skipped when unavailable.",
            "Dynamic/network tools require explicit scope and are denied by default.",
            "Planner v1 does not install external tools.",
        ),
    )


def write_run_plan(plan: RunPlan, path: str | Path) -> None:
    import json

    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(plan.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _relevant(capability: ToolCapability, target_profile: dict[str, Any], flags: str) -> bool:
    flag_set = {item.strip() for item in str(flags or "auto").split(",") if item.strip()}
    if "auto" in flag_set:
        flag_set.update(target_profile.get("recommended_flags") or [])
    if capability.tool_id == "belief":
        return target_profile.get("exists") and target_profile.get("target_type") not in {"url", "har_file", "burp_xml", "openapi_file", "pdx_json"}
    if capability.category == "secrets":
        return "secrets" in flag_set or "code" in flag_set
    if capability.category == "sca":
        return "sca" in flag_set
    if capability.category == "iac":
        return "iac" in flag_set
    if capability.category == "api":
        return "api" in flag_set
    if capability.category == "traffic":
        return "imported" in flag_set or "web-passive" in flag_set
    if capability.category == "dast":
        return "dynamic" in flag_set or "web-passive" in flag_set
    return "code" in flag_set or capability.category == "static"


def _command_for_tool(
    capability: ToolCapability,
    target: str,
    layout: dict[str, str],
    timeout_seconds: int | None,
    *,
    reportability: bool,
) -> RunCommand:
    raw_output = Path(layout["raw"]) / f"{capability.tool_id}.json"
    command_target = _command_target(target)
    normalized = (
        Path(layout["normalized"]) / capability.normalized_output_name
        if capability.normalized_output_name
        else None
    )
    if capability.tool_id == "belief":
        argv = [
            sys.executable,
            "-m",
            "belief",
            "scan",
            command_target,
            "--json-output",
            raw_output.as_posix(),
        ]
        if reportability:
            argv.append("--reportability")
    else:
        argv = tuple(
            item.replace("{target}", command_target).replace("{raw_output}", raw_output.as_posix())
            for item in capability.run_command_template
        )
    return RunCommand(
        tool_id=capability.tool_id,
        argv=tuple(argv),
        cwd=_cwd_for_target(target),
        raw_output=raw_output.as_posix(),
        normalized_output=normalized.as_posix() if normalized else None,
        timeout_seconds=int(timeout_seconds or capability.default_timeout_seconds),
        requires_network=capability.requires_network,
        requires_dynamic=capability.requires_dynamic,
        allowed_by_scope=True,
        tool_status="installed",
    )


def _scope_summary(scope: ScopePolicy | None) -> dict[str, Any]:
    if scope is None:
        return {"present": False, "mode": "absent", "rules": {}}
    payload = scope.to_dict()
    payload["present"] = True
    return payload


def _cwd_for_target(target: str) -> str:
    """Constrain local tool processes to the target directory when possible."""
    path = Path(target)
    if path.exists():
        return str((path if path.is_dir() else path.parent).resolve())
    return str(Path.cwd())


def _command_target(target: str) -> str:
    path = Path(target)
    return str(path.resolve()) if path.exists() else target


__all__ = ["build_run_plan", "write_run_plan"]
