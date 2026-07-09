"""Safety gates for BELIEF tool bridge execution."""

from __future__ import annotations

from belief.scope import allow_tool, load_scope

from .errors import ToolSafetyError
from .schemas import ToolInput, ToolManifest


MAX_TOOL_TIMEOUT_SECONDS = 3600


def validate_tool_input(manifest: ToolManifest, tool_input: ToolInput) -> None:
    """Reject risky tool execution unless the caller explicitly opted in."""
    try:
        timeout = int(tool_input.timeout_seconds)
    except (TypeError, ValueError):
        timeout = 0
    if not 1 <= timeout <= MAX_TOOL_TIMEOUT_SECONDS:
        raise ToolSafetyError(
            f"timeout_seconds must be between 1 and {MAX_TOOL_TIMEOUT_SECONDS}"
        )
    risk = manifest.risk
    dynamic = risk.active_scanning or risk.replays_requests or risk.fuzzing or risk.network
    if dynamic and not tool_input.allow_dynamic:
        raise ToolSafetyError(
            f"{manifest.tool_id} can perform dynamic activity; pass allow_dynamic=True "
            "and an explicit scope file to run it."
        )
    if risk.network and not tool_input.allow_network:
        raise ToolSafetyError(
            f"{manifest.tool_id} can use network access; pass allow_network=True explicitly."
        )
    if dynamic and tool_input.allow_dynamic and tool_input.scope_file is None:
        raise ToolSafetyError(
            f"{manifest.tool_id} requires an explicit scope_file for dynamic execution."
        )
    if risk.requires_auth_tokens:
        forbidden = {"cookie", "cookies", "authorization", "auth_header", "token", "secret"}
        present = forbidden & set(str(key).lower() for key in tool_input.config)
        if present:
            raise ToolSafetyError(
                "Do not pass auth tokens, cookies, or secrets through tool config files."
            )
    if tool_input.scope_file is not None:
        _validate_scope_policy(manifest, tool_input, dynamic)


def is_dynamic_or_network(manifest: ToolManifest) -> bool:
    risk = manifest.risk
    return bool(risk.network or risk.active_scanning or risk.replays_requests or risk.fuzzing)


def _validate_scope_policy(manifest: ToolManifest, tool_input: ToolInput, dynamic: bool) -> None:
    """Apply the v1 JSON scope engine to legacy bridge execution."""
    try:
        scope = load_scope(tool_input.scope_file)
    except (OSError, ValueError) as exc:
        raise ToolSafetyError(f"invalid BELIEF scope policy: {exc}") from exc

    capability = {
        "tool_id": manifest.tool_id,
        "requires_network": manifest.risk.network,
        "requires_dynamic": dynamic,
        "requires_scope": dynamic,
        "capabilities": [
            *(["active_scan"] if manifest.risk.active_scanning else []),
            *(["fuzzing"] if manifest.risk.fuzzing else []),
        ],
    }
    target = str(tool_input.target) if tool_input.target is not None else ""
    decision = allow_tool(scope, capability, target)
    if not decision.allowed:
        raise ToolSafetyError(f"{manifest.tool_id} denied by BELIEF scope: {decision.reason}")


__all__ = ["MAX_TOOL_TIMEOUT_SECONDS", "is_dynamic_or_network", "validate_tool_input"]
