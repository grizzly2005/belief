"""Safety gates for BELIEF tool bridge execution."""

from __future__ import annotations

from .errors import ToolSafetyError
from .schemas import ToolInput, ToolManifest


def validate_tool_input(manifest: ToolManifest, tool_input: ToolInput) -> None:
    """Reject risky tool execution unless the caller explicitly opted in."""
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


def is_dynamic_or_network(manifest: ToolManifest) -> bool:
    risk = manifest.risk
    return bool(risk.network or risk.active_scanning or risk.replays_requests or risk.fuzzing)


__all__ = ["is_dynamic_or_network", "validate_tool_input"]
