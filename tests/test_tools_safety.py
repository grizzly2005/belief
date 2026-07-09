import pytest
from pathlib import Path

from belief.tools import ToolInput, ToolRegistry
from belief.tools.errors import ToolSafetyError
from belief.tools.safety import validate_tool_input


def test_dynamic_tool_without_flags_is_rejected():
    manifest = ToolRegistry.with_builtin_bridges().get("zap").manifest()
    with pytest.raises(ToolSafetyError, match="dynamic"):
        validate_tool_input(manifest, ToolInput())


def test_network_tool_without_allow_network_is_rejected(tmp_path):
    manifest = ToolRegistry.with_builtin_bridges().get("schemathesis").manifest()
    scope = Path(__file__).parent / "fixtures" / "scope" / "local_safe_scope.json"
    with pytest.raises(ToolSafetyError, match="network"):
        validate_tool_input(manifest, ToolInput(allow_dynamic=True, scope_file=scope))


def test_dynamic_tool_requires_scope_file():
    manifest = ToolRegistry.with_builtin_bridges().get("restler").manifest()
    with pytest.raises(ToolSafetyError, match="scope_file"):
        validate_tool_input(manifest, ToolInput(allow_dynamic=True, allow_network=True))


def test_tool_timeout_must_be_bounded():
    manifest = ToolRegistry.with_builtin_bridges().get("semgrep").manifest()
    with pytest.raises(ToolSafetyError, match="timeout_seconds"):
        validate_tool_input(manifest, ToolInput(timeout_seconds=0))


def test_dynamic_tool_scope_policy_denies_network_even_with_flags():
    manifest = ToolRegistry.with_builtin_bridges().get("zap").manifest()
    scope = Path(__file__).parent / "fixtures" / "scope" / "local_safe_scope.json"
    with pytest.raises(ToolSafetyError, match="denied by BELIEF scope"):
        validate_tool_input(
            manifest,
            ToolInput(
                target=Path("tests/fixtures/sample_app"),
                allow_dynamic=True,
                allow_network=True,
                scope_file=scope,
            ),
        )


def test_passive_safe_import_tool_is_allowed():
    manifest = ToolRegistry.with_builtin_bridges().get("codeql").manifest()
    validate_tool_input(manifest, ToolInput())


def test_secret_like_config_keys_are_rejected_for_token_tools(tmp_path):
    manifest = ToolRegistry.with_builtin_bridges().get("autorize").manifest()
    scope = Path(__file__).parent / "fixtures" / "scope" / "local_safe_scope.json"
    with pytest.raises(ToolSafetyError, match="auth tokens"):
        validate_tool_input(
            manifest,
            ToolInput(
                allow_dynamic=True,
                scope_file=scope,
                config={"cookie": "do-not-store"},
            ),
        )
