from belief.tools import ToolRegistry


def test_registry_loads_builtin_bridge_ids():
    registry = ToolRegistry.with_builtin_bridges()
    expected = {
        "arjun",
        "authmatrix",
        "autorize",
        "codeql",
        "dradis",
        "evomaster",
        "faraday",
        "joern",
        "param_miner",
        "restler",
        "schemathesis",
        "semgrep",
        "threat_dragon",
        "zap",
    }
    assert set(registry.tool_ids()) == expected


def test_each_bridge_has_manifest_and_risk_profile():
    registry = ToolRegistry.with_builtin_bridges()
    for bridge in registry.list_tools():
        manifest = bridge.manifest()
        assert manifest.tool_id == bridge.tool_id
        assert manifest.name
        assert manifest.description
        assert manifest.risk is not None


def test_dynamic_bridges_are_not_safe_default():
    registry = ToolRegistry.with_builtin_bridges()
    for tool_id in {"arjun", "evomaster", "restler", "schemathesis", "zap"}:
        manifest = registry.get(tool_id).manifest()
        assert manifest.risk.network is True
        assert manifest.risk.safe_default is False


def test_recipe_only_safe_bridges_can_be_safe_default():
    registry = ToolRegistry.with_builtin_bridges()
    assert registry.get("param_miner").manifest().risk.safe_default is True
    assert registry.get("dradis").manifest().risk.safe_default is True
