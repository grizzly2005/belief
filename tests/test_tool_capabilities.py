from belief.tools.capabilities import load_builtin_capabilities, load_tool_capability


def test_capability_registry_loads_expected_tools():
    capabilities = load_builtin_capabilities()

    for tool_id in {"belief", "semgrep", "bandit", "gitleaks", "pip_audit", "checkov", "nuclei", "har", "burp"}:
        assert tool_id in capabilities


def test_dynamic_tools_require_scope_and_network():
    nuclei = load_tool_capability("nuclei")

    assert nuclei.requires_network is True
    assert nuclei.requires_dynamic is True
    assert nuclei.requires_scope is True
    assert nuclei.can_import_only is True
