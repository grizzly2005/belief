"""Bridge status normalization regressions."""

from __future__ import annotations

import pytest

from belief.bridges import BridgeRegistry, BridgeResult
from belief.bridges.belief_adapter import dict_to_finding

pytestmark = pytest.mark.security


def test_bridge_result_classifies_missing_tools():
    result = BridgeResult(source="bandit", errors=["bandit not found on PATH"])

    assert result.status == "missing"


def test_bridge_registry_classifies_crashes_and_argument_mismatch():
    registry = BridgeRegistry()

    def boom(**kwargs):
        raise RuntimeError("broken")

    def mismatch():
        return BridgeResult(source="mismatch")

    registry.register("boom", boom)
    registry.register("mismatch", mismatch)

    assert registry.run("boom").status == "failed"
    assert registry.run("mismatch", project_path=".").status == "skipped"
    assert registry.run("unknown").status == "missing"


def test_bridge_dict_to_finding_preserves_source_rule_and_location():
    finding = dict_to_finding({
        "source": "semgrep",
        "check_id": "python.lang.security.audit.eval",
        "message": "eval reaches user input",
        "path": "app.py",
        "line": 12,
        "cwe": "CWE-95",
    })

    assert finding is not None
    assert finding.source == "semgrep"
    assert finding.rule_id == "python.lang.security.audit.eval"
    assert finding.file == "app.py"
    assert finding.cwe == "CWE-95"
