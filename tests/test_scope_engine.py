import json
import subprocess
import sys
from pathlib import Path

from belief.scope import allow_tool, is_excluded, is_in_scope, load_scope
from belief.tools.capabilities import load_tool_capability


FIXTURES = Path(__file__).parent / "fixtures" / "scope"


def test_scope_loads_and_validates_safe_defaults():
    scope = load_scope(FIXTURES / "local_safe_scope.json")

    assert scope.schema_version == "belief.scope.v1"
    assert scope.rules.allow_network is False
    assert scope.redaction["authorization"] is True


def test_exclusions_override_inclusions():
    scope = load_scope(FIXTURES / "local_safe_scope.json")

    assert is_in_scope(scope, "tests/fixtures/sample_app/app.py") is True
    assert is_excluded(scope, "tests/fixtures/sample_app/private/secret.py") is True
    assert is_in_scope(scope, "tests/fixtures/sample_app/private/secret.py") is False


def test_relative_scope_does_not_match_unrelated_suffix_path(tmp_path):
    scope = load_scope(FIXTURES / "local_safe_scope.json")
    unrelated = tmp_path / "other" / "sample_app" / "app.py"

    assert is_in_scope(scope, str(unrelated)) is False


def test_network_dynamic_tool_denied_without_scope_permission():
    scope = load_scope(FIXTURES / "local_safe_scope.json")
    nuclei = load_tool_capability("nuclei")

    decision = allow_tool(scope, nuclei, "https://app.example.test")

    assert decision.allowed is False
    assert "network" in decision.reason


def test_scope_validate_cli_outputs_json():
    result = subprocess.run(
        [sys.executable, "-m", "belief", "scope", "validate", "--file", str(FIXTURES / "local_safe_scope.json")],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["passed"] is True
