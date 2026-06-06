import json
import subprocess
import sys
from pathlib import Path

from belief.importers.bandit_json import import_bandit_json
from belief.importers.burp_xml import import_burp_xml
from belief.importers.gitleaks_json import import_gitleaks_json
from belief.importers.har import import_har


FIXTURES = Path(__file__).parent / "fixtures" / "tools"


def test_bandit_import_maps_external_finding():
    result = import_bandit_json(FIXTURES / "bandit_sample.json")

    assert result.tool_id == "bandit"
    assert result.findings[0].rule_id == "B307"
    assert "CWE-94" in result.findings[0].cwe


def test_secret_and_header_importers_redact_sensitive_values():
    gitleaks = import_gitleaks_json(FIXTURES / "gitleaks_sample.json")
    har = import_har(FIXTURES / "traffic_sample.har")
    burp = import_burp_xml(FIXTURES / "burp_sample.xml")

    encoded = json.dumps([gitleaks.raw, [finding.raw for finding in gitleaks.findings], har.raw, burp.raw])
    assert "abc123secret" not in encoded
    assert "Bearer secret" not in encoded
    assert "session=secret" not in encoded


def test_importer_cli_acceptance_for_all_pack_tools(tmp_path):
    cases = {
        "bandit": "bandit_sample.json",
        "gitleaks": "gitleaks_sample.json",
        "pip-audit": "pip_audit_sample.json",
        "checkov": "checkov_sample.json",
        "nuclei": "nuclei_sample.json",
        "har": "traffic_sample.har",
        "burp": "burp_sample.xml",
    }
    for tool_id, filename in cases.items():
        output = tmp_path / f"{tool_id}.json"
        result = subprocess.run(
            [
                sys.executable, "-m", "belief", "tools", "import", tool_id,
                "--file", str(FIXTURES / filename),
                "--normalized-output", str(output),
            ],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, (tool_id, result.stderr)
        assert json.loads(output.read_text(encoding="utf-8"))["tool_id"].replace("_", "-") in {tool_id, "pip-audit"}
