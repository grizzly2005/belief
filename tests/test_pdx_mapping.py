from pathlib import Path

from belief.pdx.io import read_pdx_bundle
from belief.pdx.mapping import pdx_bundle_to_normalized_tool_result


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def test_pdx_bundle_maps_to_normalized_tool_result():
    bundle = read_pdx_bundle(FIXTURES / "pdx_bundle_sample.json")
    result = pdx_bundle_to_normalized_tool_result(bundle)

    assert result.tool_id == "pdx"
    assert len(result.findings) == 1
    assert result.findings[0].rule_id == "PDX_AUTH_BYPASS"
    assert result.findings[0].cwe == ["CWE-862"]
    assert result.findings[0].confidence == "medium"
    assert result.findings[0].raw["pdx"]["validation_results"][0]["outcome"] == "inconclusive"


def test_pdx_chain_maps_to_passive_review_attack_path():
    bundle = read_pdx_bundle(FIXTURES / "pdx_bundle_sample.json")
    result = pdx_bundle_to_normalized_tool_result(bundle)

    assert len(result.attack_paths) == 1
    assert result.attack_paths[0].steps[0].method == "REVIEW"
    assert "Review PDX delta delta-auth-1" in result.attack_paths[0].evidence_needed[0]
