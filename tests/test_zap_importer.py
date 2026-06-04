import json

from belief.importers.zap_json import import_zap_json


def test_zap_json_maps_alerts_to_external_findings(tmp_path):
    payload = {
        "site": [{
            "alerts": [{
                "pluginid": "40012",
                "alert": "Cross Site Scripting",
                "risk": "High",
                "confidence": "Medium",
                "desc": "Reflected input",
                "instances": [{
                    "uri": "https://example.test/search?q=x",
                    "param": "q",
                    "evidence": "<script>",
                }],
            }]
        }]
    }
    path = tmp_path / "zap.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    findings = import_zap_json(path)
    assert len(findings) == 1
    assert findings[0].tool_id == "zap"
    assert findings[0].rule_id == "40012"
    assert findings[0].route == "https://example.test/search?q=x"
    assert "q" in findings[0].evidence
