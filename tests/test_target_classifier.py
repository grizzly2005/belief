import json
import subprocess
import sys
from pathlib import Path

from belief.targeting import classify_target


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_APP = ROOT / "tests" / "fixtures" / "sample_app"


def test_classifies_python_repo():
    profile = classify_target(SAMPLE_APP)

    assert profile.target_type == "python_repo"
    assert "python" in profile.languages
    assert "code" in profile.recommended_flags


def test_classifies_url_without_network():
    profile = classify_target("https://app.example.test")

    assert profile.target_type == "url"
    assert profile.exists is False
    assert any("scope" in note for note in profile.safety_notes)


def test_classifies_har_and_burp_artifacts():
    har = classify_target(ROOT / "tests" / "fixtures" / "tools" / "traffic_sample.har")
    burp = classify_target(ROOT / "tests" / "fixtures" / "tools" / "burp_sample.xml")

    assert har.target_type == "har_file"
    assert burp.target_type == "burp_xml"


def test_classifies_only_real_pdx_bundle_as_pdx(tmp_path):
    unrelated = tmp_path / "ordinary.json"
    unrelated.write_text('{"meta": "ordinary metadata"}', encoding="utf-8")

    profile = classify_target(unrelated)

    assert profile.target_type == "json_file"


def test_target_classify_cli_writes_json(tmp_path):
    output = tmp_path / "target.json"
    result = subprocess.run(
        [sys.executable, "-m", "belief", "target", "classify", str(SAMPLE_APP), "--json-output", str(output)],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(output.read_text(encoding="utf-8"))["target_type"] == "python_repo"
