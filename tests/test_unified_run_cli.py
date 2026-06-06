import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SAMPLE_APP = ROOT / "tests" / "fixtures" / "sample_app"
SCOPE = ROOT / "tests" / "fixtures" / "scope" / "local_safe_scope.json"


def test_unified_run_cli_writes_manifest(tmp_path):
    output_dir = tmp_path / "run"
    result = subprocess.run(
        [
            sys.executable, "-m", "belief", "run", str(SAMPLE_APP),
            "--profile", "local-safe",
            "--flags", "auto",
            "--scope", str(SCOPE),
            "--output-dir", str(output_dir),
            "--reportability",
            "--reason",
        ],
        text=True,
        capture_output=True,
        timeout=60,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    manifest = json.loads((output_dir / "metadata" / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == "belief.run_manifest.v1"
    assert manifest["reportability_requested"] is True
