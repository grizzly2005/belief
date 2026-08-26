import json
from pathlib import Path


SCHEMAS = [
    "belief-pdx-v1.schema.json",
    "belief-validation-result-v1.schema.json",
    "belief-validation-proof-v1.schema.json",
    "belief-feedback-v1.schema.json",
    "belief-sft-v1.schema.json",
    "belief-sft-v2.schema.json",
    "belief-reasoning-v1.schema.json",
    "belief-holdout-attestation-v1.schema.json",
    "belief.exploration-objective.v1.schema.json",
    "belief.path-artifact.v1.schema.json",
]


def test_minimal_schema_files_exist_and_are_valid_json():
    root = Path(__file__).resolve().parents[1] / "schemas"
    for name in SCHEMAS:
        path = root / name
        assert path.exists(), name
        payload = json.loads(path.read_text(encoding="utf-8"))
        assert payload["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert payload["type"] == "object"
