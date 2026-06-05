import json
from pathlib import Path

from belief.pdx.models import PDXBundle, PDXDelta, PDXVerdict


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def test_pdx_bundle_round_trip_is_stable():
    payload = json.loads((FIXTURES / "pdx_bundle_sample.json").read_text(encoding="utf-8"))
    bundle = PDXBundle.from_dict(payload)
    round_trip = PDXBundle.from_dict(bundle.to_dict())

    assert round_trip.to_dict() == bundle.to_dict()
    assert bundle.schema_version == "belief.pdx.v1"
    assert bundle.deltas[0].id == "delta-auth-1"


def test_pdx_delta_supports_vector_dims_list():
    payload = json.loads((FIXTURES / "pdx_delta_sample.json").read_text(encoding="utf-8"))
    delta = PDXDelta.from_dict(payload)

    assert delta.vector["severity"] == 0.7
    assert delta.vector["confidence"] == 0.6
    assert delta.vector["exploitability"] == 0.4


def test_pdx_verdict_normalizes_result():
    verdict = PDXVerdict.from_dict({
        "delta_ref": "delta-1",
        "result": "vulnerable",
        "weight": 1.5,
    })

    assert verdict.result == "VULNERABLE"
    assert verdict.weight == 1.0
