from pathlib import Path

from belief.pdx.io import read_pdx_bundle, write_pdx_bundle
from belief.pdx.models import PDXBundle, PDXDelta


FIXTURES = Path(__file__).parent / "fixtures" / "pdx"


def test_read_write_pdx_bundle(tmp_path):
    bundle = read_pdx_bundle(FIXTURES / "pdx_bundle_sample.json")
    output = tmp_path / "bundle.json"

    write_pdx_bundle(bundle, output)
    loaded = read_pdx_bundle(output)

    assert loaded.to_dict() == bundle.to_dict()


def test_pdx_io_redacts_sensitive_values(tmp_path):
    bundle = PDXBundle(deltas=(
        PDXDelta(
            id="secret-delta",
            description="secret header sample",
            raw={"headers": {"Authorization": "Bearer secret-token-value"}},
        ),
    ))
    output = tmp_path / "bundle.json"
    write_pdx_bundle(bundle, output)

    text = output.read_text(encoding="utf-8")
    assert "secret-token-value" not in text
    assert "[REDACTED]" in text
