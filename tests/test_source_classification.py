"""Tests for the fail-closed Python source classification gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from belief.source_classification import (
    SOURCE_CLASSIFICATION_SCHEMA_VERSION,
    SourceClassificationError,
    build_python_inventory,
    check_python3_sources,
    load_source_classification,
)

pytestmark = pytest.mark.security


def _write_manifest(
    root: Path,
    *,
    classifications: list[dict] | None = None,
    python3_roots: list[str] | None = None,
) -> Path:
    manifest = root / "classification.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": SOURCE_CLASSIFICATION_SCHEMA_VERSION,
                "python3_roots": python3_roots or ["belief"],
                "classifications": classifications or [],
            }
        ),
        encoding="utf-8",
    )
    return manifest


def _legacy_entry(root: Path, prefix: str) -> dict:
    count, digest = build_python_inventory(root, prefix)
    return {
        "classification_id": "legacy_z3_playground_python2",
        "path_prefix": prefix,
        "language": "python2",
        "role": "vendored_reference_examples",
        "python3_compile": "excluded",
        "execution": "forbidden",
        "expected_python_file_count": count,
        "inventory_sha256": digest,
    }


def test_repository_classification_is_exact_and_python3_gate_passes():
    repo_root = Path(__file__).resolve().parents[1]

    report = check_python3_sources(repo_root)

    assert report.ok is True
    assert report.excluded_legacy_files == 29
    assert report.compiled_python3_files > 0
    assert report.classifications == ("legacy_z3_playground_python2",)


def test_unclassified_python2_source_fails_python3_gate(tmp_path):
    package = tmp_path / "belief"
    package.mkdir()
    (package / "legacy.py").write_text("print 'python two'\n", encoding="utf-8")
    manifest = _write_manifest(tmp_path)

    report = check_python3_sources(tmp_path, manifest_path=manifest)

    assert report.ok is False
    assert report.excluded_legacy_files == 0
    assert report.syntax_errors
    assert report.syntax_errors[0].startswith("belief/legacy.py:1:")


def test_classified_inventory_change_fails_closed(tmp_path):
    legacy = tmp_path / "belief" / "tools_bundled" / "z3_playground"
    legacy.mkdir(parents=True)
    source = legacy / "example.py"
    source.write_text("print 'reference'\n", encoding="utf-8")
    prefix = "belief/tools_bundled/z3_playground"
    entry = _legacy_entry(tmp_path, prefix)
    manifest = _write_manifest(tmp_path, classifications=[entry])
    source.write_text("print 'changed reference'\n", encoding="utf-8")

    with pytest.raises(SourceClassificationError, match="inventory digest mismatch"):
        check_python3_sources(tmp_path, manifest_path=manifest)


def test_classified_inventory_is_stable_across_lf_and_crlf(tmp_path):
    legacy = tmp_path / "belief" / "tools_bundled" / "z3_playground"
    legacy.mkdir(parents=True)
    source = legacy / "example.py"
    source.write_bytes(b"print 'reference'\nprint 'second line'\n")
    prefix = "belief/tools_bundled/z3_playground"

    lf_inventory = build_python_inventory(tmp_path, prefix)
    source.write_bytes(b"print 'reference'\r\nprint 'second line'\r\n")
    crlf_inventory = build_python_inventory(tmp_path, prefix)

    assert crlf_inventory == lf_inventory


def test_manifest_rejects_path_traversal(tmp_path):
    (tmp_path / "belief").mkdir()
    entry = {
        "classification_id": "legacy",
        "path_prefix": "../outside",
        "language": "python2",
        "role": "vendored_reference_examples",
        "python3_compile": "excluded",
        "execution": "forbidden",
        "expected_python_file_count": 1,
        "inventory_sha256": hashlib.sha256(b"inventory").hexdigest(),
    }
    manifest = _write_manifest(tmp_path, classifications=[entry])

    with pytest.raises(SourceClassificationError, match="forbidden path component"):
        load_source_classification(manifest)


def test_manifest_rejects_unknown_fields(tmp_path):
    (tmp_path / "belief").mkdir()
    manifest = _write_manifest(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["compile_everything_except"] = ["belief/tools_bundled"]
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SourceClassificationError, match="unknown"):
        load_source_classification(manifest)
