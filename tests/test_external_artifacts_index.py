"""Contracts for the external measurement-artifact index and verifier.

Every test here builds its own synthetic tree. None of them reads the real
external volume, so the suite stays runnable on a machine that has never seen
it, and none of them can touch a reserved holdout case.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "verify_external_artifacts.py"
_INDEX = _REPO_ROOT / "research" / "external_artifacts.json"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "verify_external_artifacts",
        _SCRIPT,
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


verifier = _load_module()


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _write_index(tmp_path: Path, artifacts: list[dict]) -> Path:
    index_path = tmp_path / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "schema_version": "belief.external_artifacts.v1",
                "recorded_on": "2026-08-08",
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )
    return index_path


def _tree(tmp_path: Path, payload: bytes = b"recorded") -> tuple[Path, Path]:
    root = tmp_path / "artifacts"
    (root / "results").mkdir(parents=True)
    target = root / "results" / "run.json"
    target.write_bytes(payload)
    return root, target


# --------------------------------------------------------------------------
# The committed index
# --------------------------------------------------------------------------


def test_the_committed_index_is_structurally_valid():
    index = verifier.load_index(_INDEX)

    assert index["schema_version"] == "belief.external_artifacts.v1"
    assert len(index["artifacts"]) >= 14


def test_the_committed_index_names_every_recorded_result_document():
    index = verifier.load_index(_INDEX)
    recorded_in = {
        source.strip()
        for entry in index["artifacts"]
        for source in str(entry.get("recorded_in", "")).split(",")
        if source.strip()
    }

    assert "docs/GENERALIZATION_RESULTS.md" in recorded_in
    assert "benchmark_susvibes/README.md" in recorded_in
    for document in recorded_in:
        assert (_REPO_ROOT / document).is_file(), document


def test_the_committed_index_has_unique_paths_and_roles():
    index = verifier.load_index(_INDEX)
    paths = [entry["path"] for entry in index["artifacts"]]
    roles = [entry["role"] for entry in index["artifacts"]]

    assert len(paths) == len(set(paths))
    assert len(roles) == len(set(roles))


# --------------------------------------------------------------------------
# Verification outcomes
# --------------------------------------------------------------------------


def test_a_matching_artifact_verifies(tmp_path):
    root, _ = _tree(tmp_path)
    index = json.loads(
        _write_index(
            tmp_path,
            [
                {
                    "path": "results/run.json",
                    "sha256": _sha256(b"recorded"),
                    "role": "sample",
                }
            ],
        ).read_text(encoding="utf-8")
    )

    report = verifier.verify(root, index)

    assert report["ok"] is True
    assert report["counts"]["verified"] == 1
    assert report["artifacts"][0]["status"] == "verified"


def test_a_modified_artifact_is_reported_as_mismatched(tmp_path):
    root, target = _tree(tmp_path)
    index = json.loads(
        _write_index(
            tmp_path,
            [
                {
                    "path": "results/run.json",
                    "sha256": _sha256(b"recorded"),
                    "role": "sample",
                }
            ],
        ).read_text(encoding="utf-8")
    )
    target.write_bytes(b"tampered")

    report = verifier.verify(root, index)

    assert report["ok"] is False
    assert report["counts"]["mismatched"] == 1
    assert report["artifacts"][0]["actual_sha256"] == _sha256(b"tampered")


def test_a_deleted_artifact_is_reported_as_missing(tmp_path):
    root, target = _tree(tmp_path)
    index = json.loads(
        _write_index(
            tmp_path,
            [
                {
                    "path": "results/run.json",
                    "sha256": _sha256(b"recorded"),
                    "role": "sample",
                }
            ],
        ).read_text(encoding="utf-8")
    )
    target.unlink()

    report = verifier.verify(root, index)

    assert report["ok"] is False
    assert report["counts"]["missing"] == 1


def test_verification_is_fail_closed_at_the_command_boundary(tmp_path):
    root, target = _tree(tmp_path)
    index_path = _write_index(
        tmp_path,
        [
            {
                "path": "results/run.json",
                "sha256": _sha256(b"recorded"),
                "role": "sample",
            }
        ],
    )
    output = tmp_path / "report.json"

    argv = [
        "--root", str(root),
        "--index", str(index_path),
        "--json-output", str(output),
    ]
    assert verifier.main(argv) == 0

    target.write_bytes(b"tampered")
    assert verifier.main(argv) == 1

    written = json.loads(output.read_text(encoding="utf-8"))
    assert written["ok"] is False


# --------------------------------------------------------------------------
# Index rejection
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "artifacts",
    [
        pytest.param(
            [{"path": "/etc/passwd", "sha256": "a" * 64, "role": "r"}],
            id="absolute_path",
        ),
        pytest.param(
            [{"path": "../outside.json", "sha256": "a" * 64, "role": "r"}],
            id="parent_traversal",
        ),
        pytest.param(
            [
                {"path": "results/run.json", "sha256": "a" * 64, "role": "r"},
                {"path": "results/run.json", "sha256": "b" * 64, "role": "s"},
            ],
            id="duplicate_path",
        ),
        pytest.param(
            [{"path": "results/run.json", "sha256": "abc", "role": "r"}],
            id="short_digest",
        ),
        pytest.param(
            [{"path": "results/run.json", "sha256": "A" * 64, "role": "r"}],
            id="uppercase_digest",
        ),
        pytest.param(
            [{"path": "results/run.json", "sha256": "z" * 64, "role": "r"}],
            id="non_hexadecimal_digest",
        ),
        pytest.param([{"sha256": "a" * 64, "role": "r"}], id="missing_path"),
        pytest.param([], id="empty_index"),
    ],
)
def test_malformed_index_entries_are_refused(tmp_path, artifacts):
    index_path = _write_index(tmp_path, artifacts)

    with pytest.raises(SystemExit):
        verifier.load_index(index_path)


def test_an_unknown_schema_version_is_refused(tmp_path):
    index_path = tmp_path / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "schema_version": "belief.external_artifacts.v99",
                "artifacts": [
                    {
                        "path": "results/run.json",
                        "sha256": "a" * 64,
                        "role": "r",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit, match="schema"):
        verifier.load_index(index_path)


def test_a_missing_root_is_refused(tmp_path):
    index_path = _write_index(
        tmp_path,
        [{"path": "results/run.json", "sha256": "a" * 64, "role": "r"}],
    )

    with pytest.raises(SystemExit, match="not a directory"):
        verifier.main(
            ["--root", str(tmp_path / "absent"), "--index", str(index_path)]
        )
