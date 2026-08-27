from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from belief.benchmark.open_source_pairs import (
    OPEN_SOURCE_PAIRS_RESULT_SCHEMA_VERSION,
    OpenSourcePairsError,
    evaluate_open_source_pairs_benchmark,
    load_open_source_pairs_manifest,
    write_open_source_pairs_result,
)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return completed.stdout.decode("utf-8").strip()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fixture(tmp_path: Path) -> tuple[Path, Path]:
    repositories = tmp_path / "repos"
    repository = repositories / "example__demo"
    repository.mkdir(parents=True)
    _git(repository, "init")
    _git(repository, "config", "user.email", "benchmark@example.invalid")
    _git(repository, "config", "user.name", "Benchmark Fixture")
    _git(repository, "remote", "add", "origin", "https://github.com/example/demo.git")

    target = repository / "src" / "app.py"
    target.parent.mkdir()
    (repository / "LICENSE").write_text("MIT test fixture\n", encoding="utf-8")
    vulnerable = b"from pathlib import Path\n\ndef read(name):\n    return Path(name).read_text()\n"
    target.write_bytes(vulnerable)
    _git(repository, "add", "LICENSE", "src/app.py")
    _git(repository, "commit", "-m", "vulnerable")
    vulnerable_revision = _git(repository, "rev-parse", "HEAD")

    fixed = (
        b"from pathlib import Path\n\ndef read(name):\n"
        b"    root = Path('/safe').resolve()\n"
        b"    candidate = (root / name).resolve()\n"
        b"    candidate.relative_to(root)\n"
        b"    return candidate.read_text()\n"
    )
    target.write_bytes(fixed)
    _git(repository, "add", "src/app.py")
    _git(repository, "commit", "-m", "fixed")
    fixed_revision = _git(repository, "rev-parse", "HEAD")

    manifest = {
        "schema_version": "belief.open_source_pairs_corpus.v1",
        "corpus_id": "test-public-pair-v1",
        "classification": {
            "role": "unit_fixture",
            "evaluation_mode": "oracle_localized_changed_file_pair",
            "project_disjoint_from_susvibes_v1": True,
            "negative_controls_present": True,
            "dynamic_execution": False,
            "secpass_comparable": False,
            "claim_boundary": "unit fixture only",
        },
        "thresholds": {
            "minimum_vulnerable_warning_recall": 1.0,
            "maximum_fixed_warning_false_positive_rate": 0.0,
            "minimum_paired_discrimination_rate": 1.0,
            "minimum_deterministic_repetition_rate": 1.0,
            "maximum_analysis_error_count": 0,
        },
        "cases": [
            {
                "id": "demo-cve-2026-99999",
                "project": "example/demo",
                "repository_url": "https://github.com/example/demo.git",
                "checkout_dir": "example__demo",
                "advisory_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
                "cve_id": "CVE-2026-99999",
                "cwe": "CWE-22",
                "case_type": "path_traversal_possible",
                "license": {"spdx": "MIT", "path": "LICENSE"},
                "vulnerable_revision": vulnerable_revision,
                "fixed_revision": fixed_revision,
                "targets": [
                    {
                        "path": "src/app.py",
                        "vulnerable_sha256": _sha256(vulnerable),
                        "fixed_sha256": _sha256(fixed),
                        "relevant_line_range": [1, 20],
                    }
                ],
            }
        ],
    }
    manifest_path = tmp_path / "cases.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    return manifest_path, repositories


def _analyzer(root: Path, _options) -> dict:
    source = (root / "src" / "app.py").read_text(encoding="utf-8")
    status = "protected" if "relative_to" in source else "needs_review"
    return {
        "records": [{"category": "security"}],
        "audit_cases": [
            {
                "case_id": "case_fixture",
                "case_type": "path_traversal_possible",
                "cwe": "CWE-22",
                "status": status,
                "file": "src/app.py",
                "line": 4,
                "source": "name",
                "sink": "read_text",
                "metadata": {
                    "reportability": {
                        "proof_state": "signal_only",
                        "score": 10,
                        "verdict": "likely_false_positive",
                    }
                },
            }
        ],
    }


def test_open_source_pair_runner_discriminates_vulnerable_and_fixed(tmp_path):
    manifest, repositories = _fixture(tmp_path)

    result = evaluate_open_source_pairs_benchmark(
        manifest,
        repositories,
        belief_revision="a" * 40,
        analyzer=_analyzer,
    )

    assert result["schema_version"] == OPEN_SOURCE_PAIRS_RESULT_SCHEMA_VERSION
    assert result["status"] == "passed"
    assert result["metrics"]["vulnerable_warning_recall"] == 1.0
    assert result["metrics"]["fixed_warning_false_positive_rate"] == 0.0
    assert result["metrics"]["paired_discrimination_rate"] == 1.0
    assert result["metrics"]["deterministic_repetition_rate"] == 1.0
    assert result["boundaries"]["third_party_code_executed"] is False


def test_open_source_pair_manifest_rejects_source_digest_change(tmp_path):
    manifest, repositories = _fixture(tmp_path)
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["cases"][0]["targets"][0]["vulnerable_sha256"] = "0" * 64
    manifest.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(OpenSourcePairsError, match="source digest mismatch"):
        evaluate_open_source_pairs_benchmark(
            manifest,
            repositories,
            belief_revision="a" * 40,
            analyzer=_analyzer,
        )


def test_open_source_pair_result_is_create_only(tmp_path):
    manifest, repositories = _fixture(tmp_path)
    output = tmp_path / "result.json"

    write_open_source_pairs_result(
        manifest,
        repositories,
        output,
        belief_revision="a" * 40,
        analyzer=_analyzer,
    )

    with pytest.raises(OpenSourcePairsError, match="already exists"):
        write_open_source_pairs_result(
            manifest,
            repositories,
            output,
            belief_revision="a" * 40,
            analyzer=_analyzer,
        )


def test_committed_open_source_pair_manifest_is_strictly_valid():
    root = Path(__file__).resolve().parents[1]
    payload = load_open_source_pairs_manifest(
        root / "benchmark_open_source_pairs" / "cases.json"
    )

    assert len(payload["cases"]) == 3
    assert {case["project"] for case in payload["cases"]} == {
        "pypa/setuptools",
        "ormar-orm/ormar",
        "Mayuri-Chan/pyrofork",
    }
