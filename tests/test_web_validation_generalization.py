"""Preregistration tests for the transparent web generalization corpus."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark.web_generalization import (
    WEB_VALIDATION_THRESHOLDS,
    build_web_validation_development_manifest,
    build_web_validation_preregistration,
    verify_web_validation_development_corpus,
    write_web_validation_development_corpus,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "benchmark_web_validation"
STARTING_COMMIT = "a5e9fdac71e96b39fffdd543e8c1e8135fc4f01e"


def _committed_preregistration() -> dict:
    return json.loads(
        (CORPUS / "preregistration.json").read_text(encoding="utf-8")
    )


def _committed_manifest() -> dict:
    return json.loads(
        (CORPUS / "development" / "cases.json").read_text(
            encoding="utf-8"
        )
    )


def test_preregistration_is_exact_balanced_family_split():
    payload = build_web_validation_preregistration(STARTING_COMMIT)
    corpus = payload["corpus"]

    assert payload == _committed_preregistration()
    assert corpus["case_count"] == 48
    assert corpus["family_count"] == 12
    assert corpus["development_case_count"] == 32
    assert corpus["development_family_count"] == 8
    assert corpus["reserved_case_count"] == 16
    assert corpus["reserved_family_count"] == 4
    assert not (
        set(corpus["development_case_ids"])
        & set(corpus["reserved_case_ids"])
    )
    assert not (
        set(corpus["development_family_ids"])
        & set(corpus["reserved_family_ids"])
    )
    assert payload["split"]["unit"] == "application_template_family"
    assert payload["split"]["outcomes_used_for_allocation"] is False
    assert payload["thresholds"] == dict(WEB_VALIDATION_THRESHOLDS)


def test_development_corpus_covers_required_shapes_and_variants():
    manifest, sources = build_web_validation_development_manifest(
        STARTING_COMMIT
    )
    cases = manifest["cases"]
    tags = {
        tag
        for case in cases
        for tag in case["feature_tags"]
    }

    assert manifest == _committed_manifest()
    assert len(cases) == 32
    assert len(sources) == 32
    assert {
        (case["framework"], case["case_type"])
        for case in cases
    } == {
        ("flask", "path_traversal_possible"),
        ("flask", "idor_bola_possible"),
        ("fastapi", "path_traversal_possible"),
        ("fastapi", "idor_bola_possible"),
    }
    assert {
        case["variant"] for case in cases
    } == {"vulnerable", "protected", "ambiguous", "trap"}
    assert {
        "async_route",
        "sync_route",
        "direct_indirection",
        "helper_indirection",
        "decorator_indirection",
        "dependency_indirection",
        "dictionary_backend",
        "model_backend",
        "guard_before_sink",
        "guard_after_sink",
        "wrong_resource_guard",
        "owner_only",
        "tenant_only",
        "owner_and_tenant_bound",
        "sanitizer_result_used",
        "sanitizer_result_ignored",
    } <= tags


def test_every_development_source_is_exact_and_python3_syntax():
    manifest, expected_sources = build_web_validation_development_manifest(
        STARTING_COMMIT
    )
    reserved_ids = set(
        _committed_preregistration()["corpus"]["reserved_case_ids"]
    )

    for case in manifest["cases"]:
        relative = case["source_path"]
        path = CORPUS / Path(relative)
        source = path.read_text(encoding="utf-8")
        assert source == expected_sources[relative]
        compile(source, str(path), "exec")
        assert case["case_id"] not in reserved_ids
    assert not (CORPUS / "reserved").exists()


def test_writer_is_create_only_and_verifier_detects_drift(tmp_path):
    output = tmp_path / "corpus"

    written = write_web_validation_development_corpus(
        output,
        starting_commit=STARTING_COMMIT,
    )
    verified = verify_web_validation_development_corpus(output)

    assert verified["development_digest"] == written[
        "development_digest"
    ]
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_web_validation_development_corpus(
            output,
            starting_commit=STARTING_COMMIT,
        )

    source = next((output / "development" / "sources").glob("*.py"))
    source.write_text(
        source.read_text(encoding="utf-8") + "# drift\n",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="artifact drift"):
        verify_web_validation_development_corpus(output)


def test_preregistration_digest_rejects_tampering():
    payload = _committed_preregistration()
    tampered = copy.deepcopy(payload)
    tampered["thresholds"]["minimum_static_recall"] = 0.1

    assert tampered != build_web_validation_preregistration(
        STARTING_COMMIT
    )


def test_boundaries_keep_reserved_and_susvibes_closed():
    payload = _committed_preregistration()
    boundaries = payload["boundaries"]

    assert boundaries == {
        "artifacts_create_only": True,
        "docker_required": False,
        "external_project_code_used": False,
        "leaderboard_comparable": False,
        "network_required": False,
        "reserved_outcomes_committed": False,
        "reserved_source_committed": False,
        "secpass_equivalent": False,
        "subprocess_required": False,
        "susvibes_artifacts_used": False,
        "susvibes_holdout_opened": False,
    }
    assert not any(
        "benchmark_susvibes" in path.parts
        for path in CORPUS.rglob("*")
    )


def test_corpus_cli_verifies_without_writing():
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "build_web_validation_corpus.py"),
            "--verify",
            str(CORPUS),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["mode"] == "verify"
    assert summary["case_count"] == 32
    assert summary["family_count"] == 8
