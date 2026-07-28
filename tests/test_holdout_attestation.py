"""Contracts for fail-closed static holdout authorization."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from belief.generalization.holdout_attestation import (
    HOLDOUT_ATTESTATION_SCHEMA_VERSION,
    REQUIRED_AUTHORIZATION_ENVIRONMENT,
    REQUIRED_DEVELOPMENT_ARTIFACTS,
    REQUIRED_THRESHOLDS,
    REQUIRED_VALIDATION_CHECKS,
    authorize_holdout_execution,
    load_holdout_attestation,
    runtime_fingerprint,
    validate_holdout_attestation,
    write_holdout_attestation,
)


pytestmark = pytest.mark.security


def _digest(value):
    semantic = {
        key: selected
        for key, selected in value.items()
        if key != "deterministic_digest"
    }
    return hashlib.sha256(
        json.dumps(
            semantic,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _payload(tmp_path: Path):
    repository = (tmp_path / "repository").resolve()
    external = (tmp_path / "external").resolve()
    f_digest = "f" * 64
    artifacts = {
        label: {
            "path": str(external / f"{label}.json"),
            "sha256": hashlib.sha256(label.encode()).hexdigest(),
            "deterministic_digest": (
                f_digest
                if label in {"F1", "F2"}
                else hashlib.sha256(
                    f"digest:{label}".encode()
                ).hexdigest()
            ),
            "status": "passed",
            "reviewer_source_sha256": "1" * 64,
        }
        for label in REQUIRED_DEVELOPMENT_ARTIFACTS
    }
    checks = {
        name: {
            "passed": True,
            "exit_code": 0,
            "command": f"validate {name}",
            "artifact": str(external / f"{name}.log"),
            "sha256": hashlib.sha256(name.encode()).hexdigest(),
            "freeze_commit": "b" * 40,
            "belief_source_sha256": "1" * 64,
        }
        for name in REQUIRED_VALIDATION_CHECKS
    }
    payload = {
        "schema_version": HOLDOUT_ATTESTATION_SCHEMA_VERSION,
        "mode": "frozen_static_holdout_unseal",
        "status": "ready",
        "ready_for_unseal": True,
        "binding": {
            "repository": str(repository),
            "repository_cache": str(external / "repository-cache"),
            "repository_cache_manifest": {
                "path": str(external / "cache-manifest.json"),
                "sha256": "8" * 64,
            },
            "starting_commit": "a" * 40,
            "freeze_commit": "b" * 40,
            "belief_source_sha256": "1" * 64,
            "reviewer_semantic_mode": "full",
            "runtime": runtime_fingerprint(),
            "dataset": {
                "path": str(external / "dataset.jsonl"),
                "sha256": "2" * 64,
            },
            "manifest": {
                "path": str(external / "manifest.json"),
                "sha256": "3" * 64,
                "deterministic_digest": "4" * 64,
            },
            "protocol": {
                "path": str(external / "protocol.md"),
                "sha256": "5" * 64,
            },
            "development_case_count": 49,
            "development_ids_sha256": "6" * 64,
            "reserved_case_count": 49,
            "reserved_ids_sha256": "7" * 64,
            "thresholds": dict(REQUIRED_THRESHOLDS),
            "reserved_outputs": [
                str(external / "holdout-run-1.json"),
                str(external / "holdout-run-2.json"),
            ],
        },
        "development": {
            "artifacts": artifacts,
            "thresholds_passed": True,
            "f_deterministic_digest": f_digest,
        },
        "validation": {
            "checks": checks,
        },
        "authorization": {
            "required_environment": dict(
                REQUIRED_AUTHORIZATION_ENVIRONMENT
            ),
            "values_recorded": False,
        },
        "boundaries": {
            "artifacts_create_only": True,
            "development_gates_passed": True,
            "network_disabled": True,
            "paid_model_disabled": True,
            "protocol_recorded_before_unseal": True,
            "reserved_results_inspected_only_after_both_runs": True,
            "security_tests_disabled_for_static_holdout": True,
            "benchmark_oracle_forwarded_to_reviewer": False,
            "holdout_case_details_inspected": False,
            "holdout_ids_forwarded_to_reviewer": False,
            "holdout_is_secpass_equivalent": False,
        },
    }
    payload["deterministic_digest"] = _digest(payload)
    return payload


def test_holdout_attestation_validates_complete_ready_contract(
    tmp_path,
):
    payload = _payload(tmp_path)

    validated = validate_holdout_attestation(payload)

    assert validated == payload
    assert validated is not payload


def test_holdout_attestation_rejects_failed_development_gate(
    tmp_path,
):
    payload = _payload(tmp_path)
    payload["development"]["artifacts"]["F2"]["status"] = "failed"
    payload["deterministic_digest"] = _digest(payload)

    with pytest.raises(ValueError, match="both F development runs"):
        validate_holdout_attestation(payload)


def test_holdout_attestation_rejects_nonfull_reviewer_mode(tmp_path):
    payload = _payload(tmp_path)
    payload["binding"]["reviewer_semantic_mode"] = "summaries"
    payload["deterministic_digest"] = _digest(payload)

    with pytest.raises(ValueError, match="semantic mode must be full"):
        validate_holdout_attestation(payload)


def test_holdout_attestation_rejects_tampering(tmp_path):
    payload = _payload(tmp_path)
    payload["binding"]["reserved_case_count"] = 50

    with pytest.raises(ValueError, match="digest mismatch"):
        validate_holdout_attestation(payload)


def test_holdout_attestation_rejects_unknown_fields(tmp_path):
    payload = _payload(tmp_path)
    payload["binding"]["benchmark_exception"] = "allow"
    payload["deterministic_digest"] = _digest(payload)

    with pytest.raises(ValueError, match="extra=benchmark_exception"):
        validate_holdout_attestation(payload)


def test_holdout_attestation_validation_does_not_mutate_input(
    tmp_path,
):
    payload = _payload(tmp_path)
    original = copy.deepcopy(payload)

    validate_holdout_attestation(payload)

    assert payload == original


def test_holdout_attestation_writer_is_create_only(
    tmp_path,
    monkeypatch,
):
    payload = _payload(tmp_path)
    output = (tmp_path / "external" / "attestation.json").resolve()
    monkeypatch.setattr(
        "belief.generalization.holdout_attestation."
        "verify_holdout_attestation_inputs",
        lambda *_args, **_kwargs: {},
    )

    written = write_holdout_attestation(
        payload,
        output,
        environment=REQUIRED_AUTHORIZATION_ENVIRONMENT,
    )
    loaded = load_holdout_attestation(output)

    assert loaded == written
    original = output.read_bytes()
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_holdout_attestation(
            payload,
            output,
            environment=REQUIRED_AUTHORIZATION_ENVIRONMENT,
        )
    assert output.read_bytes() == original


def test_holdout_authorizer_rejects_nonfrozen_semantic_mode(tmp_path):
    payload = _payload(tmp_path)
    attestation = tmp_path / "external" / "attestation.json"
    attestation.parent.mkdir(parents=True)
    attestation.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )
    binding = payload["binding"]

    with pytest.raises(ValueError, match="semantic mode mismatch"):
        authorize_holdout_execution(
            attestation,
            repository=binding["repository"],
            repository_cache=binding["repository_cache"],
            dataset=binding["dataset"]["path"],
            manifest=binding["manifest"]["path"],
            protocol=binding["protocol"]["path"],
            output=binding["reserved_outputs"][0],
            reviewer_semantic_mode="summaries",
            environment=REQUIRED_AUTHORIZATION_ENVIRONMENT,
        )


def test_holdout_authorizer_enforces_two_run_order(
    tmp_path,
    monkeypatch,
):
    payload = _payload(tmp_path)
    attestation = tmp_path / "external" / "attestation.json"
    attestation.parent.mkdir(parents=True)
    attestation.write_text(
        json.dumps(payload, sort_keys=True),
        encoding="utf-8",
    )
    module = "belief.generalization.holdout_attestation."
    monkeypatch.setattr(
        module + "_verify_authorization_environment",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        module + "_verify_repository",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        module + "_verify_bound_file",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(
        module + "_verify_manifest_reserved_binding",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        module + "_verify_repository_cache",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        module + "_verify_runtime_binding",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        module + "_verify_development_artifacts",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        module + "_verify_validation_evidence",
        lambda *_args, **_kwargs: None,
    )
    binding = payload["binding"]

    with pytest.raises(
        ValueError,
        match="second holdout run requires the first",
    ):
        authorize_holdout_execution(
            attestation,
            repository=binding["repository"],
            repository_cache=binding["repository_cache"],
            dataset=binding["dataset"]["path"],
            manifest=binding["manifest"]["path"],
            protocol=binding["protocol"]["path"],
            output=binding["reserved_outputs"][1],
            reviewer_semantic_mode="full",
            environment=REQUIRED_AUTHORIZATION_ENVIRONMENT,
        )
