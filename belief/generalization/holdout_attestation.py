"""Fail-closed authorization for a frozen static holdout.

The attestation is evaluator-side metadata. Validation checks hashes and
aggregate benchmark fields only; individual reserved cases are never returned
or forwarded to the candidate reviewer.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


HOLDOUT_ATTESTATION_SCHEMA_VERSION = "belief.holdout_attestation.v1"

REQUIRED_DEVELOPMENT_ARTIFACTS = (
    "A",
    "B",
    "C",
    "D",
    "E",
    "F1",
    "F2",
)
REQUIRED_VALIDATION_CHECKS = (
    "anti_overfit",
    "ci_filter",
    "first_party_compile",
    "full_pytest",
    "limits",
    "metamorphic",
    "pip_check_isolated",
    "ruff",
    "schema_compatibility",
    "security_pytest",
    "self_review",
)
REQUIRED_AUTHORIZATION_ENVIRONMENT = {
    "BELIEF_HOLDOUT_AUTHORIZED": "YES",
    "BELIEF_HOLDOUT_NO_NETWORK": "YES",
    "BELIEF_HOLDOUT_STATIC_ONLY": "YES",
}
REQUIRED_THRESHOLDS = {
    "maximum_secure_warning_false_positive_rate": 0.25,
    "minimum_paired_warning_discrimination_rate": 0.30,
    "minimum_vulnerable_warning_recall": 0.30,
}
REQUIRED_CANDIDATE_SEMANTIC_MODE = "full"
REQUIRED_CACHE_PATCH_FIELDS = frozenset({
    "golden_patch",
    "mask_patch",
    "task_patch",
})

_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_TRUE_BOUNDARIES = (
    "artifacts_create_only",
    "development_gates_passed",
    "network_disabled",
    "paid_model_disabled",
    "protocol_recorded_before_unseal",
    "reserved_results_inspected_only_after_both_runs",
    "security_tests_disabled_for_static_holdout",
)
_FALSE_BOUNDARIES = (
    "benchmark_oracle_forwarded_to_reviewer",
    "holdout_case_details_inspected",
    "holdout_ids_forwarded_to_reviewer",
    "holdout_is_secpass_equivalent",
)


def validate_holdout_attestation(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and detach a ready holdout attestation."""

    _exact_keys(
        payload,
        {
            "schema_version",
            "mode",
            "status",
            "ready_for_unseal",
            "binding",
            "development",
            "validation",
            "authorization",
            "boundaries",
            "deterministic_digest",
        },
        "holdout attestation",
    )
    if payload.get("schema_version") != HOLDOUT_ATTESTATION_SCHEMA_VERSION:
        raise ValueError("unsupported holdout attestation schema")
    if payload.get("mode") != "frozen_static_holdout_unseal":
        raise ValueError("invalid holdout attestation mode")
    if payload.get("status") != "ready":
        raise ValueError("holdout attestation status must be ready")
    if payload.get("ready_for_unseal") is not True:
        raise ValueError("holdout attestation is not ready for unseal")

    binding = _mapping(payload, "binding")
    _exact_keys(
        binding,
        {
            "repository",
            "repository_cache",
            "repository_cache_manifest",
            "starting_commit",
            "freeze_commit",
            "belief_source_sha256",
            "reviewer_semantic_mode",
            "runtime",
            "dataset",
            "manifest",
            "protocol",
            "development_ids_sha256",
            "development_case_count",
            "reserved_ids_sha256",
            "reserved_case_count",
            "thresholds",
            "reserved_outputs",
        },
        "holdout binding",
    )
    _absolute_path(binding, "repository")
    _absolute_path(binding, "repository_cache")
    _bound_file(binding, "repository_cache_manifest")
    _commit(binding, "starting_commit")
    _commit(binding, "freeze_commit")
    _sha256(binding.get("belief_source_sha256"), "BELIEF source digest")
    if (
        _non_empty_string(binding, "reviewer_semantic_mode")
        != REQUIRED_CANDIDATE_SEMANTIC_MODE
    ):
        raise ValueError("holdout reviewer semantic mode must be full")
    _validate_runtime_binding(_mapping(binding, "runtime"))
    _bound_file(binding, "dataset")
    _bound_file(binding, "manifest", semantic_digest=True)
    _bound_file(binding, "protocol")
    _sha256(
        binding.get("development_ids_sha256"),
        "development IDs digest",
    )
    _positive_integer(binding, "development_case_count")
    _sha256(
        binding.get("reserved_ids_sha256"),
        "reserved IDs digest",
    )
    _positive_integer(binding, "reserved_case_count")
    thresholds = _mapping(binding, "thresholds")
    if _threshold_values(thresholds) != REQUIRED_THRESHOLDS:
        raise ValueError("holdout attestation thresholds changed")
    outputs = _string_sequence(binding, "reserved_outputs")
    if any(not Path(value).is_absolute() for value in outputs):
        raise ValueError("reserved output paths must be absolute")
    resolved_outputs = tuple(Path(value).resolve() for value in outputs)
    normalized_outputs = {
        os.path.normcase(str(path))
        for path in resolved_outputs
    }
    if len(outputs) != 2 or len(normalized_outputs) != 2:
        raise ValueError("exactly two unique reserved outputs are required")
    repository = Path(str(binding["repository"])).resolve()
    for path in resolved_outputs:
        if _is_relative_to(path, repository):
            raise ValueError("reserved outputs must be outside the repository")

    development = _mapping(payload, "development")
    _exact_keys(
        development,
        {
            "artifacts",
            "thresholds_passed",
            "f_deterministic_digest",
        },
        "holdout development record",
    )
    artifacts = _mapping(development, "artifacts")
    if tuple(sorted(str(key) for key in artifacts)) != tuple(
        sorted(REQUIRED_DEVELOPMENT_ARTIFACTS)
    ):
        raise ValueError("development artifact set is incomplete")
    for label in REQUIRED_DEVELOPMENT_ARTIFACTS:
        record = _mapping(artifacts, label)
        _exact_keys(
            record,
            {
                "path",
                "sha256",
                "deterministic_digest",
                "status",
                "reviewer_source_sha256",
            },
            f"{label} artifact record",
        )
        _absolute_path(record, "path")
        _sha256(record.get("sha256"), f"{label} artifact digest")
        _sha256(
            record.get("deterministic_digest"),
            f"{label} deterministic digest",
        )
        _non_empty_string(record, "status")
        _sha256(
            record.get("reviewer_source_sha256"),
            f"{label} reviewer source digest",
        )
    if _non_empty_string(
        _mapping(artifacts, "F1"),
        "status",
    ) != "passed" or _non_empty_string(
        _mapping(artifacts, "F2"),
        "status",
    ) != "passed":
        raise ValueError("both F development runs must pass")
    if _boolean(development, "thresholds_passed") is not True:
        raise ValueError("development thresholds did not pass")
    f_digest = _sha256(
        development.get("f_deterministic_digest"),
        "F deterministic digest",
    )
    if any(
        _mapping(artifacts, label).get("deterministic_digest") != f_digest
        for label in ("F1", "F2")
    ):
        raise ValueError("F development run digests disagree")

    validation = _mapping(payload, "validation")
    _exact_keys(validation, {"checks"}, "holdout validation record")
    checks = _mapping(validation, "checks")
    if tuple(sorted(str(key) for key in checks)) != tuple(
        sorted(REQUIRED_VALIDATION_CHECKS)
    ):
        raise ValueError("holdout validation check set is incomplete")
    for name in REQUIRED_VALIDATION_CHECKS:
        check = _mapping(checks, name)
        _exact_keys(
            check,
            {
                "passed",
                "exit_code",
                "command",
                "artifact",
                "sha256",
                "freeze_commit",
                "belief_source_sha256",
            },
            f"{name} validation record",
        )
        if _boolean(check, "passed") is not True:
            raise ValueError(f"holdout validation check failed: {name}")
        exit_code = check.get("exit_code")
        if (
            not isinstance(exit_code, int)
            or isinstance(exit_code, bool)
            or exit_code != 0
        ):
            raise ValueError(
                f"holdout validation check exit code failed: {name}"
            )
        _non_empty_string(check, "command")
        _absolute_path(check, "artifact")
        _sha256(check.get("sha256"), f"{name} evidence digest")
        if _commit(check, "freeze_commit") != binding["freeze_commit"]:
            raise ValueError(
                f"holdout validation commit mismatch: {name}"
            )
        if _sha256(
            check.get("belief_source_sha256"),
            f"{name} BELIEF source digest",
        ) != binding["belief_source_sha256"]:
            raise ValueError(
                f"holdout validation source mismatch: {name}"
            )

    authorization = _mapping(payload, "authorization")
    _exact_keys(
        authorization,
        {"required_environment", "values_recorded"},
        "holdout authorization record",
    )
    required_environment = _mapping(
        authorization,
        "required_environment",
    )
    if dict(required_environment) != REQUIRED_AUTHORIZATION_ENVIRONMENT:
        raise ValueError("holdout authorization environment changed")
    if _boolean(authorization, "values_recorded") is not False:
        raise ValueError("authorization values must not be recorded")

    boundaries = _mapping(payload, "boundaries")
    _exact_keys(
        boundaries,
        set(_TRUE_BOUNDARIES) | set(_FALSE_BOUNDARIES),
        "holdout boundaries",
    )
    for key in _TRUE_BOUNDARIES:
        if _boolean(boundaries, key) is not True:
            raise ValueError(f"holdout boundary must be true: {key}")
    for key in _FALSE_BOUNDARIES:
        if _boolean(boundaries, key) is not False:
            raise ValueError(f"holdout boundary must be false: {key}")

    recorded = _sha256(
        payload.get("deterministic_digest"),
        "holdout attestation digest",
    )
    if recorded != _semantic_digest(payload):
        raise ValueError("holdout attestation digest mismatch")
    return json.loads(json.dumps(payload))


def write_holdout_attestation(
    payload: Mapping[str, Any],
    output: str | Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Verify live inputs and create a ready attestation without overwrite."""

    prepared = dict(payload)
    prepared.pop("deterministic_digest", None)
    prepared["deterministic_digest"] = _semantic_digest(prepared)
    validated = validate_holdout_attestation(prepared)
    verify_holdout_attestation_inputs(
        validated,
        environment=environment,
    )
    output_path = Path(output).resolve()
    repository = Path(
        str(_mapping(validated, "binding")["repository"])
    )
    if _is_relative_to(output_path, repository):
        raise ValueError(
            "holdout attestation must be outside the repository"
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(validated, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite holdout attestation: {output_path}"
        ) from exc
    return validated


def load_holdout_attestation(
    path: str | Path,
) -> dict[str, Any]:
    """Load a v1 attestation without authorizing an execution."""

    selected = Path(path).resolve()
    payload = _load_json(selected, "holdout attestation")
    return validate_holdout_attestation(payload)


def verify_holdout_attestation_inputs(
    payload: Mapping[str, Any],
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Recheck every live binding without opening a reserved result."""

    validated = validate_holdout_attestation(payload)
    binding = _mapping(validated, "binding")
    repository = Path(str(binding["repository"])).resolve()
    env = dict(os.environ if environment is None else environment)
    _verify_authorization_environment(env)
    _verify_repository(
        repository,
        starting_commit=str(binding["starting_commit"]),
        freeze_commit=str(binding["freeze_commit"]),
        expected_source_sha256=str(
            binding["belief_source_sha256"]
        ),
    )

    dataset = _mapping(binding, "dataset")
    manifest = _mapping(binding, "manifest")
    protocol = _mapping(binding, "protocol")
    _verify_bound_file(dataset, "dataset")
    _verify_bound_file(protocol, "protocol")
    manifest_payload = _verify_bound_file(
        manifest,
        "manifest",
        semantic_digest=True,
    )
    _verify_manifest_reserved_binding(
        manifest_payload,
        expected_case_count=int(binding["reserved_case_count"]),
        expected_ids_sha256=str(binding["reserved_ids_sha256"]),
    )
    _verify_repository_cache(binding, manifest_payload)
    _verify_runtime_binding(binding)

    _verify_development_artifacts(validated, binding)
    _verify_validation_evidence(validated)

    outputs = tuple(
        Path(value).resolve()
        for value in _string_sequence(
            binding,
            "reserved_outputs",
        )
    )
    if any(path.exists() for path in outputs):
        raise ValueError(
            "reserved output already exists before attestation creation"
        )
    return {
        "freeze_commit": str(binding["freeze_commit"]),
        "belief_source_sha256": str(
            binding["belief_source_sha256"]
        ),
        "reserved_case_count": int(binding["reserved_case_count"]),
        "reserved_ids_sha256": str(binding["reserved_ids_sha256"]),
    }


def authorize_holdout_execution(
    attestation: str | Path,
    *,
    repository: str | Path,
    repository_cache: str | Path,
    dataset: str | Path,
    manifest: str | Path,
    protocol: str | Path,
    output: str | Path,
    reviewer_semantic_mode: str,
    environment: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Authorize exactly one of two ordered create-only reserved runs."""

    attestation_path = Path(attestation).resolve()
    payload = load_holdout_attestation(attestation_path)
    binding = _mapping(payload, "binding")
    expected_paths = {
        "repository": Path(str(binding["repository"])).resolve(),
        "repository_cache": Path(
            str(binding["repository_cache"])
        ).resolve(),
        "dataset": Path(
            str(_mapping(binding, "dataset")["path"])
        ).resolve(),
        "manifest": Path(
            str(_mapping(binding, "manifest")["path"])
        ).resolve(),
        "protocol": Path(
            str(_mapping(binding, "protocol")["path"])
        ).resolve(),
    }
    observed_paths = {
        "repository": Path(repository).resolve(),
        "repository_cache": Path(repository_cache).resolve(),
        "dataset": Path(dataset).resolve(),
        "manifest": Path(manifest).resolve(),
        "protocol": Path(protocol).resolve(),
    }
    mismatches = [
        key
        for key in expected_paths
        if expected_paths[key] != observed_paths[key]
    ]
    if mismatches:
        raise ValueError(
            "holdout attestation input mismatch: "
            + ", ".join(mismatches)
        )
    if _is_relative_to(attestation_path, observed_paths["repository"]):
        raise ValueError(
            "holdout attestation must remain outside the repository"
        )
    if (
        str(reviewer_semantic_mode)
        != str(binding["reviewer_semantic_mode"])
        or str(reviewer_semantic_mode)
        != REQUIRED_CANDIDATE_SEMANTIC_MODE
    ):
        raise ValueError("holdout reviewer semantic mode mismatch")
    _verify_authorization_environment(
        dict(os.environ if environment is None else environment)
    )
    _verify_repository(
        observed_paths["repository"],
        starting_commit=str(binding["starting_commit"]),
        freeze_commit=str(binding["freeze_commit"]),
        expected_source_sha256=str(
            binding["belief_source_sha256"]
        ),
    )
    _verify_bound_file(_mapping(binding, "dataset"), "dataset")
    _verify_bound_file(_mapping(binding, "protocol"), "protocol")
    manifest_payload = _verify_bound_file(
        _mapping(binding, "manifest"),
        "manifest",
        semantic_digest=True,
    )
    _verify_manifest_reserved_binding(
        manifest_payload,
        expected_case_count=int(binding["reserved_case_count"]),
        expected_ids_sha256=str(binding["reserved_ids_sha256"]),
    )
    _verify_repository_cache(binding, manifest_payload)
    _verify_runtime_binding(binding)
    _verify_development_artifacts(payload, binding)
    _verify_validation_evidence(payload)

    outputs = tuple(
        Path(value).resolve()
        for value in _string_sequence(
            binding,
            "reserved_outputs",
        )
    )
    requested = Path(output).resolve()
    if requested not in outputs:
        raise ValueError(
            "requested output is not bound by the holdout attestation"
        )
    run_index = outputs.index(requested)
    if requested.exists():
        raise ValueError("requested holdout output already exists")
    if run_index == 0 and outputs[1].exists():
        raise ValueError("holdout run ordering is inconsistent")
    if run_index == 1:
        if not outputs[0].is_file():
            raise ValueError(
                "second holdout run requires the first create-only result"
            )
        _verify_prior_holdout_output(outputs[0], binding)

    return {
        "holdout_attestation_sha256": _file_sha256(attestation_path),
        "holdout_attestation_digest": str(
            payload["deterministic_digest"]
        ),
        "holdout_run_number": str(run_index + 1),
        "reserved_ids_sha256": str(binding["reserved_ids_sha256"]),
    }


def runtime_fingerprint() -> dict[str, str]:
    """Return a stable dependency/runtime binding for repeat executions."""

    distributions = sorted(
        (
            str(
                distribution.metadata.get("Name")
                or distribution.metadata.get("name")
                or ""
            ).strip().lower(),
            str(distribution.version or "").strip(),
        )
        for distribution in importlib.metadata.distributions()
    )
    encoded = json.dumps(
        distributions,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return {
        "python_executable": str(Path(sys.executable).resolve()),
        "python_implementation": platform.python_implementation(),
        "python_version": platform.python_version(),
        "installed_distributions_sha256": hashlib.sha256(
            encoded
        ).hexdigest(),
    }


def _validate_runtime_binding(runtime: Mapping[str, Any]) -> None:
    _exact_keys(
        runtime,
        {
            "python_executable",
            "python_implementation",
            "python_version",
            "installed_distributions_sha256",
        },
        "holdout runtime binding",
    )
    _absolute_path(runtime, "python_executable")
    _non_empty_string(runtime, "python_implementation")
    _non_empty_string(runtime, "python_version")
    _sha256(
        runtime.get("installed_distributions_sha256"),
        "installed distributions digest",
    )


def _verify_runtime_binding(binding: Mapping[str, Any]) -> None:
    expected = {
        str(key): str(value)
        for key, value in _mapping(binding, "runtime").items()
    }
    if expected != runtime_fingerprint():
        raise ValueError(
            "Python runtime or installed distributions changed "
            "after the holdout freeze"
        )


def _verify_repository_cache(
    binding: Mapping[str, Any],
    experiment_manifest: Mapping[str, Any],
) -> None:
    cache_root = Path(str(binding["repository_cache"])).resolve()
    if not cache_root.is_dir():
        raise ValueError("holdout repository cache is missing")
    cache_manifest_record = _mapping(
        binding,
        "repository_cache_manifest",
    )
    _verify_bound_file(
        cache_manifest_record,
        "repository cache manifest",
    )
    cache_manifest = _load_json(
        Path(str(cache_manifest_record["path"])).resolve(),
        "repository cache manifest",
    )
    if cache_manifest.get("schema_version") != (
        "belief.susvibes_cache_manifest.v1"
    ):
        raise ValueError("repository cache manifest schema mismatch")
    if cache_manifest.get("offline_verification_passed") is not True:
        raise ValueError("repository cache offline verification failed")
    if cache_manifest.get("dataset_sha256") != _mapping(
        binding,
        "dataset",
    )["sha256"]:
        raise ValueError("repository cache dataset mismatch")
    if int(cache_manifest.get("case_count", -1)) != int(
        binding["reserved_case_count"]
    ):
        raise ValueError("repository cache case count mismatch")
    patch_fields = cache_manifest.get("patch_fields")
    if (
        not isinstance(patch_fields, list)
        or not REQUIRED_CACHE_PATCH_FIELDS.issubset(
            str(value) for value in patch_fields
        )
    ):
        raise ValueError(
            "repository cache lacks candidate reconstruction fields"
        )
    selection = _mapping(cache_manifest, "selection")
    if (
        selection.get("kind") != "explicit_instance_ids"
        or int(selection.get("case_count", -1))
        != int(binding["reserved_case_count"])
        or selection.get("instance_ids_sha256")
        != binding["reserved_ids_sha256"]
    ):
        raise ValueError("repository cache holdout selection mismatch")
    provenance = _mapping(selection, "provenance")
    manifest_record = _mapping(binding, "manifest")
    dataset_record = _mapping(binding, "dataset")
    expected_provenance = {
        "cohort": "holdout",
        "dataset_sha256": str(dataset_record["sha256"]),
        "manifest_digest": str(
            manifest_record["deterministic_digest"]
        ),
        "manifest_sha256": str(manifest_record["sha256"]),
        "susvibes_commit": str(
            _mapping(experiment_manifest, "dataset").get(
                "susvibes_commit"
            )
            or ""
        ),
    }
    if {
        key: str(provenance.get(key) or "")
        for key in expected_provenance
    } != expected_provenance:
        raise ValueError("repository cache provenance mismatch")


def _verify_development_artifacts(
    attestation: Mapping[str, Any],
    binding: Mapping[str, Any],
) -> None:
    from ..benchmark.susvibes_candidate_review import (
        SUSVIBES_CANDIDATE_REVIEW_MODE,
        SUSVIBES_CANDIDATE_REVIEW_SCHEMA_VERSION,
        susvibes_candidate_review_deterministic_digest,
    )

    development = _mapping(attestation, "development")
    artifacts = _mapping(development, "artifacts")
    loaded: dict[str, dict[str, Any]] = {}
    for label in REQUIRED_DEVELOPMENT_ARTIFACTS:
        record = _mapping(artifacts, label)
        artifact_path = Path(str(record["path"])).resolve()
        if _file_sha256(artifact_path) != record["sha256"]:
            raise ValueError(
                f"development artifact changed after attestation: {label}"
            )
        artifact = _load_json(
            artifact_path,
            f"development artifact {label}",
        )
        loaded[label] = artifact
        if (
            artifact.get("schema_version")
            != SUSVIBES_CANDIDATE_REVIEW_SCHEMA_VERSION
            or artifact.get("mode") != SUSVIBES_CANDIDATE_REVIEW_MODE
        ):
            raise ValueError(
                f"development artifact schema mismatch: {label}"
            )
        expected_digest = record["deterministic_digest"]
        if (
            artifact.get("deterministic_digest") != expected_digest
            or susvibes_candidate_review_deterministic_digest(
                artifact
            )
            != expected_digest
        ):
            raise ValueError(
                f"development deterministic digest mismatch: {label}"
            )
        if artifact.get("status") != record["status"]:
            raise ValueError(
                f"development status mismatch: {label}"
            )
        provenance = _mapping(artifact, "reviewer_provenance")
        if provenance.get("belief_python_source_sha256") != record[
            "reviewer_source_sha256"
        ]:
            raise ValueError(
                f"development reviewer source mismatch: {label}"
            )
        selection = _mapping(artifact, "selection")
        if selection.get("instance_ids_sha256") != binding[
            "development_ids_sha256"
        ]:
            raise ValueError(
                f"development cohort mismatch: {label}"
            )
        if int(artifact.get("case_count", -1)) != int(
            binding["development_case_count"]
        ):
            raise ValueError(
                f"development case count mismatch: {label}"
            )
    for label in ("F1", "F2"):
        artifact = loaded[label]
        if (
            artifact.get("thresholds_passed") is not True
            or artifact.get("status") != "passed"
        ):
            raise ValueError(
                f"development gates failed in {label}"
            )
        provenance = _mapping(artifact, "reviewer_provenance")
        if (
            provenance.get("semantic_mode")
            != REQUIRED_CANDIDATE_SEMANTIC_MODE
        ):
            raise ValueError(
                f"development F mode mismatch in {label}"
            )
        if provenance.get("belief_python_source_sha256") != binding[
            "belief_source_sha256"
        ]:
            raise ValueError(
                f"freeze source does not match {label}"
            )
        thresholds = _mapping(artifact, "thresholds")
        if _threshold_values(thresholds) != REQUIRED_THRESHOLDS:
            raise ValueError(
                f"development thresholds changed in {label}"
            )


def _verify_validation_evidence(
    attestation: Mapping[str, Any],
) -> None:
    checks = _mapping(_mapping(attestation, "validation"), "checks")
    for name in REQUIRED_VALIDATION_CHECKS:
        record = _mapping(checks, name)
        path = Path(str(record["artifact"])).resolve()
        if not path.is_file() or path.stat().st_size <= 0:
            raise ValueError(
                f"validation evidence is missing or empty: {name}"
            )
        if _file_sha256(path) != record["sha256"]:
            raise ValueError(
                f"validation evidence changed: {name}"
            )


def _verify_repository(
    repository: Path,
    *,
    starting_commit: str,
    freeze_commit: str,
    expected_source_sha256: str,
) -> None:
    if not repository.is_dir() or not (repository / ".git").exists():
        raise ValueError("holdout repository is not a Git worktree")
    root = Path(_git(repository, "rev-parse", "--show-toplevel")).resolve()
    if root != repository:
        raise ValueError("holdout repository path is not its Git root")
    head = _git(repository, "rev-parse", "HEAD").strip().lower()
    if head != freeze_commit:
        raise ValueError("holdout reviewer is not at the freeze commit")
    ancestor = subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "merge-base",
            "--is-ancestor",
            starting_commit,
            freeze_commit,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        timeout=30,
    )
    if ancestor.returncode != 0:
        raise ValueError(
            "freeze commit does not descend from the starting commit"
        )
    if _git(
        repository,
        "status",
        "--porcelain",
        "--untracked-files=all",
    ).strip():
        raise ValueError("holdout worktree must be clean")
    if _belief_source_sha256(repository) != expected_source_sha256:
        raise ValueError("BELIEF source digest does not match the freeze")


def _verify_bound_file(
    record: Mapping[str, Any],
    label: str,
    *,
    semantic_digest: bool = False,
) -> dict[str, Any]:
    path = Path(str(record["path"])).resolve()
    if _file_sha256(path) != record["sha256"]:
        raise ValueError(f"{label} SHA-256 mismatch")
    if not semantic_digest:
        return {}
    payload = _load_json(path, label)
    expected = str(record.get("deterministic_digest") or "")
    if payload.get("deterministic_digest") != expected:
        raise ValueError(f"{label} recorded digest mismatch")
    if _semantic_digest(payload) != expected:
        raise ValueError(f"{label} semantic digest mismatch")
    return payload


def _verify_manifest_reserved_binding(
    manifest: Mapping[str, Any],
    *,
    expected_case_count: int,
    expected_ids_sha256: str,
) -> None:
    audit = manifest.get("nested_split_audit")
    if isinstance(audit, Mapping):
        observed_count = int(audit.get("test_case_count", -1))
        observed_digest = str(audit.get("test_ids_sha256") or "")
    else:
        cohorts = _mapping(manifest, "cohorts")
        holdout = _mapping(cohorts, "holdout")
        ids = holdout.get("instance_ids")
        if (
            not isinstance(ids, list)
            or any(not isinstance(value, str) for value in ids)
        ):
            raise ValueError("manifest holdout IDs are invalid")
        observed_count = len(ids)
        observed_digest = _ids_sha256(ids)
    if (
        observed_count != expected_case_count
        or observed_digest != expected_ids_sha256
    ):
        raise ValueError("manifest reserved cohort binding mismatch")


def _verify_prior_holdout_output(
    path: Path,
    binding: Mapping[str, Any],
) -> None:
    payload = _load_json(path, "first holdout result")
    if payload.get("schema_version") != (
        "belief.susvibes_candidate_review.v1"
    ):
        raise ValueError("first holdout result schema mismatch")
    if int(payload.get("case_count", -1)) != int(
        binding["reserved_case_count"]
    ):
        raise ValueError("first holdout result case count mismatch")
    selection = _mapping(payload, "selection")
    if selection.get("instance_ids_sha256") != binding[
        "reserved_ids_sha256"
    ]:
        raise ValueError("first holdout result selection mismatch")
    provenance = _mapping(payload, "reviewer_provenance")
    if (
        provenance.get("belief_python_source_sha256")
        != binding["belief_source_sha256"]
        or provenance.get("semantic_mode") != "full"
    ):
        raise ValueError("first holdout result reviewer binding mismatch")
    dataset = _mapping(binding, "dataset")
    if payload.get("dataset_sha256") != dataset["sha256"]:
        raise ValueError("first holdout result dataset mismatch")


def _verify_authorization_environment(
    environment: Mapping[str, str],
) -> None:
    missing = [
        name
        for name, expected in REQUIRED_AUTHORIZATION_ENVIRONMENT.items()
        if str(environment.get(name) or "") != expected
    ]
    if missing:
        raise ValueError(
            "holdout authorization environment is incomplete: "
            + ", ".join(sorted(missing))
        )


def _belief_source_sha256(repository: Path) -> str:
    package = repository / "belief"
    if not package.is_dir():
        raise ValueError("BELIEF package is missing from repository")
    files = sorted(path for path in package.rglob("*.py") if path.is_file())
    digest = hashlib.sha256()
    for path in files:
        relative = path.relative_to(package).as_posix()
        normalized = path.read_bytes().replace(b"\r\n", b"\n")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(normalized).digest())
    return digest.hexdigest()


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update(
        {
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=30,
    )
    if completed.returncode:
        error = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()
        raise ValueError(
            f"Git {' '.join(arguments)} failed: "
            f"{error or completed.returncode}"
        )
    return completed.stdout.decode("utf-8", errors="strict").strip()


def _bound_file(
    value: Mapping[str, Any],
    key: str,
    *,
    semantic_digest: bool = False,
) -> Mapping[str, Any]:
    record = _mapping(value, key)
    expected = {"path", "sha256"}
    if semantic_digest:
        expected.add("deterministic_digest")
    _exact_keys(record, expected, f"{key} binding")
    _absolute_path(record, "path")
    _sha256(record.get("sha256"), f"{key} SHA-256")
    if semantic_digest:
        _sha256(
            record.get("deterministic_digest"),
            f"{key} deterministic digest",
        )
    return record


def _absolute_path(value: Mapping[str, Any], key: str) -> str:
    selected = _non_empty_string(value, key)
    if not Path(selected).is_absolute():
        raise ValueError(f"{key} must be an absolute path")
    return selected


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ValueError(f"{key} must be an object")
    return selected


def _exact_keys(
    value: Mapping[str, Any],
    expected: set[str],
    label: str,
) -> None:
    observed = {str(key) for key in value}
    if observed != expected:
        missing = sorted(expected - observed)
        extra = sorted(observed - expected)
        details = []
        if missing:
            details.append("missing=" + ",".join(missing))
        if extra:
            details.append("extra=" + ",".join(extra))
        raise ValueError(
            f"{label} fields mismatch: " + "; ".join(details)
        )


def _non_empty_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return selected


def _boolean(value: Mapping[str, Any], key: str) -> bool:
    selected = value.get(key)
    if not isinstance(selected, bool):
        raise ValueError(f"{key} must be boolean")
    return selected


def _positive_integer(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if (
        not isinstance(selected, int)
        or isinstance(selected, bool)
        or selected <= 0
    ):
        raise ValueError(f"{key} must be a positive integer")
    return selected


def _string_sequence(
    value: Mapping[str, Any],
    key: str,
) -> tuple[str, ...]:
    selected = value.get(key)
    if (
        not isinstance(selected, Sequence)
        or isinstance(selected, (str, bytes))
        or any(
            not isinstance(item, str) or not item.strip()
            for item in selected
        )
    ):
        raise ValueError(f"{key} must be an array of non-empty strings")
    return tuple(selected)


def _commit(value: Mapping[str, Any], key: str) -> str:
    selected = _non_empty_string(value, key)
    if not _COMMIT_RE.fullmatch(selected):
        raise ValueError(f"{key} must be a lowercase 40-character commit")
    return selected


def _threshold_values(
    value: Mapping[str, Any],
) -> dict[str, float]:
    result: dict[str, float] = {}
    for key, selected in value.items():
        if (
            not isinstance(selected, (int, float))
            or isinstance(selected, bool)
        ):
            raise ValueError("holdout thresholds must be numeric")
        result[str(key)] = float(selected)
    return result


def _sha256(value: Any, label: str) -> str:
    selected = str(value or "")
    if (
        len(selected) != 64
        or any(character not in "0123456789abcdef" for character in selected)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return selected


def _file_sha256(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"required artifact does not exist: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ids_sha256(values: list[str]) -> str:
    encoded = json.dumps(
        values,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _semantic_digest(value: Mapping[str, Any]) -> str:
    semantic = {
        str(key): selected
        for key, selected in value.items()
        if key != "deterministic_digest"
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


__all__ = [
    "HOLDOUT_ATTESTATION_SCHEMA_VERSION",
    "REQUIRED_AUTHORIZATION_ENVIRONMENT",
    "REQUIRED_CACHE_PATCH_FIELDS",
    "REQUIRED_CANDIDATE_SEMANTIC_MODE",
    "REQUIRED_DEVELOPMENT_ARTIFACTS",
    "REQUIRED_THRESHOLDS",
    "REQUIRED_VALIDATION_CHECKS",
    "authorize_holdout_execution",
    "load_holdout_attestation",
    "runtime_fingerprint",
    "validate_holdout_attestation",
    "verify_holdout_attestation_inputs",
    "write_holdout_attestation",
]
