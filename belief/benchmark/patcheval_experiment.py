"""Deterministic evaluator-side PatchEval-Verified development split."""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


PATCHEVAL_EXPERIMENT_SCHEMA_VERSION = (
    "belief.patcheval_verified_experiment.v1"
)
PATCHEVAL_EXPERIMENT_ALGORITHM = (
    "patcheval_verified_python_project_hash_v1"
)

_SEED_NAMESPACE = "belief-patcheval-verified-v1"
_DEVELOPMENT_REPOSITORY_FRACTION = 0.60
_MINIMUM_DEVELOPMENT_CASES = 24
_MINIMUM_DEVELOPMENT_REPOSITORIES = 8
_MINIMUM_RESERVED_CASES = 24
_MINIMUM_RESERVED_REPOSITORIES = 5


def build_patcheval_experiment_manifest(
    dataset: str | Path,
    susvibes_dataset: str | Path,
    protocol: str | Path,
    *,
    upstream_commit: str,
    belief_starting_commit: str,
    preparation_commit: str,
) -> dict[str, Any]:
    """Build a project-disjoint split without exposing evaluator metadata."""

    dataset_path = Path(dataset).resolve()
    susvibes_path = Path(susvibes_dataset).resolve()
    protocol_path = Path(protocol).resolve()
    dataset_sha256 = _file_sha256(dataset_path)
    susvibes_sha256 = _file_sha256(susvibes_path)
    protocol_sha256 = _file_sha256(protocol_path)
    normalized_upstream = _commit(upstream_commit, "upstream_commit")
    normalized_belief = _commit(
        belief_starting_commit,
        "belief_starting_commit",
    )
    normalized_preparation = _commit(
        preparation_commit,
        "preparation_commit",
    )
    records = _load_json_array(dataset_path, "PatchEval dataset")
    python_record_count = sum(
        isinstance(record, Mapping)
        and str(
            record.get("programing_language") or ""
        ).strip().lower()
        == "python"
        for record in records
    )
    python_cases, ineligible_counts = (
        _eligible_python_cases(records)
    )
    susvibes_projects = _load_susvibes_projects(susvibes_path)
    independent = [
        case
        for case in python_cases
        if case["repository"] not in susvibes_projects
    ]
    excluded = [
        case
        for case in python_cases
        if case["repository"] in susvibes_projects
    ]
    seed = hashlib.sha256(
        "\0".join(
            (
                _SEED_NAMESPACE,
                normalized_upstream,
                dataset_sha256,
                normalized_belief,
            )
        ).encode("utf-8")
    ).hexdigest()
    repositories = sorted(
        {case["repository"] for case in independent},
        key=lambda repository: (
            _rank(seed, "repository", repository),
            repository,
        ),
    )
    development_repository_count = math.ceil(
        _DEVELOPMENT_REPOSITORY_FRACTION * len(repositories)
    )
    development_repositories = frozenset(
        repositories[:development_repository_count]
    )
    development = _ordered_cases(
        (
            case
            for case in independent
            if case["repository"] in development_repositories
        ),
        seed=seed,
        cohort="development",
    )
    reserved = _ordered_cases(
        (
            case
            for case in independent
            if case["repository"] not in development_repositories
        ),
        seed=seed,
        cohort="reserved",
    )
    minimums = {
        "development_case_count": _MINIMUM_DEVELOPMENT_CASES,
        "development_repository_count": (
            _MINIMUM_DEVELOPMENT_REPOSITORIES
        ),
        "reserved_case_count": _MINIMUM_RESERVED_CASES,
        "reserved_repository_count": _MINIMUM_RESERVED_REPOSITORIES,
    }
    observed = {
        "development_case_count": len(development),
        "development_repository_count": len(
            {case["repository"] for case in development}
        ),
        "reserved_case_count": len(reserved),
        "reserved_repository_count": len(
            {case["repository"] for case in reserved}
        ),
    }
    payload: dict[str, Any] = {
        "schema_version": PATCHEVAL_EXPERIMENT_SCHEMA_VERSION,
        "selection_algorithm": PATCHEVAL_EXPERIMENT_ALGORITHM,
        "source": {
            "upstream_commit": normalized_upstream,
            "dataset_name": dataset_path.name,
            "dataset_sha256": dataset_sha256,
            "dataset_record_count": len(records),
            "python_record_count": python_record_count,
            "python_required_field_eligible_count": len(python_cases),
            "python_required_field_ineligible_count": (
                python_record_count - len(python_cases)
            ),
            "python_ineligibility_counts": ineligible_counts,
        },
        "belief": {
            "starting_commit": normalized_belief,
            "preparation_commit": normalized_preparation,
            "protocol_name": protocol_path.name,
            "protocol_sha256": protocol_sha256,
        },
        "susvibes_exclusion": {
            "dataset_name": susvibes_path.name,
            "dataset_sha256": susvibes_sha256,
            "project_count": len(susvibes_projects),
            "projects_sha256": _strings_sha256(
                sorted(susvibes_projects)
            ),
            "excluded_case_count": len(excluded),
            "excluded_case_ids_sha256": _strings_sha256(
                sorted(case["case_id"] for case in excluded)
            ),
        },
        "selection": {
            "language": "Python",
            "seed_sha256": seed,
            "development_repository_fraction": (
                _DEVELOPMENT_REPOSITORY_FRACTION
            ),
            "eligible_case_count": len(independent),
            "eligible_repository_count": len(repositories),
            "eligible_case_ids_sha256": _strings_sha256(
                sorted(case["case_id"] for case in independent)
            ),
            "eligible_repositories_sha256": _strings_sha256(
                sorted(repositories)
            ),
        },
        "cohorts": {
            "development": _cohort_payload(development),
            "reserved": _cohort_payload(reserved),
        },
        "minimums": minimums,
        "observed": observed,
        "eligible_for_architecture_tuning": all(
            observed[key] >= value
            for key, value in minimums.items()
        ),
        "boundaries": {
            "manifest_is_evaluator_side": True,
            "aggregate_only_cli_output": True,
            "project_disjoint_from_susvibes": True,
            "reserved_case_details_inspected": False,
            "reserved_case_ids_forwarded_to_reviewer": False,
            "reference_metadata_forwarded_to_reviewer": False,
            "docker_images_pulled": False,
            "dynamic_tests_executed": False,
        },
    }
    payload["status"] = (
        "ready"
        if payload["eligible_for_architecture_tuning"]
        else "ineligible"
    )
    payload["deterministic_digest"] = _semantic_digest(payload)
    return payload


def validate_patcheval_experiment_manifest(
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate split integrity without returning reserved identities."""

    if payload.get("schema_version") != (
        PATCHEVAL_EXPERIMENT_SCHEMA_VERSION
    ):
        raise ValueError("unsupported PatchEval experiment schema")
    if payload.get("selection_algorithm") != (
        PATCHEVAL_EXPERIMENT_ALGORITHM
    ):
        raise ValueError("unsupported PatchEval selection algorithm")
    if payload.get("status") not in {"ready", "ineligible"}:
        raise ValueError("invalid PatchEval experiment status")
    recorded = _sha256(
        payload.get("deterministic_digest"),
        "PatchEval manifest digest",
    )
    if recorded != _semantic_digest(payload):
        raise ValueError("PatchEval experiment manifest digest mismatch")

    source = _mapping(payload, "source")
    _commit(source.get("upstream_commit"), "upstream commit")
    _sha256(source.get("dataset_sha256"), "PatchEval dataset digest")
    belief = _mapping(payload, "belief")
    _commit(belief.get("starting_commit"), "BELIEF starting commit")
    _commit(belief.get("preparation_commit"), "BELIEF preparation commit")
    _sha256(belief.get("protocol_sha256"), "BELIEF protocol digest")
    exclusion = _mapping(payload, "susvibes_exclusion")
    _sha256(
        exclusion.get("dataset_sha256"),
        "SusVibes dataset digest",
    )
    _sha256(
        exclusion.get("projects_sha256"),
        "SusVibes project digest",
    )
    _sha256(
        exclusion.get("excluded_case_ids_sha256"),
        "excluded case digest",
    )
    selection = _mapping(payload, "selection")
    _sha256(selection.get("seed_sha256"), "selection seed")
    _sha256(
        selection.get("eligible_case_ids_sha256"),
        "eligible case digest",
    )
    _sha256(
        selection.get("eligible_repositories_sha256"),
        "eligible repository digest",
    )

    cohorts = _mapping(payload, "cohorts")
    development = _validate_cohort(cohorts, "development")
    reserved = _validate_cohort(cohorts, "reserved")
    if set(development) & set(reserved):
        raise ValueError("PatchEval cohorts overlap")
    if len(development) + len(reserved) != _integer(
        selection,
        "eligible_case_count",
    ):
        raise ValueError("PatchEval eligible case count mismatch")
    observed = _mapping(payload, "observed")
    if len(development) != _integer(
        observed,
        "development_case_count",
    ):
        raise ValueError("PatchEval development count mismatch")
    if len(reserved) != _integer(
        observed,
        "reserved_case_count",
    ):
        raise ValueError("PatchEval reserved count mismatch")
    minimums = _mapping(payload, "minimums")
    expected_eligibility = all(
        _integer(observed, key) >= _integer(minimums, key)
        for key in (
            "development_case_count",
            "development_repository_count",
            "reserved_case_count",
            "reserved_repository_count",
        )
    )
    if payload.get("eligible_for_architecture_tuning") is not (
        expected_eligibility
    ):
        raise ValueError("PatchEval minimum eligibility mismatch")
    expected_status = "ready" if expected_eligibility else "ineligible"
    if payload.get("status") != expected_status:
        raise ValueError("PatchEval status does not match minimums")
    boundaries = _mapping(payload, "boundaries")
    required_true = (
        "manifest_is_evaluator_side",
        "aggregate_only_cli_output",
        "project_disjoint_from_susvibes",
    )
    required_false = (
        "reserved_case_details_inspected",
        "reserved_case_ids_forwarded_to_reviewer",
        "reference_metadata_forwarded_to_reviewer",
        "docker_images_pulled",
        "dynamic_tests_executed",
    )
    if any(boundaries.get(key) is not True for key in required_true):
        raise ValueError("PatchEval manifest boundary is not enforced")
    if any(boundaries.get(key) is not False for key in required_false):
        raise ValueError("PatchEval manifest boundary is not enforced")
    return json.loads(json.dumps(payload))


def write_patcheval_experiment_manifest(
    dataset: str | Path,
    susvibes_dataset: str | Path,
    protocol: str | Path,
    output: str | Path,
    *,
    upstream_commit: str,
    belief_starting_commit: str,
    preparation_commit: str,
) -> dict[str, Any]:
    """Create an evaluator-side PatchEval split without overwrite."""

    payload = build_patcheval_experiment_manifest(
        dataset,
        susvibes_dataset,
        protocol,
        upstream_commit=upstream_commit,
        belief_starting_commit=belief_starting_commit,
        preparation_commit=preparation_commit,
    )
    output_path = Path(output).resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open(
            "x",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise ValueError(
            f"refusing to overwrite PatchEval manifest: {output_path}"
        ) from exc
    return payload


def load_patcheval_development_cohort(
    manifest: str | Path,
    *,
    dataset: str | Path,
    susvibes_dataset: str | Path,
    protocol: str | Path,
) -> tuple[list[str], dict[str, str]]:
    """Load only the development IDs after rebuilding the frozen split."""

    manifest_path = Path(manifest).resolve()
    payload = _load_json_object(
        manifest_path,
        "PatchEval experiment manifest",
    )
    validated = validate_patcheval_experiment_manifest(payload)
    if validated["status"] != "ready":
        raise ValueError(
            "PatchEval corpus is ineligible for architecture tuning"
        )
    source = _mapping(validated, "source")
    belief = _mapping(validated, "belief")
    rebuilt = build_patcheval_experiment_manifest(
        dataset,
        susvibes_dataset,
        protocol,
        upstream_commit=str(source["upstream_commit"]),
        belief_starting_commit=str(belief["starting_commit"]),
        preparation_commit=str(belief["preparation_commit"]),
    )
    if rebuilt["deterministic_digest"] != validated[
        "deterministic_digest"
    ]:
        raise ValueError("PatchEval frozen inputs or split changed")
    development = _mapping(
        _mapping(validated, "cohorts"),
        "development",
    )
    ids = [str(value) for value in development["case_ids"]]
    return ids, {
        "manifest_sha256": _file_sha256(manifest_path),
        "manifest_digest": str(validated["deterministic_digest"]),
        "dataset_sha256": str(source["dataset_sha256"]),
        "cohort": "development",
    }


def _eligible_python_cases(
    records: list[Any],
) -> tuple[list[dict[str, str]], dict[str, int]]:
    cases: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    ineligible_counts = {
        "invalid_repository": 0,
        "missing_cve_id": 0,
        "missing_image_url": 0,
        "missing_patch_url": 0,
        "missing_repository": 0,
    }
    for record in records:
        if not isinstance(record, Mapping):
            raise ValueError("PatchEval records must be objects")
        if str(record.get("programing_language") or "").strip().lower() != (
            "python"
        ):
            continue
        required = {
            "cve_id": record.get("cve_id"),
            "image_url": record.get("image_url"),
            "patch_url": record.get("patch_url"),
            "repository": record.get("repo"),
        }
        missing = [
            key
            for key, value in required.items()
            if not isinstance(value, str) or not value.strip()
        ]
        if missing:
            for key in missing:
                ineligible_counts[f"missing_{key}"] += 1
            continue
        case_id = str(required["cve_id"]).strip()
        try:
            repository = _normalize_repository(
                str(required["repository"]).strip()
            )
        except ValueError:
            ineligible_counts["invalid_repository"] += 1
            continue
        if case_id in seen_ids:
            raise ValueError("PatchEval Python case IDs must be unique")
        seen_ids.add(case_id)
        cases.append({
            "case_id": case_id,
            "repository": repository,
        })
    return cases, ineligible_counts


def _load_susvibes_projects(path: Path) -> set[str]:
    projects: set[str] = set()
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                record = json.loads(line)
                if not isinstance(record, Mapping):
                    raise ValueError(
                        f"SusVibes line {line_number} must be an object"
                    )
                projects.add(
                    _normalize_repository(
                        _required_string(record, "project")
                    )
                )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid SusVibes dataset: {path}: {exc}") from exc
    if not projects:
        raise ValueError("SusVibes project exclusion set is empty")
    return projects


def _normalize_repository(value: str) -> str:
    selected = value.strip().replace("\\", "/")
    parsed = urlparse(selected)
    if parsed.scheme:
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("repository URL scheme must be HTTP(S)")
        if parsed.netloc.lower() not in {"github.com", "www.github.com"}:
            raise ValueError("repository URL must use github.com")
        selected = parsed.path
    selected = selected.strip("/")
    if selected.lower().startswith("github.com/"):
        selected = selected[len("github.com/"):]
    if selected.lower().endswith(".git"):
        selected = selected[:-4]
    parts = selected.split("/")
    if (
        len(parts) != 2
        or any(not part or part in {".", ".."} for part in parts)
    ):
        raise ValueError("repository identity must be owner/repository")
    return "/".join(parts).lower()


def _ordered_cases(
    cases: Any,
    *,
    seed: str,
    cohort: str,
) -> list[dict[str, str]]:
    return sorted(
        cases,
        key=lambda case: (
            _rank(seed, cohort, case["case_id"]),
            case["case_id"],
        ),
    )


def _cohort_payload(cases: list[dict[str, str]]) -> dict[str, Any]:
    case_ids = [case["case_id"] for case in cases]
    repositories = sorted({case["repository"] for case in cases})
    return {
        "case_count": len(case_ids),
        "repository_count": len(repositories),
        "case_ids": case_ids,
        "case_ids_sha256": _strings_sha256(case_ids),
        "repositories_sha256": _strings_sha256(repositories),
    }


def _validate_cohort(
    cohorts: Mapping[str, Any],
    name: str,
) -> tuple[str, ...]:
    cohort = _mapping(cohorts, name)
    raw_ids = cohort.get("case_ids")
    if (
        not isinstance(raw_ids, list)
        or any(
            not isinstance(value, str) or not value.strip()
            for value in raw_ids
        )
        or len(raw_ids) != len(set(raw_ids))
    ):
        raise ValueError(f"invalid PatchEval {name} case IDs")
    ids = tuple(raw_ids)
    if len(ids) != _integer(cohort, "case_count"):
        raise ValueError(f"PatchEval {name} case count mismatch")
    if _strings_sha256(list(ids)) != _sha256(
        cohort.get("case_ids_sha256"),
        f"PatchEval {name} case digest",
    ):
        raise ValueError(f"PatchEval {name} case digest mismatch")
    _sha256(
        cohort.get("repositories_sha256"),
        f"PatchEval {name} repository digest",
    )
    _integer(cohort, "repository_count")
    return ids


def _rank(seed: str, namespace: str, value: str) -> str:
    return hashlib.sha256(
        f"{seed}\0{namespace}\0{value}".encode("utf-8")
    ).hexdigest()


def _strings_sha256(values: list[str]) -> str:
    encoded = json.dumps(
        values,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        str(key): value
        for key, value in payload.items()
        if key != "deterministic_digest"
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _file_sha256(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"required dataset does not exist: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json_array(path: Path, label: str) -> list[Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{label} must be a JSON array")
    return payload


def _load_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected.strip():
        raise ValueError(f"{key} must be a non-empty string")
    return selected.strip()


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ValueError(f"{key} must be an object")
    return selected


def _integer(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if (
        not isinstance(selected, int)
        or isinstance(selected, bool)
        or selected < 0
    ):
        raise ValueError(f"{key} must be a non-negative integer")
    return selected


def _commit(value: Any, label: str) -> str:
    selected = str(value or "").strip().lower()
    if (
        len(selected) != 40
        or any(character not in "0123456789abcdef" for character in selected)
    ):
        raise ValueError(f"{label} must be a 40-character Git commit")
    return selected


def _sha256(value: Any, label: str) -> str:
    selected = str(value or "")
    if (
        len(selected) != 64
        or any(character not in "0123456789abcdef" for character in selected)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")
    return selected


__all__ = [
    "PATCHEVAL_EXPERIMENT_ALGORITHM",
    "PATCHEVAL_EXPERIMENT_SCHEMA_VERSION",
    "build_patcheval_experiment_manifest",
    "load_patcheval_development_cohort",
    "validate_patcheval_experiment_manifest",
    "write_patcheval_experiment_manifest",
]
