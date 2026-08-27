"""Offline, revision-bound benchmark for public vulnerable/fixed source pairs.

The runner reads only explicitly listed Python blobs from local Git object
databases.  It never checks out, imports, installs, or executes third-party
code, and it disables Git lazy fetching while the benchmark is running.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

from ..static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target


OPEN_SOURCE_PAIRS_CORPUS_SCHEMA_VERSION = "belief.open_source_pairs_corpus.v1"
OPEN_SOURCE_PAIRS_RESULT_SCHEMA_VERSION = "belief.open_source_pairs_result.v1"
OPEN_SOURCE_PAIRS_RUNNER_VERSION = "open_source_pairs_static_v1"
OPEN_SOURCE_PAIRS_REPETITIONS = 2

_WARNING_STATUSES = frozenset({"actionable", "needs_review"})
_MAX_TARGET_FILES = 8
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_TOTAL_BYTES = 8 * 1024 * 1024
_COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CVE_PATTERN = re.compile(r"^CVE-[0-9]{4}-[0-9]+$")
_CWE_PATTERN = re.compile(r"^CWE-[0-9]+$")
_GHSA_PATTERN = re.compile(r"^https://github\.com/advisories/GHSA-[0-9a-z-]+$")

_TOP_LEVEL_FIELDS = {
    "schema_version",
    "corpus_id",
    "classification",
    "thresholds",
    "cases",
}
_CLASSIFICATION_FIELDS = {
    "role",
    "evaluation_mode",
    "project_disjoint_from_susvibes_v1",
    "negative_controls_present",
    "dynamic_execution",
    "secpass_comparable",
    "claim_boundary",
}
_THRESHOLD_FIELDS = {
    "minimum_vulnerable_warning_recall",
    "maximum_fixed_warning_false_positive_rate",
    "minimum_paired_discrimination_rate",
    "minimum_deterministic_repetition_rate",
    "maximum_analysis_error_count",
}
_CASE_FIELDS = {
    "id",
    "project",
    "repository_url",
    "checkout_dir",
    "advisory_url",
    "cve_id",
    "cwe",
    "case_type",
    "license",
    "vulnerable_revision",
    "fixed_revision",
    "targets",
}
_LICENSE_FIELDS = {"spdx", "path"}
_TARGET_FIELDS = {
    "path",
    "vulnerable_sha256",
    "fixed_sha256",
    "relevant_line_range",
}

Analyzer = Callable[[Path, StaticAnalysisOptions], Any]


class OpenSourcePairsError(ValueError):
    """The corpus, repository identity, or source binding is invalid."""


def load_open_source_pairs_manifest(path: str | Path) -> dict[str, Any]:
    """Load and strictly validate the public paired-source manifest."""

    manifest_path = Path(path)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OpenSourcePairsError(f"invalid open-source pair manifest: {exc}") from exc
    if not isinstance(payload, dict):
        raise OpenSourcePairsError("open-source pair manifest must be an object")
    _require_exact_fields(payload, _TOP_LEVEL_FIELDS, "manifest")
    if payload["schema_version"] != OPEN_SOURCE_PAIRS_CORPUS_SCHEMA_VERSION:
        raise OpenSourcePairsError("unsupported open-source pair manifest schema")
    _non_empty_string(payload, "corpus_id", "manifest")

    classification = _mapping(payload, "classification", "manifest")
    _require_exact_fields(classification, _CLASSIFICATION_FIELDS, "classification")
    for field in ("role", "evaluation_mode", "claim_boundary"):
        _non_empty_string(classification, field, "classification")
    for field in (
        "project_disjoint_from_susvibes_v1",
        "negative_controls_present",
        "dynamic_execution",
        "secpass_comparable",
    ):
        if not isinstance(classification.get(field), bool):
            raise OpenSourcePairsError(f"classification.{field} must be a boolean")

    thresholds = _mapping(payload, "thresholds", "manifest")
    _require_exact_fields(thresholds, _THRESHOLD_FIELDS, "thresholds")
    for field in _THRESHOLD_FIELDS - {"maximum_analysis_error_count"}:
        value = thresholds.get(field)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise OpenSourcePairsError(f"thresholds.{field} must be numeric")
        if not 0.0 <= float(value) <= 1.0:
            raise OpenSourcePairsError(f"thresholds.{field} must be between 0 and 1")
    maximum_errors = thresholds.get("maximum_analysis_error_count")
    if isinstance(maximum_errors, bool) or not isinstance(maximum_errors, int):
        raise OpenSourcePairsError(
            "thresholds.maximum_analysis_error_count must be an integer"
        )
    if maximum_errors < 0:
        raise OpenSourcePairsError(
            "thresholds.maximum_analysis_error_count must be non-negative"
        )

    raw_cases = payload.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise OpenSourcePairsError("manifest.cases must be a non-empty array")
    case_ids: set[str] = set()
    projects: set[str] = set()
    checkout_dirs: set[str] = set()
    for index, raw_case in enumerate(raw_cases):
        if not isinstance(raw_case, dict):
            raise OpenSourcePairsError(f"cases[{index}] must be an object")
        _validate_case(raw_case, index)
        case_id = str(raw_case["id"])
        project = str(raw_case["project"]).casefold()
        checkout_dir = str(raw_case["checkout_dir"]).casefold()
        if case_id in case_ids:
            raise OpenSourcePairsError(f"duplicate case id: {case_id}")
        if project in projects:
            raise OpenSourcePairsError(f"duplicate project: {raw_case['project']}")
        if checkout_dir in checkout_dirs:
            raise OpenSourcePairsError(
                f"duplicate checkout directory: {raw_case['checkout_dir']}"
            )
        case_ids.add(case_id)
        projects.add(project)
        checkout_dirs.add(checkout_dir)
    return payload


def evaluate_open_source_pairs_benchmark(
    manifest: str | Path,
    repositories_root: str | Path,
    *,
    belief_revision: str,
    analyzer: Analyzer = analyze_static_target,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Evaluate exact vulnerable/fixed blobs twice without third-party execution."""

    normalized_revision = _commit(belief_revision, "belief_revision")
    manifest_path = Path(manifest).resolve(strict=True)
    payload = load_open_source_pairs_manifest(manifest_path)
    root = Path(repositories_root).resolve(strict=True)
    if not root.is_dir():
        raise OpenSourcePairsError("repositories root must be a directory")

    options = StaticAnalysisOptions(
        max_files=_MAX_TARGET_FILES,
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        include_audit_cases=True,
        audit_mode=True,
        reportability=True,
        max_file_bytes=_MAX_FILE_BYTES,
        max_total_source_bytes=_MAX_TOTAL_BYTES,
    )
    started = clock()
    rows: list[dict[str, Any]] = []
    for case in payload["cases"]:
        repository = _resolve_repository(root, case)
        source_blobs = {
            "vulnerable": _read_variant_blobs(repository, case, "vulnerable"),
            "fixed": _read_variant_blobs(repository, case, "fixed"),
        }
        variants = {
            name: _evaluate_variant(
                case,
                name,
                blobs,
                analyzer=analyzer,
                options=options,
                clock=clock,
            )
            for name, blobs in source_blobs.items()
        }
        vulnerable = variants["vulnerable"]
        fixed = variants["fixed"]
        vulnerable_detected = bool(vulnerable["localized_target_warning_present"])
        fixed_warning = bool(fixed["localized_target_warning_observed_any"])
        rows.append(
            {
                "id": case["id"],
                "project": case["project"],
                "advisory_url": case["advisory_url"],
                "cve_id": case["cve_id"],
                "cwe": case["cwe"],
                "case_type": case["case_type"],
                "license": dict(case["license"]),
                "vulnerable_revision": case["vulnerable_revision"],
                "fixed_revision": case["fixed_revision"],
                "variants": variants,
                "vulnerable_warning_detected": vulnerable_detected,
                "fixed_warning_false_positive": fixed_warning,
                "paired_vulnerable_only_discrimination": bool(
                    vulnerable_detected
                    and not fixed_warning
                    and vulnerable["deterministic"]
                    and fixed["deterministic"]
                ),
            }
        )

    metrics = _summarize(rows)
    threshold_evaluation = _evaluate_thresholds(metrics, payload["thresholds"])
    passed = all(item["passed"] for item in threshold_evaluation.values())
    result: dict[str, Any] = {
        "schema_version": OPEN_SOURCE_PAIRS_RESULT_SCHEMA_VERSION,
        "runner_version": OPEN_SOURCE_PAIRS_RUNNER_VERSION,
        "corpus": {
            "corpus_id": payload["corpus_id"],
            "manifest_name": manifest_path.name,
            "manifest_sha256": _file_sha256(manifest_path),
            "classification": dict(payload["classification"]),
        },
        "belief": {
            "revision": normalized_revision,
            "analysis_options": options.to_dict(),
        },
        "boundaries": {
            "third_party_code_executed": False,
            "third_party_code_imported": False,
            "third_party_dependencies_installed": False,
            "network_used_by_runner": False,
            "git_worktree_read": False,
            "only_manifest_listed_git_blobs_read": True,
            "oracle_localized_target_files": True,
        },
        "case_count": len(rows),
        "repetitions_per_variant": OPEN_SOURCE_PAIRS_REPETITIONS,
        "metrics": metrics,
        "thresholds": dict(payload["thresholds"]),
        "threshold_evaluation": threshold_evaluation,
        "status": "passed" if passed else "failed",
        "exit_code": 0 if passed else 1,
        "cases": rows,
        "duration_seconds": round(max(0.0, float(clock() - started)), 6),
    }
    result["deterministic_digest"] = _semantic_digest(result)
    return result


def write_open_source_pairs_result(
    manifest: str | Path,
    repositories_root: str | Path,
    output: str | Path,
    *,
    belief_revision: str,
    analyzer: Analyzer = analyze_static_target,
) -> dict[str, Any]:
    """Run the benchmark and create, but never replace, its JSON artifact."""

    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    result = evaluate_open_source_pairs_benchmark(
        manifest,
        repositories_root,
        belief_revision=belief_revision,
        analyzer=analyzer,
    )
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
    except FileExistsError as exc:
        raise OpenSourcePairsError(
            f"open-source pair result already exists: {destination}"
        ) from exc
    return result


def _validate_case(case: Mapping[str, Any], index: int) -> None:
    label = f"cases[{index}]"
    _require_exact_fields(case, _CASE_FIELDS, label)
    for field in ("id", "project", "repository_url", "checkout_dir", "case_type"):
        _non_empty_string(case, field, label)
    project = str(case["project"])
    parts = project.split("/")
    if len(parts) != 2 or any(not part or part in {".", ".."} for part in parts):
        raise OpenSourcePairsError(f"{label}.project must be owner/repository")
    expected_url = f"https://github.com/{project}.git"
    if _normalized_repository_url(str(case["repository_url"])) != (
        _normalized_repository_url(expected_url)
    ):
        raise OpenSourcePairsError(f"{label}.repository_url does not match project")
    checkout_dir = str(case["checkout_dir"])
    if (
        checkout_dir in {".", ".."}
        or "/" in checkout_dir
        or "\\" in checkout_dir
        or Path(checkout_dir).is_absolute()
    ):
        raise OpenSourcePairsError(f"{label}.checkout_dir must be one directory name")
    advisory = str(case.get("advisory_url") or "")
    if not _GHSA_PATTERN.fullmatch(advisory):
        raise OpenSourcePairsError(f"{label}.advisory_url must be a GitHub advisory")
    if not _CVE_PATTERN.fullmatch(str(case.get("cve_id") or "")):
        raise OpenSourcePairsError(f"{label}.cve_id is invalid")
    if not _CWE_PATTERN.fullmatch(str(case.get("cwe") or "")):
        raise OpenSourcePairsError(f"{label}.cwe is invalid")
    vulnerable = _commit(case.get("vulnerable_revision"), f"{label}.vulnerable_revision")
    fixed = _commit(case.get("fixed_revision"), f"{label}.fixed_revision")
    if vulnerable == fixed:
        raise OpenSourcePairsError(f"{label} revisions must differ")

    license_payload = _mapping(case, "license", label)
    _require_exact_fields(license_payload, _LICENSE_FIELDS, f"{label}.license")
    _non_empty_string(license_payload, "spdx", f"{label}.license")
    _relative_posix_path(license_payload.get("path"), f"{label}.license.path")

    targets = case.get("targets")
    if not isinstance(targets, list) or not 1 <= len(targets) <= _MAX_TARGET_FILES:
        raise OpenSourcePairsError(
            f"{label}.targets must contain 1 to {_MAX_TARGET_FILES} entries"
        )
    paths: set[str] = set()
    for target_index, target in enumerate(targets):
        target_label = f"{label}.targets[{target_index}]"
        if not isinstance(target, Mapping):
            raise OpenSourcePairsError(f"{target_label} must be an object")
        _require_exact_fields(target, _TARGET_FIELDS, target_label)
        path = _relative_posix_path(target.get("path"), f"{target_label}.path")
        if not path.endswith(".py"):
            raise OpenSourcePairsError(f"{target_label}.path must be Python source")
        if path in paths:
            raise OpenSourcePairsError(f"{label} contains duplicate target paths")
        paths.add(path)
        for variant in ("vulnerable", "fixed"):
            digest = str(target.get(f"{variant}_sha256") or "")
            if not _SHA256_PATTERN.fullmatch(digest):
                raise OpenSourcePairsError(
                    f"{target_label}.{variant}_sha256 must be lowercase SHA-256"
                )
        if target["vulnerable_sha256"] == target["fixed_sha256"]:
            raise OpenSourcePairsError(
                f"{target_label} must bind different vulnerable and fixed blobs"
            )
        line_range = target.get("relevant_line_range")
        if (
            not isinstance(line_range, list)
            or len(line_range) != 2
            or any(
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
                for value in line_range
            )
            or line_range[0] > line_range[1]
        ):
            raise OpenSourcePairsError(
                f"{target_label}.relevant_line_range must be [start, end]"
            )


def _resolve_repository(root: Path, case: Mapping[str, Any]) -> Path:
    try:
        repository = (root / str(case["checkout_dir"])).resolve(strict=True)
        repository.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise OpenSourcePairsError(
            f"repository is unavailable for {case['id']}"
        ) from exc
    if not repository.is_dir() or not (repository / ".git").is_dir():
        raise OpenSourcePairsError(f"repository is not an in-place Git checkout: {case['id']}")
    top_level = Path(_git_text(repository, "rev-parse", "--show-toplevel")).resolve()
    if top_level != repository:
        raise OpenSourcePairsError(f"repository top level mismatch: {case['id']}")
    observed_url = _git_text(repository, "remote", "get-url", "origin")
    if _normalized_repository_url(observed_url) != _normalized_repository_url(
        str(case["repository_url"])
    ):
        raise OpenSourcePairsError(f"repository origin mismatch: {case['id']}")
    vulnerable = _git_text(
        repository,
        "rev-parse",
        "--verify",
        f"{case['vulnerable_revision']}^{{commit}}",
    ).lower()
    fixed = _git_text(
        repository,
        "rev-parse",
        "--verify",
        f"{case['fixed_revision']}^{{commit}}",
    ).lower()
    if vulnerable != case["vulnerable_revision"] or fixed != case["fixed_revision"]:
        raise OpenSourcePairsError(f"repository revisions mismatch: {case['id']}")
    parent = _git_text(repository, "rev-parse", f"{fixed}^").lower()
    if parent != vulnerable:
        raise OpenSourcePairsError(f"fixed revision is not paired to its first parent: {case['id']}")
    _git_bytes(
        repository,
        "cat-file",
        "-e",
        f"{fixed}:{case['license']['path']}",
    )
    return repository


def _read_variant_blobs(
    repository: Path,
    case: Mapping[str, Any],
    variant: str,
) -> tuple[tuple[str, bytes, str], ...]:
    revision = str(case[f"{variant}_revision"])
    blobs: list[tuple[str, bytes, str]] = []
    total_bytes = 0
    for target in case["targets"]:
        path = str(target["path"])
        data = _git_bytes(repository, "cat-file", "blob", f"{revision}:{path}")
        if len(data) > _MAX_FILE_BYTES:
            raise OpenSourcePairsError(f"source file exceeds byte limit: {case['id']}:{path}")
        total_bytes += len(data)
        if total_bytes > _MAX_TOTAL_BYTES:
            raise OpenSourcePairsError(f"source snapshot exceeds byte limit: {case['id']}")
        digest = hashlib.sha256(data).hexdigest()
        if digest != target[f"{variant}_sha256"]:
            raise OpenSourcePairsError(
                f"source digest mismatch: {case['id']}:{variant}:{path}"
            )
        blobs.append((path, data, digest))
    return tuple(blobs)


def _evaluate_variant(
    case: Mapping[str, Any],
    variant: str,
    blobs: Sequence[tuple[str, bytes, str]],
    *,
    analyzer: Analyzer,
    options: StaticAnalysisOptions,
    clock: Callable[[], float],
) -> dict[str, Any]:
    projections: list[dict[str, Any]] = []
    durations: list[float] = []
    for _ in range(OPEN_SOURCE_PAIRS_REPETITIONS):
        started = clock()
        with tempfile.TemporaryDirectory(prefix="belief-open-source-pair-") as directory:
            snapshot_root = Path(directory)
            for relative, data, _digest in blobs:
                destination = snapshot_root.joinpath(*PurePosixPath(relative).parts)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            try:
                analysis = analyzer(snapshot_root, options)
                projection = _project_analysis(analysis, case, snapshot_root)
            except Exception as exc:  # failures remain benchmark evidence
                projection = {
                    "analysis_succeeded": False,
                    "error": _normalized_error(exc, snapshot_root),
                    "finding_count": 0,
                    "audit_case_count": 0,
                    "warning_count": 0,
                    "target_signal_count": 0,
                    "target_warning_count": 0,
                    "localized_target_warning_count": 0,
                    "unrelated_warning_count": 0,
                    "audit_cases": [],
                    "diagnostics": [],
                }
        durations.append(round(max(0.0, float(clock() - started)), 6))
        projections.append(projection)

    repetition_digests = [_semantic_digest(item) for item in projections]
    all_succeeded = all(item["analysis_succeeded"] for item in projections)
    deterministic = bool(
        all_succeeded and len(set(repetition_digests)) == 1
    )
    localized_counts = [
        int(item["localized_target_warning_count"]) for item in projections
    ]
    return {
        "revision": case[f"{variant}_revision"],
        "source_files": [
            {"path": path, "bytes": len(data), "sha256": digest}
            for path, data, digest in blobs
        ],
        "source_set_sha256": _source_set_digest(blobs),
        "analysis": projections[0],
        "analysis_succeeded": all_succeeded,
        "repetition_digests": repetition_digests,
        "deterministic": deterministic,
        "localized_target_warning_present": bool(
            deterministic and localized_counts and all(count > 0 for count in localized_counts)
        ),
        "localized_target_warning_observed_any": any(count > 0 for count in localized_counts),
        "duration_seconds": durations,
    }


def _project_analysis(
    result: Any,
    case: Mapping[str, Any],
    snapshot_root: Path,
) -> dict[str, Any]:
    if isinstance(result, Mapping):
        audit_cases = result.get("audit_cases") or ()
        diagnostics = result.get("diagnostics") or ()
        records = result.get("records") or result.get("findings") or ()
    else:
        audit_cases = getattr(result, "audit_cases", ()) or ()
        diagnostics = getattr(result, "diagnostics", ()) or ()
        records = getattr(result, "records", ()) or ()
    normalized_cases = sorted(
        (_normalize_audit_case(item, snapshot_root) for item in _iterable(audit_cases)),
        key=_stable_json,
    )
    normalized_diagnostics = sorted(
        (_normalize_diagnostic(item, snapshot_root) for item in _iterable(diagnostics)),
        key=_stable_json,
    )
    warnings = [item for item in normalized_cases if item["status"] in _WARNING_STATUSES]
    target_signals = [
        item for item in normalized_cases if _matches_target(item, case, localized=False)
    ]
    target_warnings = [item for item in warnings if _matches_target(item, case, localized=False)]
    localized = [item for item in warnings if _matches_target(item, case, localized=True)]
    return {
        "analysis_succeeded": True,
        "finding_count": len(tuple(_iterable(records))),
        "audit_case_count": len(normalized_cases),
        "warning_count": len(warnings),
        "target_signal_count": len(target_signals),
        "target_warning_count": len(target_warnings),
        "localized_target_warning_count": len(localized),
        "unrelated_warning_count": len(warnings) - len(target_warnings),
        "audit_cases": normalized_cases,
        "diagnostics": normalized_diagnostics,
    }


def _normalize_audit_case(item: Any, snapshot_root: Path) -> dict[str, Any]:
    raw = _to_mapping(item)
    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
    reportability = (
        metadata.get("reportability")
        if isinstance(metadata.get("reportability"), Mapping)
        else {}
    )
    return {
        "case_id": str(raw.get("case_id") or ""),
        "case_type": str(raw.get("case_type") or raw.get("vulnerability_type") or ""),
        "cwe": str(raw.get("cwe") or raw.get("rule_id") or ""),
        "status": str(raw.get("status") or ""),
        "file": _normalized_source_path(raw.get("file"), snapshot_root),
        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
        "source": str(raw.get("source") or ""),
        "sink": str(raw.get("sink") or ""),
        "guarantees": _string_list(raw.get("guarantees")),
        "sanitizers": _string_list(raw.get("sanitizers")),
        "reason": str(raw.get("reason") or raw.get("root_cause") or ""),
        "reportability": {
            "proof_state": str(reportability.get("proof_state") or ""),
            "score": reportability.get("score")
            if isinstance(reportability.get("score"), int)
            else None,
            "verdict": str(reportability.get("verdict") or ""),
        },
    }


def _normalize_diagnostic(item: Any, snapshot_root: Path) -> dict[str, Any]:
    raw = _to_mapping(item)
    return {
        "code": str(raw.get("code") or ""),
        "message": _replace_snapshot(str(raw.get("message") or ""), snapshot_root),
        "file": _normalized_source_path(raw.get("file"), snapshot_root),
        "line": raw.get("line") if isinstance(raw.get("line"), int) else None,
        "function": str(raw.get("function") or ""),
    }


def _matches_target(
    audit_case: Mapping[str, Any],
    case: Mapping[str, Any],
    *,
    localized: bool,
) -> bool:
    if audit_case.get("case_type") != case.get("case_type"):
        return False
    observed_file = str(audit_case.get("file") or "").replace("\\", "/")
    observed_line = audit_case.get("line")
    for target in case["targets"]:
        expected_file = str(target["path"])
        file_matches = observed_file == expected_file or observed_file.endswith(
            f"/{expected_file}"
        ) or PurePosixPath(observed_file).name == PurePosixPath(expected_file).name
        if not file_matches:
            continue
        if not localized:
            return True
        start, end = target["relevant_line_range"]
        if isinstance(observed_line, int) and start <= observed_line <= end:
            return True
    return False


def _summarize(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    case_count = len(rows)
    vulnerable_detected = sum(bool(row["vulnerable_warning_detected"]) for row in rows)
    fixed_false_positive = sum(bool(row["fixed_warning_false_positive"]) for row in rows)
    paired = sum(bool(row["paired_vulnerable_only_discrimination"]) for row in rows)
    variant_results = [
        row["variants"][variant] for row in rows for variant in ("vulnerable", "fixed")
    ]
    deterministic = sum(bool(item["deterministic"]) for item in variant_results)
    analysis_errors = sum(not bool(item["analysis_succeeded"]) for item in variant_results)
    return {
        "case_count": case_count,
        "vulnerable_warning_count": vulnerable_detected,
        "vulnerable_warning_recall": _rate(vulnerable_detected, case_count),
        "fixed_warning_false_positive_count": fixed_false_positive,
        "fixed_warning_false_positive_rate": _rate(fixed_false_positive, case_count),
        "paired_discrimination_count": paired,
        "paired_discrimination_rate": _rate(paired, case_count),
        "deterministic_variant_count": deterministic,
        "variant_count": len(variant_results),
        "deterministic_repetition_rate": _rate(deterministic, len(variant_results)),
        "analysis_error_count": analysis_errors,
        "unrelated_warning_count_vulnerable": sum(
            int(row["variants"]["vulnerable"]["analysis"]["unrelated_warning_count"])
            for row in rows
        ),
        "unrelated_warning_count_fixed": sum(
            int(row["variants"]["fixed"]["analysis"]["unrelated_warning_count"])
            for row in rows
        ),
    }


def _evaluate_thresholds(
    metrics: Mapping[str, Any], thresholds: Mapping[str, Any]
) -> dict[str, dict[str, Any]]:
    checks = {
        "minimum_vulnerable_warning_recall": (
            "vulnerable_warning_recall",
            ">=",
            float(thresholds["minimum_vulnerable_warning_recall"]),
        ),
        "maximum_fixed_warning_false_positive_rate": (
            "fixed_warning_false_positive_rate",
            "<=",
            float(thresholds["maximum_fixed_warning_false_positive_rate"]),
        ),
        "minimum_paired_discrimination_rate": (
            "paired_discrimination_rate",
            ">=",
            float(thresholds["minimum_paired_discrimination_rate"]),
        ),
        "minimum_deterministic_repetition_rate": (
            "deterministic_repetition_rate",
            ">=",
            float(thresholds["minimum_deterministic_repetition_rate"]),
        ),
        "maximum_analysis_error_count": (
            "analysis_error_count",
            "<=",
            int(thresholds["maximum_analysis_error_count"]),
        ),
    }
    result: dict[str, dict[str, Any]] = {}
    for name, (metric, comparator, threshold) in checks.items():
        actual = metrics[metric]
        passed = actual >= threshold if comparator == ">=" else actual <= threshold
        result[name] = {
            "metric": metric,
            "actual": actual,
            "comparator": comparator,
            "threshold": threshold,
            "passed": bool(passed),
        }
    return result


def _git_text(repository: Path, *arguments: str) -> str:
    return _git_bytes(repository, *arguments).decode("utf-8", errors="strict").strip()


def _git_bytes(repository: Path, *arguments: str) -> bytes:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    try:
        completed = subprocess.run(
            ["git", "-C", str(repository), *arguments],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OpenSourcePairsError(f"offline Git read failed: {type(exc).__name__}") from exc
    if completed.returncode:
        message = completed.stderr.decode("utf-8", errors="replace").strip()
        raise OpenSourcePairsError(
            f"offline Git read failed ({completed.returncode}): {message or 'no details'}"
        )
    return completed.stdout


def _to_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    if hasattr(value, "to_dict") and callable(value.to_dict):
        payload = value.to_dict()
        if isinstance(payload, Mapping):
            return dict(payload)
    return {
        name: getattr(value, name)
        for name in (
            "case_id",
            "case_type",
            "vulnerability_type",
            "cwe",
            "rule_id",
            "status",
            "file",
            "line",
            "source",
            "sink",
            "guarantees",
            "sanitizers",
            "reason",
            "root_cause",
            "metadata",
            "code",
            "message",
            "function",
        )
        if hasattr(value, name)
    }


def _iterable(value: Any) -> Iterable[Any]:
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes, Mapping)):
        return value
    return ()


def _normalized_source_path(value: Any, snapshot_root: Path) -> str:
    selected = str(value or "")
    if not selected:
        return ""
    try:
        candidate = Path(selected)
        if candidate.is_absolute():
            return candidate.resolve().relative_to(snapshot_root.resolve()).as_posix()
    except (OSError, RuntimeError, ValueError):
        pass
    return selected.replace("\\", "/")


def _normalized_error(exc: Exception, snapshot_root: Path) -> str:
    return f"{type(exc).__name__}: {_replace_snapshot(str(exc), snapshot_root)}"


def _replace_snapshot(value: str, snapshot_root: Path) -> str:
    selected = value.replace(str(snapshot_root), "<snapshot>")
    return selected.replace(snapshot_root.as_posix(), "<snapshot>")


def _source_set_digest(blobs: Sequence[tuple[str, bytes, str]]) -> str:
    records = [
        {"path": path, "bytes": len(data), "sha256": digest}
        for path, data, digest in blobs
    ]
    return hashlib.sha256(_stable_json(records).encode("ascii")).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _semantic_digest(payload: Any) -> str:
    def normalize(value: Any) -> Any:
        if isinstance(value, Mapping):
            return {
                str(key): normalize(item)
                for key, item in value.items()
                if key not in {"deterministic_digest", "duration_seconds"}
            }
        if isinstance(value, (list, tuple)):
            return [normalize(item) for item in value]
        return value

    encoded = json.dumps(
        normalize(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _rate(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, Iterable) or isinstance(value, (str, bytes, Mapping)):
        return []
    return sorted({str(item) for item in value if str(item)})


def _mapping(value: Mapping[str, Any], key: str, label: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise OpenSourcePairsError(f"{label}.{key} must be an object")
    return selected


def _non_empty_string(value: Mapping[str, Any], key: str, label: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected.strip():
        raise OpenSourcePairsError(f"{label}.{key} must be a non-empty string")
    return selected


def _require_exact_fields(value: Mapping[str, Any], fields: set[str], label: str) -> None:
    observed = set(value)
    if observed != fields:
        missing = sorted(fields - observed)
        unknown = sorted(observed - fields)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if unknown:
            details.append(f"unknown={unknown}")
        raise OpenSourcePairsError(f"{label} fields are invalid: {'; '.join(details)}")


def _relative_posix_path(value: Any, label: str) -> str:
    selected = str(value or "")
    candidate = PurePosixPath(selected)
    if (
        not selected
        or "\\" in selected
        or candidate.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate.parts)
    ):
        raise OpenSourcePairsError(f"{label} must be a safe relative POSIX path")
    return selected


def _commit(value: Any, label: str) -> str:
    selected = str(value or "").lower()
    if not _COMMIT_PATTERN.fullmatch(selected):
        raise OpenSourcePairsError(f"{label} must be a 40-character Git commit")
    return selected


def _normalized_repository_url(value: str) -> str:
    selected = value.strip().rstrip("/").casefold()
    if selected.endswith(".git"):
        selected = selected[:-4]
    return selected


__all__ = [
    "OPEN_SOURCE_PAIRS_CORPUS_SCHEMA_VERSION",
    "OPEN_SOURCE_PAIRS_REPETITIONS",
    "OPEN_SOURCE_PAIRS_RESULT_SCHEMA_VERSION",
    "OPEN_SOURCE_PAIRS_RUNNER_VERSION",
    "OpenSourcePairsError",
    "evaluate_open_source_pairs_benchmark",
    "load_open_source_pairs_manifest",
    "write_open_source_pairs_result",
]
