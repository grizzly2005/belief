"""Evaluate BELIEF feedback on canonical SusVibes candidate implementations.

For each task, the evaluator reconstructs the masked task baseline, then
reviews two candidate worktrees:

* the historical vulnerable implementation reconstructed from ``task_patch``;
* the canonical secure implementation from ``golden_patch``.

The reviewer receives only each candidate worktree diff. It never receives the
dataset record, CWE labels, ``security_patch``, ``test_patch``, or hidden test
outcomes. Dataset-only artifacts remain on the evaluator side.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from .susvibes import LocalGitCorpus, load_susvibes_cases, parse_security_diff
from ..patch_review import review_candidate_patch


SUSVIBES_CANDIDATE_REVIEW_SCHEMA_VERSION = (
    "belief.susvibes_candidate_review.v1"
)
SUSVIBES_CANDIDATE_REVIEW_MODE = "susvibes_candidate_review_v1"


@dataclass(frozen=True)
class SusVibesCandidateReviewThresholds:
    """Acceptance gates for security-feedback discrimination."""

    minimum_vulnerable_warning_recall: float = 0.30
    maximum_secure_warning_false_positive_rate: float = 0.25
    minimum_paired_warning_discrimination_rate: float = 0.30

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            normalized = float(value)
            if not 0.0 <= normalized <= 1.0:
                raise ValueError(f"{name} must be between 0.0 and 1.0")
            object.__setattr__(self, name, normalized)

    def to_dict(self) -> dict[str, float]:
        return {
            key: float(value)
            for key, value in asdict(self).items()
        }


DEFAULT_CANDIDATE_REVIEW_THRESHOLDS = (
    SusVibesCandidateReviewThresholds()
)


def evaluate_susvibes_candidate_review(
    dataset: str | Path,
    repository_cache: str | Path,
    *,
    reviewer: Callable[..., dict[str, Any]] = review_candidate_patch,
    only_cwes: Iterable[str] = (),
    max_cases: int = 0,
    instance_ids: Iterable[str] = (),
    selection_provenance: Mapping[str, str] | None = None,
    thresholds: (
        SusVibesCandidateReviewThresholds
        | Mapping[str, float]
        | None
    ) = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Measure whether BELIEF warns on vulnerable but not secure candidates."""

    dataset_path = Path(dataset)
    corpus = LocalGitCorpus(repository_cache)
    configured_thresholds = _coerce_thresholds(thresholds)
    started = clock()
    reviewer_provenance = _reviewer_runtime_provenance(reviewer)
    requested_ids = tuple(str(value) for value in instance_ids)
    configured_cwes = tuple(str(value) for value in only_cwes)
    if len(requested_ids) != len(set(requested_ids)):
        raise ValueError("candidate-review instance IDs must be unique")
    if requested_ids and (configured_cwes or max_cases):
        raise ValueError(
            "explicit instance IDs cannot be combined with only_cwes or "
            "max_cases"
        )
    loaded_cases = load_susvibes_cases(
        dataset_path,
        only_cwes=configured_cwes,
        max_cases=0 if requested_ids else max_cases,
    )
    selected_cases = loaded_cases
    if requested_ids:
        cases_by_id = {
            str(case["instance_id"]): case
            for case in loaded_cases
        }
        missing = [
            instance_id
            for instance_id in requested_ids
            if instance_id not in cases_by_id
        ]
        if missing:
            raise ValueError(
                "candidate-review instance IDs are absent from the dataset: "
                + ", ".join(missing)
            )
        selected_cases = [
            cases_by_id[instance_id]
            for instance_id in requested_ids
        ]
    rows = [
        _evaluate_case(case, corpus, reviewer)
        for case in selected_cases
    ]
    metrics = _summarize(rows)
    threshold_evaluation = _evaluate_thresholds(
        metrics,
        configured_thresholds,
    )
    passed = all(
        item["passed"]
        for item in threshold_evaluation.values()
    )
    payload: dict[str, Any] = {
        "schema_version": SUSVIBES_CANDIDATE_REVIEW_SCHEMA_VERSION,
        "mode": SUSVIBES_CANDIDATE_REVIEW_MODE,
        "dataset": dataset_path.name,
        "dataset_sha256": _file_sha256(dataset_path),
        "case_count": len(rows),
        "metrics": metrics,
        "thresholds": configured_thresholds.to_dict(),
        "threshold_evaluation": threshold_evaluation,
        "thresholds_passed": passed,
        "status": "passed" if passed else "failed",
        "exit_code": 0 if passed else 1,
        "cases": rows,
        "reviewer_provenance": reviewer_provenance,
        "comparability": {
            "susvibes_secpass_equivalent": False,
            "security_tests_executed": False,
            "reviewer_received_benchmark_oracle": False,
            "evaluator_used_canonical_candidates": True,
            "measurement": (
                "oracle-separated static feedback discrimination on "
                "canonical vulnerable and secure candidate patches"
            ),
        },
        "duration_seconds": round(
            max(0.0, float(clock() - started)),
            6,
        ),
    }
    if requested_ids:
        selection = {
            "kind": "explicit_instance_ids",
            "case_count": len(requested_ids),
            "instance_ids_sha256": hashlib.sha256(
                json.dumps(
                    requested_ids,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest(),
        }
        if selection_provenance:
            selection["provenance"] = {
                str(key): str(value)
                for key, value in sorted(selection_provenance.items())
            }
        payload["selection"] = selection
    payload["deterministic_digest"] = _semantic_digest(payload)
    payload["metrics"]["deterministic_digest"] = payload[
        "deterministic_digest"
    ]
    payload["metrics"]["duration_seconds"] = payload["duration_seconds"]
    return payload


def write_susvibes_candidate_review_json(
    dataset: str | Path,
    repository_cache: str | Path,
    output: str | Path,
    **kwargs: Any,
) -> dict[str, Any]:
    payload = evaluate_susvibes_candidate_review(
        dataset,
        repository_cache,
        **kwargs,
    )
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _evaluate_case(
    case: dict[str, Any],
    corpus: LocalGitCorpus,
    reviewer: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    errors: list[str] = []
    for field in ("mask_patch", "task_patch", "golden_patch"):
        if not str(case.get(field) or "").strip():
            errors.append(f"missing_{field}")
    if errors:
        return _failed_case(case, errors)

    test_paths = {
        item.output_path
        for item in parse_security_diff(str(case.get("test_patch") or ""))
    }
    production_paths = _production_paths(case, test_paths)
    if not production_paths:
        return _failed_case(case, ["no_candidate_python_files"])

    fixed_sources: dict[str, str] = {}
    for path in production_paths:
        source = corpus.source(
            str(case["project"]),
            str(case["base_commit"]),
            path,
        )
        if source is None:
            errors.append(f"fixed_blob_missing:{path}")
        else:
            fixed_sources[path] = source
    if errors:
        return _failed_case(case, errors)

    try:
        with tempfile.TemporaryDirectory(
            prefix="belief-susvibes-candidate-"
        ) as temp:
            temp_root = Path(temp)
            masked = temp_root / "masked"
            _initialize_masked_repository(
                masked,
                fixed_sources,
                _filter_patch(
                    str(case["task_patch"]),
                    production_paths,
                ),
            )
            vulnerable = temp_root / "vulnerable"
            secure = temp_root / "secure"
            shutil.copytree(masked, vulnerable)
            shutil.copytree(masked, secure)
            _apply_patch(
                vulnerable,
                _filter_patch(
                    str(case["mask_patch"]),
                    production_paths,
                ),
                reverse=True,
            )
            _apply_patch(
                secure,
                _filter_patch(
                    str(case["golden_patch"]),
                    production_paths,
                ),
                reverse=False,
            )
            vulnerable_review = reviewer(vulnerable)
            secure_review = reviewer(secure)
    except (
        OSError,
        UnicodeError,
        subprocess.TimeoutExpired,
        ValueError,
    ) as exc:
        return _failed_case(
            case,
            [f"{type(exc).__name__}: {exc}"],
        )

    vulnerable_summary = _review_summary(vulnerable_review)
    secure_summary = _review_summary(secure_review)
    succeeded = bool(
        vulnerable_summary["analysis_succeeded"]
        and secure_summary["analysis_succeeded"]
    )
    return {
        "id": str(case["instance_id"]),
        "project": str(case["project"]),
        "commit": str(case["base_commit"]),
        "cwe_ids": list(case["cwe_ids"]),
        "cve_id": str(case.get("cve_id") or ""),
        "analysis_succeeded": succeeded,
        "errors": [],
        "vulnerable_candidate": vulnerable_summary,
        "secure_candidate": secure_summary,
        "vulnerable_warned": bool(
            vulnerable_summary["actionable_count"]
        ),
        "secure_warning_false_positive": bool(
            secure_summary["actionable_count"]
        ),
        "paired_warning_discriminated": bool(
            succeeded
            and vulnerable_summary["actionable_count"]
            and not secure_summary["actionable_count"]
        ),
    }


def _initialize_masked_repository(
    repository: Path,
    fixed_sources: Mapping[str, str],
    task_patch: str,
) -> None:
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")
    for relative, source in sorted(fixed_sources.items()):
        destination = _safe_destination(repository, relative)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(source, encoding="utf-8")
    _apply_patch(repository, task_patch, reverse=False)
    _git(repository, "add", "-A")
    _git(repository, "commit", "--quiet", "-m", "masked baseline")


def _apply_patch(
    repository: Path,
    patch: str,
    *,
    reverse: bool,
) -> None:
    if not patch.strip():
        raise ValueError("filtered candidate patch is empty")
    arguments = [
        "git",
        "-C",
        str(repository),
        "apply",
        "--whitespace=nowarn",
        "--recount",
    ]
    if reverse:
        arguments.append("--reverse")
    completed = subprocess.run(
        arguments,
        input=patch.encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=_git_env(),
        timeout=30,
    )
    if completed.returncode:
        error = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()
        raise ValueError(
            f"git apply failed: {error or completed.returncode}"
        )


def _filter_patch(patch: str, allowed_paths: set[str]) -> str:
    sections = _diff_sections(patch)
    kept: list[str] = []
    for section in sections:
        parsed = parse_security_diff(section)
        if not parsed:
            continue
        if parsed[0].output_path in allowed_paths:
            kept.append(section)
    return "".join(kept)


def _diff_sections(patch: str) -> list[str]:
    lines = str(patch or "").splitlines(keepends=True)
    starts = [
        index
        for index, line in enumerate(lines)
        if line.startswith("diff --git ")
    ]
    sections = []
    for offset, start in enumerate(starts):
        end = starts[offset + 1] if offset + 1 < len(starts) else len(lines)
        section = "".join(lines[start:end])
        if section and not section.endswith("\n"):
            section += "\n"
        sections.append(section)
    return sections


def _production_paths(
    case: Mapping[str, Any],
    test_paths: set[str],
) -> set[str]:
    paths = set()
    for field in ("mask_patch", "task_patch", "golden_patch"):
        for item in parse_security_diff(str(case.get(field) or "")):
            path = item.output_path
            if (
                path
                and path not in test_paths
                and not _looks_like_test(path)
            ):
                paths.add(path)
    return paths


def _looks_like_test(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(
        any(part.lower().startswith("test") for part in path.parts[:-1])
        or path.name.lower().startswith("test_")
        or path.name.lower().endswith("_test.py")
    )


def _review_summary(review: Mapping[str, Any]) -> dict[str, Any]:
    analysis = review.get("analysis")
    candidate_succeeded = False
    if isinstance(analysis, Mapping):
        candidate = analysis.get("candidate")
        if isinstance(candidate, Mapping):
            candidate_succeeded = bool(
                candidate.get("analysis_succeeded")
            )
    actionable_rows = [
        row
        for key in ("introduced_findings", "residual_findings")
        for row in review.get(key, [])
        if isinstance(row, Mapping) and row.get("actionable")
    ]
    return {
        "analysis_succeeded": candidate_succeeded,
        "status": str(review.get("status") or ""),
        "actionable_count": len(actionable_rows),
        "introduced_actionable_count": sum(
            row.get("classification") == "introduced"
            for row in actionable_rows
        ),
        "residual_actionable_count": sum(
            row.get("classification") == "residual"
            for row in actionable_rows
        ),
        "findings": [
            {
                key: row.get(key)
                for key in (
                    "cwe",
                    "rule_id",
                    "file",
                    "line",
                    "function",
                    "classification",
                )
            }
            for row in actionable_rows
        ],
        "review_digest": str(
            review.get("deterministic_digest") or ""
        ),
    }


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    succeeded = [
        row for row in rows if row["analysis_succeeded"]
    ]
    count = len(rows)
    evaluable = len(succeeded)
    vulnerable = sum(row["vulnerable_warned"] for row in succeeded)
    secure_fp = sum(
        row["secure_warning_false_positive"]
        for row in succeeded
    )
    paired = sum(
        row["paired_warning_discriminated"]
        for row in succeeded
    )
    return {
        "case_count": count,
        "evaluable_case_count": evaluable,
        "analysis_error_count": count - evaluable,
        "vulnerable_warning_count": vulnerable,
        "vulnerable_warning_recall": _ratio(
            vulnerable,
            evaluable,
        ),
        "secure_warning_false_positive_count": secure_fp,
        "secure_warning_false_positive_rate": _ratio(
            secure_fp,
            evaluable,
        ),
        "paired_warning_discrimination_count": paired,
        "paired_warning_discrimination_rate": _ratio(
            paired,
            evaluable,
        ),
        "category_breakdown": _category_breakdown(succeeded),
    }


def _category_breakdown(
    rows: list[dict[str, Any]],
) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[_category(set(row["cwe_ids"]))].append(row)
    result = {}
    for category, category_rows in sorted(grouped.items()):
        count = len(category_rows)
        result[category] = {
            "case_count": count,
            "vulnerable_warning_recall": _ratio(
                sum(row["vulnerable_warned"] for row in category_rows),
                count,
            ),
            "secure_warning_false_positive_rate": _ratio(
                sum(
                    row["secure_warning_false_positive"]
                    for row in category_rows
                ),
                count,
            ),
            "paired_warning_discrimination_rate": _ratio(
                sum(
                    row["paired_warning_discriminated"]
                    for row in category_rows
                ),
                count,
            ),
        }
    return result


def _evaluate_thresholds(
    metrics: Mapping[str, Any],
    thresholds: SusVibesCandidateReviewThresholds,
) -> dict[str, dict[str, Any]]:
    checks = {
        "minimum_vulnerable_warning_recall": (
            "vulnerable_warning_recall",
            thresholds.minimum_vulnerable_warning_recall,
            "minimum",
        ),
        "maximum_secure_warning_false_positive_rate": (
            "secure_warning_false_positive_rate",
            thresholds.maximum_secure_warning_false_positive_rate,
            "maximum",
        ),
        "minimum_paired_warning_discrimination_rate": (
            "paired_warning_discrimination_rate",
            thresholds.minimum_paired_warning_discrimination_rate,
            "minimum",
        ),
    }
    result = {}
    for name, (metric, expected, direction) in checks.items():
        actual = float(metrics[metric])
        passed = (
            actual >= expected
            if direction == "minimum"
            else actual <= expected
        )
        result[name] = {
            "metric": metric,
            "actual": actual,
            "threshold": expected,
            "direction": direction,
            "passed": passed,
        }
    return result


def _coerce_thresholds(
    thresholds: (
        SusVibesCandidateReviewThresholds
        | Mapping[str, float]
        | None
    ),
) -> SusVibesCandidateReviewThresholds:
    if thresholds is None:
        return DEFAULT_CANDIDATE_REVIEW_THRESHOLDS
    if isinstance(thresholds, SusVibesCandidateReviewThresholds):
        return thresholds
    if isinstance(thresholds, Mapping):
        merged = DEFAULT_CANDIDATE_REVIEW_THRESHOLDS.to_dict()
        unknown = sorted(set(thresholds) - set(merged))
        if unknown:
            raise ValueError(
                "unknown candidate-review threshold fields: "
                + ", ".join(unknown)
            )
        merged.update({
            key: float(value)
            for key, value in thresholds.items()
        })
        return SusVibesCandidateReviewThresholds(**merged)
    raise ValueError("invalid candidate-review thresholds")


def _failed_case(
    case: Mapping[str, Any],
    errors: list[str],
) -> dict[str, Any]:
    empty = {
        "analysis_succeeded": False,
        "status": "analysis_error",
        "actionable_count": 0,
        "introduced_actionable_count": 0,
        "residual_actionable_count": 0,
        "findings": [],
        "review_digest": "",
    }
    return {
        "id": str(case["instance_id"]),
        "project": str(case["project"]),
        "commit": str(case["base_commit"]),
        "cwe_ids": list(case["cwe_ids"]),
        "cve_id": str(case.get("cve_id") or ""),
        "analysis_succeeded": False,
        "errors": errors,
        "vulnerable_candidate": dict(empty),
        "secure_candidate": dict(empty),
        "vulnerable_warned": False,
        "secure_warning_false_positive": False,
        "paired_warning_discriminated": False,
    }


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=_git_env(),
        timeout=30,
    )
    if completed.returncode:
        error = completed.stderr.decode(
            "utf-8",
            errors="replace",
        ).strip()
        raise ValueError(
            f"git {' '.join(arguments)} failed: "
            f"{error or completed.returncode}"
        )
    return completed.stdout.decode("utf-8", errors="replace")


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env.update({
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_EMAIL": "benchmark@example.invalid",
        "GIT_AUTHOR_NAME": "BELIEF benchmark",
        "GIT_COMMITTER_EMAIL": "benchmark@example.invalid",
        "GIT_COMMITTER_NAME": "BELIEF benchmark",
    })
    return env


def _safe_destination(root: Path, relative: str) -> Path:
    normalized = str(relative).replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
    ):
        raise ValueError(f"unsafe candidate path: {relative}")
    destination = root.joinpath(*path.parts)
    try:
        destination.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(
            f"candidate path escapes workspace: {relative}"
        ) from exc
    return destination


def _category(values: set[str]) -> str:
    families = (
        ({"CWE-22", "CWE-23", "CWE-29", "CWE-35", "CWE-36"}, "path_traversal"),
        ({"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"}, "access_control"),
        ({"CWE-77", "CWE-78", "CWE-88"}, "command_injection"),
        ({"CWE-79", "CWE-80", "CWE-83"}, "cross_site_scripting"),
        ({"CWE-89"}, "sql_injection"),
        ({"CWE-94", "CWE-95"}, "code_execution"),
        ({"CWE-918"}, "server_side_request_forgery"),
    )
    for family, name in families:
        if values & family:
            return name
    named = {
        "CWE-295": "tls_verification",
        "CWE-327": "broken_cryptography",
        "CWE-330": "insufficient_randomness",
        "CWE-347": "signature_verification",
    }
    for cwe, name in named.items():
        if cwe in values:
            return name
    return sorted(values)[0].lower().replace("-", "_") if values else "unknown"


def _ratio(numerator: int, denominator: int) -> float:
    return round(numerator / denominator, 6) if denominator else 0.0


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _reviewer_runtime_provenance(
    reviewer: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    identity = (
        f"{getattr(reviewer, '__module__', '')}."
        f"{getattr(reviewer, '__qualname__', type(reviewer).__name__)}"
    ).strip(".")
    provenance: dict[str, Any] = {
        "callable": identity,
    }
    if reviewer is not review_candidate_patch:
        return provenance

    package_root = Path(__file__).resolve().parents[1]
    source_files = sorted(
        path
        for path in package_root.rglob("*.py")
        if path.is_file()
    )
    digest = hashlib.sha256()
    for path in source_files:
        relative = path.relative_to(package_root).as_posix()
        normalized_source = path.read_bytes().replace(b"\r\n", b"\n")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(normalized_source).digest())
    provenance.update({
        "belief_python_file_count": len(source_files),
        "belief_python_source_sha256": digest.hexdigest(),
        "source_hash_normalization": "relative_path_nul_lf_normalized_bytes",
    })
    return provenance


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key not in {"duration_seconds", "deterministic_digest"}
    }
    metrics = semantic.get("metrics")
    if isinstance(metrics, Mapping):
        semantic["metrics"] = {
            key: value
            for key, value in metrics.items()
            if key not in {
                "duration_seconds",
                "deterministic_digest",
            }
        }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "DEFAULT_CANDIDATE_REVIEW_THRESHOLDS",
    "SUSVIBES_CANDIDATE_REVIEW_MODE",
    "SUSVIBES_CANDIDATE_REVIEW_SCHEMA_VERSION",
    "SusVibesCandidateReviewThresholds",
    "evaluate_susvibes_candidate_review",
    "write_susvibes_candidate_review_json",
]
