"""Offline paired-revision benchmark adapter for the public SusVibes corpus.

This benchmark does not execute third-party code or security tests. It reads
already-fetched Git objects, extracts only Python files touched by each
security fix, and compares BELIEF findings on the vulnerable parent revision
with the fixed revision. The metric is therefore static patch discrimination,
not SusVibes ``SecPass`` and not Aikido's private CVE pass@3 score.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
import warnings
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping


SUSVIBES_PAIRED_SCHEMA_VERSION = "belief.susvibes_paired_static.v1"
SUSVIBES_PAIRED_MODE = "susvibes_paired_static_v1"
SURFACED_VERDICTS = {
    "weak_signal",
    "needs_manual_validation",
    "reportable_candidate",
}

_REQUIRED_FIELDS = {
    "instance_id",
    "project",
    "base_commit",
    "security_patch",
    "cwe_ids",
    "language",
}
_PROJECT_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_HUNK_RE = re.compile(
    r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
    r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@(?P<header>.*)$"
)
_FUNCTION_HEADER_RE = re.compile(r"\b(?:async\s+)?def\s+([A-Za-z_][A-Za-z0-9_]*)")

_CWE_FAMILIES: tuple[frozenset[str], ...] = (
    frozenset({"CWE-22", "CWE-23", "CWE-29", "CWE-35", "CWE-36", "CWE-73"}),
    frozenset({"CWE-284", "CWE-285", "CWE-639", "CWE-862", "CWE-863"}),
    frozenset({"CWE-77", "CWE-78", "CWE-88"}),
    frozenset({"CWE-79", "CWE-80", "CWE-83"}),
    frozenset({"CWE-89"}),
    frozenset({"CWE-94", "CWE-95"}),
    frozenset({"CWE-502"}),
    frozenset({"CWE-918"}),
)


@dataclass(frozen=True)
class SusVibesThresholds:
    """Acceptance thresholds for static paired-revision discrimination."""

    minimum_vulnerable_surface_recall: float = 0.30
    maximum_fixed_surface_false_positive_rate: float = 0.25
    minimum_paired_discrimination_rate: float = 0.30

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            normalized = float(value)
            if not 0.0 <= normalized <= 1.0:
                raise ValueError(f"{name} must be between 0.0 and 1.0")
            object.__setattr__(self, name, normalized)

    def to_dict(self) -> dict[str, float]:
        return {key: float(value) for key, value in asdict(self).items()}


DEFAULT_SUSVIBES_THRESHOLDS = SusVibesThresholds()


@dataclass(frozen=True)
class DiffHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str = ""
    old_changed_lines: tuple[int, ...] = ()
    new_changed_lines: tuple[int, ...] = ()

    def range_for(self, state: str) -> tuple[int, int]:
        if state == "vulnerable":
            start = self.old_start
            changed_lines = self.old_changed_lines
        else:
            start = self.new_start
            changed_lines = self.new_changed_lines
        if changed_lines:
            return min(changed_lines), max(changed_lines)
        return start, start


@dataclass(frozen=True)
class DiffFile:
    old_path: str
    new_path: str
    hunks: tuple[DiffHunk, ...]

    def path_for(self, state: str) -> str:
        return self.old_path if state == "vulnerable" else self.new_path

    @property
    def output_path(self) -> str:
        return self.new_path or self.old_path


@dataclass(frozen=True)
class FocusContext:
    functions: frozenset[str]
    line_ranges: tuple[tuple[int, int], ...]
    qualified_functions: frozenset[tuple[str, str]] = frozenset()


class LocalGitCorpus:
    """Read-only access to commits in an explicitly prepared local cache."""

    def __init__(self, root: str | Path, *, command_timeout: float = 30.0) -> None:
        self.root = Path(root)
        self.command_timeout = float(command_timeout)

    def repository_path(self, project: str) -> Path:
        if not _PROJECT_RE.fullmatch(project):
            raise ValueError(f"invalid SusVibes project name: {project}")
        return self.root / project.replace("/", "__")

    def parent_commit(self, project: str, commit: str) -> str:
        resolved = self._run_git(
            project,
            "rev-parse",
            f"{commit}^",
            check=False,
        )
        if resolved.returncode == 0:
            parent = resolved.stdout.decode("utf-8", errors="replace").strip()
            if _COMMIT_RE.fullmatch(parent):
                return parent.lower()

        # A later depth-limited fetch may mark an already-hydrated commit as a
        # shallow boundary. The immutable commit object still records its
        # parent, so read that object directly rather than mutating the cache.
        raw_commit = self._run_git(
            project,
            "cat-file",
            "-p",
            commit,
            check=False,
        )
        if raw_commit.returncode == 0:
            for line in raw_commit.stdout.decode(
                "utf-8",
                errors="replace",
            ).splitlines():
                if not line.startswith("parent "):
                    continue
                parent = line.removeprefix("parent ").strip()
                if _COMMIT_RE.fullmatch(parent) and self.has_commit(project, parent):
                    return parent.lower()

        error = resolved.stderr.decode("utf-8", errors="replace").strip()
        raise ValueError(
            f"local git read failed for {project}: "
            f"{error or 'fixed commit parent is unavailable'}"
        )

    def source(self, project: str, revision: str, file_path: str) -> str | None:
        normalized = _safe_diff_path(file_path)
        if not normalized:
            return None
        completed = self._run_git(
            project,
            "show",
            f"{revision}:{normalized}",
            check=False,
        )
        if completed.returncode:
            return None
        return completed.stdout.decode("utf-8", errors="replace")

    def has_commit(self, project: str, commit: str) -> bool:
        completed = self._run_git(
            project,
            "cat-file",
            "-e",
            f"{commit}^{{commit}}",
            check=False,
        )
        return completed.returncode == 0

    def _run_git(
        self,
        project: str,
        *arguments: str,
        check: bool = True,
    ) -> subprocess.CompletedProcess[bytes]:
        repository = self.repository_path(project)
        if not (repository / ".git").is_dir():
            raise ValueError(f"repository is not prepared in local cache: {project}")
        env = dict(os.environ)
        env.update({
            "GIT_ALLOW_PROTOCOL": "",
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_TERMINAL_PROMPT": "0",
        })
        try:
            completed = subprocess.run(
                ["git", "-C", str(repository), *arguments],
                capture_output=True,
                check=False,
                timeout=self.command_timeout,
                env=env,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValueError(f"local git read failed for {project}: {exc}") from exc
        if check and completed.returncode:
            error = completed.stderr.decode("utf-8", errors="replace").strip()
            raise ValueError(
                f"local git read failed for {project}: {error or completed.returncode}"
            )
        return completed


def load_susvibes_cases(
    dataset: str | Path,
    *,
    only_cwes: Iterable[str] = (),
    max_cases: int = 0,
) -> list[dict[str, Any]]:
    """Load a deterministic subset of public SusVibes JSONL records."""

    path = Path(dataset)
    if not path.is_file():
        raise ValueError(f"SusVibes dataset does not exist: {path}")
    wanted = {_normalize_cwe(value) for value in only_cwes if str(value).strip()}
    cases: list[dict[str, Any]] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
        case = _validate_case(raw, path, line_number)
        if case["language"].lower() != "python":
            continue
        if wanted and not wanted.intersection(case["cwe_ids"]):
            continue
        cases.append(case)

    cases.sort(key=lambda item: item["instance_id"])
    if max_cases < 0:
        raise ValueError("max_cases must be non-negative")
    if max_cases:
        cases = cases[:max_cases]
    return cases


def parse_security_diff(patch: str) -> tuple[DiffFile, ...]:
    """Parse the small unified-diff subset used by SusVibes metadata."""

    files: list[DiffFile] = []
    old_path = ""
    new_path = ""
    hunks: list[DiffHunk] = []
    current_hunk: dict[str, Any] | None = None
    old_line = 0
    new_line = 0

    def flush_hunk() -> None:
        nonlocal current_hunk
        if current_hunk is None:
            return
        hunks.append(DiffHunk(
            old_start=current_hunk["old_start"],
            old_count=current_hunk["old_count"],
            new_start=current_hunk["new_start"],
            new_count=current_hunk["new_count"],
            header=current_hunk["header"],
            old_changed_lines=tuple(current_hunk["old_changed_lines"]),
            new_changed_lines=tuple(current_hunk["new_changed_lines"]),
        ))
        current_hunk = None

    def flush() -> None:
        nonlocal old_path, new_path, hunks
        flush_hunk()
        if old_path or new_path:
            files.append(DiffFile(
                old_path=_safe_diff_path(old_path),
                new_path=_safe_diff_path(new_path),
                hunks=tuple(hunks),
            ))
        old_path = ""
        new_path = ""
        hunks = []

    for raw_line in str(patch or "").splitlines():
        if raw_line.startswith("diff --git "):
            flush()
            parts = shlex.split(raw_line)
            if len(parts) != 4:
                raise ValueError(f"unsupported diff header: {raw_line}")
            old_path = _strip_diff_prefix(parts[2], "a/")
            new_path = _strip_diff_prefix(parts[3], "b/")
            continue
        match = _HUNK_RE.match(raw_line)
        if match:
            flush_hunk()
            old_line = int(match.group("old_start"))
            new_line = int(match.group("new_start"))
            current_hunk = {
                "old_start": old_line,
                "old_count": int(match.group("old_count") or 1),
                "new_start": new_line,
                "new_count": int(match.group("new_count") or 1),
                "header": match.group("header").strip(),
                "old_changed_lines": [],
                "new_changed_lines": [],
            }
            continue
        if current_hunk is None:
            continue
        if raw_line.startswith("\\"):
            continue
        if raw_line.startswith("-"):
            current_hunk["old_changed_lines"].append(old_line)
            old_line += 1
            continue
        if raw_line.startswith("+"):
            current_hunk["new_changed_lines"].append(new_line)
            new_line += 1
            continue
        old_line += 1
        new_line += 1
    flush()
    return tuple(
        item
        for item in files
        if item.output_path.endswith(".py") and item.hunks
    )


def evaluate_susvibes_paired_benchmark(
    dataset: str | Path,
    repository_cache: str | Path,
    pipeline: Callable[[Path], Any],
    *,
    only_cwes: Iterable[str] = (),
    max_cases: int = 0,
    thresholds: SusVibesThresholds | Mapping[str, float] | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Evaluate BELIEF on vulnerable/fixed changed-file pairs without execution."""

    dataset_path = Path(dataset)
    configured_thresholds = _coerce_thresholds(thresholds)
    corpus = LocalGitCorpus(repository_cache)
    started = clock()
    rows = []
    for case in load_susvibes_cases(
        dataset_path,
        only_cwes=only_cwes,
        max_cases=max_cases,
    ):
        rows.append(_evaluate_case(case, corpus, pipeline))

    metrics = _summarize(rows)
    threshold_evaluation = _evaluate_thresholds(metrics, configured_thresholds)
    passed = all(item["passed"] for item in threshold_evaluation.values())
    payload: dict[str, Any] = {
        "schema_version": SUSVIBES_PAIRED_SCHEMA_VERSION,
        "mode": SUSVIBES_PAIRED_MODE,
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
        "duration_seconds": round(max(0.0, float(clock() - started)), 6),
        "comparability": {
            "susvibes_secpass_equivalent": False,
            "aikido_pass_at_3_equivalent": False,
            "measurement": "oracle-localized static paired-revision discrimination",
        },
    }
    payload["deterministic_digest"] = _semantic_digest(payload)
    payload["metrics"]["deterministic_digest"] = payload["deterministic_digest"]
    payload["metrics"]["duration_seconds"] = payload["duration_seconds"]
    return payload


def write_susvibes_paired_benchmark_json(
    dataset: str | Path,
    repository_cache: str | Path,
    output: str | Path,
    pipeline: Callable[[Path], Any],
    *,
    only_cwes: Iterable[str] = (),
    max_cases: int = 0,
    thresholds: SusVibesThresholds | Mapping[str, float] | None = None,
) -> dict[str, Any]:
    payload = evaluate_susvibes_paired_benchmark(
        dataset,
        repository_cache,
        pipeline,
        only_cwes=only_cwes,
        max_cases=max_cases,
        thresholds=thresholds,
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
    pipeline: Callable[[Path], Any],
) -> dict[str, Any]:
    project = case["project"]
    commit = case["base_commit"]
    errors: list[str] = []
    if not corpus.has_commit(project, commit):
        errors.append("fixed_commit_missing_from_cache")
        return _failed_case(case, errors)
    try:
        parent = corpus.parent_commit(project, commit)
    except ValueError as exc:
        errors.append(str(exc))
        return _failed_case(case, errors)

    diff_files = parse_security_diff(case["security_patch"])
    if not diff_files:
        errors.append("no_changed_python_files")
        return _failed_case(case, errors)

    observations: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="belief-susvibes-") as temp:
        temp_root = Path(temp)
        for state, revision in (("vulnerable", parent), ("fixed", commit)):
            state_root = temp_root / state
            focus: dict[str, FocusContext] = {}
            for diff_file in diff_files:
                revision_path = diff_file.path_for(state)
                output_path = diff_file.output_path
                source = corpus.source(project, revision, revision_path)
                if source is None:
                    continue
                destination = _safe_destination(state_root, output_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source, encoding="utf-8")
                focus[output_path] = _focus_context(source, diff_file.hunks, state)
            if not focus:
                observations[state] = {
                    "analysis_succeeded": False,
                    "error": "no_revision_python_files",
                    "raw_detected": False,
                    "surfaced": False,
                    "findings": [],
                    "verdicts": [],
                }
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    result = pipeline(state_root)
                observations[state] = _observe_result(
                    result,
                    focus,
                    target_cwes=set(case["cwe_ids"]),
                )
            except Exception as exc:  # benchmark failures are evidence, not passes
                observations[state] = {
                    "analysis_succeeded": False,
                    "error": f"{type(exc).__name__}: {exc}",
                    "raw_detected": False,
                    "surfaced": False,
                    "findings": [],
                    "verdicts": [],
                }

    vulnerable = observations["vulnerable"]
    fixed = observations["fixed"]
    succeeded = bool(
        vulnerable["analysis_succeeded"] and fixed["analysis_succeeded"]
    )
    return {
        "id": case["instance_id"],
        "project": project,
        "commit": commit,
        "cwe_ids": list(case["cwe_ids"]),
        "cve_id": case.get("cve_id", ""),
        "analysis_succeeded": succeeded,
        "vulnerable": vulnerable,
        "fixed": fixed,
        "vulnerable_raw_detected": bool(vulnerable["raw_detected"]),
        "vulnerable_surfaced": bool(vulnerable["surfaced"]),
        "fixed_surface_false_positive": bool(fixed["surfaced"]),
        "paired_discriminated": bool(
            succeeded and vulnerable["surfaced"] and not fixed["surfaced"]
        ),
    }


def _observe_result(
    result: Any,
    focus: Mapping[str, FocusContext],
    *,
    target_cwes: set[str],
) -> dict[str, Any]:
    findings = list(getattr(result, "findings", ()) or ())
    cases = list(getattr(result, "audit_cases", ()) or ())
    family = _cwe_family(target_cwes)
    focused_findings = [
        finding
        for finding in findings
        if _finding_is_focused(finding, focus)
        and _normalize_cwe(getattr(finding, "cwe", "")) in family
    ]
    fingerprints = {
        str(getattr(finding, "fingerprint", "") or "")
        for finding in focused_findings
    }
    focused_cases = [
        case
        for case in cases
        if (
            str(getattr(case, "related_finding_fingerprint", "") or "")
            in fingerprints
        )
        and _normalize_cwe(getattr(case, "cwe", "")) in family
    ]
    verdict_set = {
        _case_verdict(case)
        for case in focused_cases
        if _case_verdict(case)
    }
    if any(_is_causal_patch_review_finding(finding) for finding in focused_findings):
        verdict_set.add("weak_signal")
    verdicts = sorted(verdict_set)
    finding_rows: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in sorted(
        focused_findings,
        key=lambda item: (
            _norm_path(getattr(item, "file", "")),
            getattr(item, "line", None) or 0,
            str(getattr(item, "rule_id", "") or ""),
        ),
    ):
        row = {
            "cwe": _normalize_cwe(getattr(finding, "cwe", "")),
            "file": _norm_path(getattr(finding, "file", "")),
            "line": getattr(finding, "line", None),
            "function": str(
                (getattr(finding, "metadata", {}) or {}).get("function_name") or ""
            ),
            "rule_id": str(getattr(finding, "rule_id", "") or ""),
        }
        key = (
            row["cwe"],
            row["file"],
            row["line"],
            row["function"],
            row["rule_id"],
        )
        finding_rows.setdefault(key, row)
    return {
        "analysis_succeeded": True,
        "error": "",
        "raw_detected": bool(focused_findings),
        "surfaced": bool(set(verdicts) & SURFACED_VERDICTS),
        "findings": list(finding_rows.values()),
        "verdicts": verdicts,
    }


def _finding_is_focused(finding: Any, focus: Mapping[str, FocusContext]) -> bool:
    file_path = _norm_path(getattr(finding, "file", ""))
    context = focus.get(file_path)
    if context is None:
        return False
    metadata = getattr(finding, "metadata", {}) or {}
    function = str(metadata.get("function_name") or "")
    class_name = str(metadata.get("class_name") or "")
    if function:
        if (class_name, function) in context.qualified_functions:
            return True
        if not context.qualified_functions and function in context.functions:
            return True
    line = getattr(finding, "line", None)
    if line is None:
        return False
    return any(start <= int(line) <= end for start, end in context.line_ranges)


def _focus_context(
    source: str,
    hunks: Iterable[DiffHunk],
    state: str,
) -> FocusContext:
    line_ranges = tuple(hunk.range_for(state) for hunk in hunks)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(source)
    except SyntaxError:
        return FocusContext(frozenset(), line_ranges)

    class_names: dict[int, str] = {}
    for class_node in ast.walk(tree):
        if not isinstance(class_node, ast.ClassDef):
            continue
        for child in class_node.body:
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                class_names[id(child)] = class_node.name
    spans = [
        (
            class_names.get(id(node), ""),
            node.name,
            int(getattr(node, "lineno", 0) or 0),
            int(getattr(node, "end_lineno", getattr(node, "lineno", 0)) or 0),
        )
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    functions: set[str] = set()
    qualified_functions: set[tuple[str, str]] = set()
    for hunk, (start, end) in zip(hunks, line_ranges, strict=True):
        overlapping = {
            (class_name, name)
            for class_name, name, function_start, function_end in spans
            if function_start <= end and function_end >= start
        }
        qualified_functions.update(overlapping)
        functions.update(name for _, name in overlapping)
        if not overlapping:
            header_match = _FUNCTION_HEADER_RE.search(hunk.header)
            if header_match:
                functions.add(header_match.group(1))
        state_has_changed_lines = (
            bool(hunk.old_changed_lines)
            if state == "vulnerable"
            else bool(hunk.new_changed_lines)
        )
        if not overlapping or not state_has_changed_lines:
            nearest = sorted(
                (
                    min(abs(function_start - end), abs(start - function_end)),
                    class_name,
                    name,
                )
                for class_name, name, function_start, function_end in spans
            )
            nearby = {
                (class_name, name)
                for distance, class_name, name in nearest
                if distance <= 8
            }
            qualified_functions.update(nearby)
            functions.update(name for _, name in nearby)
    return FocusContext(
        frozenset(functions),
        line_ranges,
        frozenset(qualified_functions),
    )


def _summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    succeeded = [row for row in rows if row["analysis_succeeded"]]
    count = len(rows)
    evaluable = len(succeeded)
    vulnerable_raw = sum(row["vulnerable_raw_detected"] for row in succeeded)
    vulnerable_surface = sum(row["vulnerable_surfaced"] for row in succeeded)
    fixed_fp = sum(row["fixed_surface_false_positive"] for row in succeeded)
    paired = sum(row["paired_discriminated"] for row in succeeded)
    return {
        "case_count": count,
        "evaluable_case_count": evaluable,
        "analysis_error_count": count - evaluable,
        "vulnerable_raw_detection_count": vulnerable_raw,
        "vulnerable_raw_recall": _ratio(vulnerable_raw, evaluable),
        "vulnerable_surface_count": vulnerable_surface,
        "vulnerable_surface_recall": _ratio(vulnerable_surface, evaluable),
        "fixed_surface_false_positive_count": fixed_fp,
        "fixed_surface_false_positive_rate": _ratio(fixed_fp, evaluable),
        "paired_discrimination_count": paired,
        "paired_discrimination_rate": _ratio(paired, evaluable),
        "category_breakdown": _category_breakdown(succeeded),
    }


def _category_breakdown(rows: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[_category_for(set(row["cwe_ids"]))].append(row)
    result = {}
    for category, category_rows in sorted(grouped.items()):
        count = len(category_rows)
        result[category] = {
            "case_count": count,
            "vulnerable_surface_recall": _ratio(
                sum(row["vulnerable_surfaced"] for row in category_rows),
                count,
            ),
            "fixed_surface_false_positive_rate": _ratio(
                sum(row["fixed_surface_false_positive"] for row in category_rows),
                count,
            ),
            "paired_discrimination_rate": _ratio(
                sum(row["paired_discriminated"] for row in category_rows),
                count,
            ),
        }
    return result


def _evaluate_thresholds(
    metrics: Mapping[str, Any],
    thresholds: SusVibesThresholds,
) -> dict[str, dict[str, Any]]:
    checks = {
        "minimum_vulnerable_surface_recall": (
            "vulnerable_surface_recall",
            thresholds.minimum_vulnerable_surface_recall,
            "minimum",
        ),
        "maximum_fixed_surface_false_positive_rate": (
            "fixed_surface_false_positive_rate",
            thresholds.maximum_fixed_surface_false_positive_rate,
            "maximum",
        ),
        "minimum_paired_discrimination_rate": (
            "paired_discrimination_rate",
            thresholds.minimum_paired_discrimination_rate,
            "minimum",
        ),
    }
    result = {}
    for threshold_name, (metric_name, expected, direction) in checks.items():
        actual = float(metrics[metric_name])
        passed = actual >= expected if direction == "minimum" else actual <= expected
        result[threshold_name] = {
            "metric": metric_name,
            "actual": actual,
            "threshold": expected,
            "direction": direction,
            "passed": passed,
        }
    return result


def _coerce_thresholds(
    thresholds: SusVibesThresholds | Mapping[str, float] | None,
) -> SusVibesThresholds:
    if thresholds is None:
        return DEFAULT_SUSVIBES_THRESHOLDS
    if isinstance(thresholds, SusVibesThresholds):
        return thresholds
    if isinstance(thresholds, Mapping):
        merged = DEFAULT_SUSVIBES_THRESHOLDS.to_dict()
        unknown = sorted(set(thresholds) - set(merged))
        if unknown:
            raise ValueError(
                f"unknown SusVibes threshold fields: {', '.join(unknown)}"
            )
        merged.update({key: float(value) for key, value in thresholds.items()})
        return SusVibesThresholds(**merged)
    raise ValueError("invalid SusVibes thresholds")


def _validate_case(
    raw: Any,
    path: Path,
    line_number: int,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ValueError(f"{path}:{line_number}: case must be an object")
    missing = sorted(_REQUIRED_FIELDS - set(raw))
    if missing:
        raise ValueError(
            f"{path}:{line_number}: missing fields: {', '.join(missing)}"
        )
    project = str(raw["project"])
    commit = str(raw["base_commit"])
    if not _PROJECT_RE.fullmatch(project):
        raise ValueError(f"{path}:{line_number}: invalid project: {project}")
    if not _COMMIT_RE.fullmatch(commit):
        raise ValueError(f"{path}:{line_number}: invalid base_commit")
    cwe_ids = tuple(sorted({
        _normalize_cwe(value)
        for value in raw.get("cwe_ids", [])
        if str(value).strip()
    }))
    if not cwe_ids:
        raise ValueError(f"{path}:{line_number}: cwe_ids must not be empty")
    return {
        **raw,
        "instance_id": str(raw["instance_id"]),
        "project": project,
        "base_commit": commit.lower(),
        "security_patch": str(raw["security_patch"]),
        "cwe_ids": cwe_ids,
        "language": str(raw["language"]),
        "cve_id": str(raw.get("cve_id") or ""),
    }


def _failed_case(case: dict[str, Any], errors: list[str]) -> dict[str, Any]:
    empty = {
        "analysis_succeeded": False,
        "error": "; ".join(errors),
        "raw_detected": False,
        "surfaced": False,
        "findings": [],
        "verdicts": [],
    }
    return {
        "id": case["instance_id"],
        "project": case["project"],
        "commit": case["base_commit"],
        "cwe_ids": list(case["cwe_ids"]),
        "cve_id": case.get("cve_id", ""),
        "analysis_succeeded": False,
        "vulnerable": dict(empty),
        "fixed": dict(empty),
        "vulnerable_raw_detected": False,
        "vulnerable_surfaced": False,
        "fixed_surface_false_positive": False,
        "paired_discriminated": False,
    }


def _case_verdict(case: Any) -> str:
    metadata = getattr(case, "metadata", {}) or {}
    reportability = metadata.get("reportability")
    if isinstance(reportability, dict):
        return str(reportability.get("verdict") or "")
    return str(getattr(case, "status", "") or "")


def _is_causal_patch_review_finding(finding: Any) -> bool:
    metadata = getattr(finding, "metadata", {}) or {}
    if metadata.get("analysis_profile") != "patch_review":
        return False
    dataflow = metadata.get("dataflow")
    return bool(
        isinstance(dataflow, Mapping)
        and dataflow.get("source")
        and dataflow.get("sink")
        and dataflow.get("missing_guarantees")
    )


def _cwe_family(values: set[str]) -> set[str]:
    normalized = {_normalize_cwe(value) for value in values}
    family = set(normalized)
    for candidate in _CWE_FAMILIES:
        if normalized & candidate:
            family.update(candidate)
    return family


def _category_for(values: set[str]) -> str:
    family = _cwe_family(values)
    if "CWE-22" in family:
        return "path_traversal"
    if "CWE-863" in family:
        return "access_control"
    if "CWE-78" in family:
        return "command_injection"
    if "CWE-79" in family:
        return "cross_site_scripting"
    if "CWE-89" in family:
        return "sql_injection"
    if "CWE-94" in family:
        return "code_execution"
    if "CWE-502" in family:
        return "unsafe_deserialization"
    if "CWE-918" in family:
        return "server_side_request_forgery"
    named_categories = {
        "CWE-295": "tls_verification",
        "CWE-327": "broken_cryptography",
        "CWE-330": "insufficient_randomness",
        "CWE-347": "signature_verification",
        "CWE-489": "debug_mode",
        "CWE-798": "hardcoded_credentials",
        "CWE-942": "cors_policy",
    }
    for cwe, category in named_categories.items():
        if cwe in family:
            return category
    return sorted(values)[0].lower().replace("-", "_") if values else "unknown"


def _normalize_cwe(value: Any) -> str:
    text = str(value or "").strip().upper().replace("_", "-")
    if text.startswith("CWE") and not text.startswith("CWE-"):
        text = "CWE-" + text[3:].lstrip("-")
    return text


def _strip_diff_prefix(value: str, prefix: str) -> str:
    if value == "/dev/null":
        return ""
    return value[len(prefix):] if value.startswith(prefix) else value


def _safe_diff_path(value: str) -> str:
    normalized = str(value or "").replace("\\", "/").strip("/")
    if not normalized:
        return ""
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe path in SusVibes diff: {value}")
    return path.as_posix()


def _safe_destination(root: Path, relative: str) -> Path:
    destination = (root / Path(*PurePosixPath(_safe_diff_path(relative)).parts)).resolve()
    resolved_root = root.resolve()
    try:
        destination.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"unsafe materialization path: {relative}") from exc
    return destination


def _norm_path(value: Any) -> str:
    return str(value or "").replace("\\", "/").strip("/")


def _ratio(numerator: int, denominator: int) -> float:
    return round(float(numerator) / denominator, 6) if denominator else 0.0


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
            if key not in {"duration_seconds", "deterministic_digest"}
        }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "DEFAULT_SUSVIBES_THRESHOLDS",
    "SUSVIBES_PAIRED_MODE",
    "SUSVIBES_PAIRED_SCHEMA_VERSION",
    "SURFACED_VERDICTS",
    "DiffFile",
    "DiffHunk",
    "FocusContext",
    "LocalGitCorpus",
    "SusVibesThresholds",
    "evaluate_susvibes_paired_benchmark",
    "load_susvibes_cases",
    "parse_security_diff",
    "write_susvibes_paired_benchmark_json",
]
