"""Oracle-free security review for a candidate Git worktree patch.

The reviewer compares BELIEF observations in the clean ``HEAD`` revision with
the current worktree, restricted to Python functions and lines touched by the
candidate diff. It never reads benchmark labels, reference fixes, hidden tests,
Git history beyond ``HEAD``, or network resources.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import warnings
from pathlib import Path, PurePosixPath
from typing import Any, Callable, Iterable, Mapping

from .benchmark.susvibes import (
    SURFACED_VERDICTS,
    DiffFile,
    FocusContext,
    build_focus_context,
    finding_is_focused,
    parse_security_diff,
)
from .static_analysis_pipeline import (
    StaticAnalysisOptions,
    analyze_static_target,
)


CANDIDATE_PATCH_REVIEW_SCHEMA_VERSION = "belief.candidate_patch_review.v1"

_GIT_ENV_OVERRIDES = {
    "GIT_ALLOW_PROTOCOL": "",
    "GIT_NO_LAZY_FETCH": "1",
    "GIT_OPTIONAL_LOCKS": "0",
    "GIT_TERMINAL_PROMPT": "0",
}


def collect_worktree_patch(target: str | Path) -> str:
    """Return tracked and untracked worktree changes without invoking diff helpers."""

    root = _repository_root(target)
    tracked = _git(
        root,
        "diff",
        "--no-ext-diff",
        "--no-textconv",
        "--binary",
        "--full-index",
        "HEAD",
        "--",
    )
    untracked_raw = _git(
        root,
        "ls-files",
        "--others",
        "--exclude-standard",
        "-z",
        decode=False,
    )
    chunks = [tracked]
    for raw_path in bytes(untracked_raw).split(b"\0"):
        if not raw_path:
            continue
        relative = os.fsdecode(raw_path)
        normalized = _safe_relative_path(relative)
        if not normalized.endswith(".py"):
            continue
        result = _git_completed(
            root,
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-textconv",
            "--binary",
            "--",
            "/dev/null",
            normalized,
        )
        if result.returncode not in {0, 1}:
            _raise_git_error(result, "diff untracked file")
        chunks.append(result.stdout.decode("utf-8", errors="replace"))
    return "".join(chunks)


def review_candidate_patch(
    target: str | Path,
    patch: str | None = None,
    *,
    include_tests: bool = False,
    max_files: int = 100,
    pipeline: Callable[[Path], Any] | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Review the candidate patch in *target* against its clean ``HEAD`` state."""

    root = _repository_root(target)
    if max_files <= 0:
        raise ValueError("max_files must be positive")
    patch_text = collect_worktree_patch(root) if patch is None else str(patch)
    started = clock()
    parsed_files = parse_security_diff(patch_text)
    excluded_files = sorted({
        item.output_path
        for item in parsed_files
        if not include_tests and _is_test_path(item.output_path)
    })
    diff_files = tuple(
        item
        for item in parsed_files
        if include_tests or not _is_test_path(item.output_path)
    )
    if len(diff_files) > max_files:
        raise ValueError(
            f"candidate patch changes {len(diff_files)} Python files; "
            f"max_files is {max_files}"
        )

    observations: dict[str, dict[str, Any]] = {}
    with tempfile.TemporaryDirectory(prefix="belief-candidate-review-") as temp:
        temp_root = Path(temp)
        for state in ("vulnerable", "fixed"):
            state_root = temp_root / state
            focus: dict[str, FocusContext] = {}
            materialization_errors: list[str] = []
            for diff_file in diff_files:
                source = _source_for_state(root, diff_file, state)
                if source is None:
                    continue
                output_path = diff_file.output_path
                destination = _safe_destination(state_root, output_path)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text(source, encoding="utf-8")
                focus[output_path] = build_focus_context(
                    source,
                    diff_file.hunks,
                    state,
                )
            if not focus:
                observations[state] = {
                    "analysis_succeeded": True,
                    "errors": materialization_errors,
                    "diagnostics": [],
                    "findings": [],
                }
                continue
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", SyntaxWarning)
                    result = (pipeline or _default_pipeline)(state_root)
                observations[state] = {
                    "analysis_succeeded": True,
                    "errors": materialization_errors,
                    "diagnostics": [
                        diagnostic.to_dict()
                        for diagnostic in (
                            getattr(result, "diagnostics", ()) or ()
                        )
                    ],
                    "findings": _focused_findings(result, focus),
                }
            except Exception as exc:
                observations[state] = {
                    "analysis_succeeded": False,
                    "errors": [
                        *materialization_errors,
                        f"{type(exc).__name__}: {exc}",
                    ],
                    "diagnostics": [],
                    "findings": [],
                }

    baseline_rows = observations["vulnerable"]["findings"]
    candidate_rows = observations["fixed"]["findings"]
    baseline_keys = {_finding_identity(item) for item in baseline_rows}
    candidate_keys = {_finding_identity(item) for item in candidate_rows}
    introduced = [
        {**item, "classification": "introduced"}
        for item in candidate_rows
        if _finding_identity(item) not in baseline_keys
    ]
    residual = [
        {**item, "classification": "residual"}
        for item in candidate_rows
        if _finding_identity(item) in baseline_keys
    ]
    resolved = [
        {**item, "classification": "resolved"}
        for item in baseline_rows
        if _finding_identity(item) not in candidate_keys
    ]
    actionable = [
        item
        for item in [*introduced, *residual]
        if item["actionable"]
    ]
    feedback = _render_feedback(actionable)
    duration = round(max(0.0, float(clock() - started)), 6)
    payload: dict[str, Any] = {
        "schema_version": CANDIDATE_PATCH_REVIEW_SCHEMA_VERSION,
        "mode": "oracle_free_candidate_patch_review",
        "target": str(root),
        "patch_sha256": hashlib.sha256(
            patch_text.encode("utf-8")
        ).hexdigest(),
        "changed_python_files": [
            item.output_path
            for item in diff_files
        ],
        "excluded_test_files": excluded_files,
        "analysis": {
            "baseline": observations["vulnerable"],
            "candidate": observations["fixed"],
        },
        "introduced_findings": introduced,
        "residual_findings": residual,
        "resolved_findings": resolved,
        "counts": {
            "changed_python_files": len(diff_files),
            "excluded_test_files": len(excluded_files),
            "baseline_findings": len(baseline_rows),
            "candidate_findings": len(candidate_rows),
            "introduced_findings": len(introduced),
            "introduced_actionable": sum(
                bool(item["actionable"]) for item in introduced
            ),
            "residual_findings": len(residual),
            "residual_actionable": sum(
                bool(item["actionable"]) for item in residual
            ),
            "resolved_findings": len(resolved),
            "candidate_actionable": len(actionable),
        },
        "status": "review_required" if actionable else "passed",
        "feedback": feedback,
        "comparability": {
            "susvibes_secpass_equivalent": False,
            "security_tests_executed": False,
            "benchmark_oracle_used": False,
            "measurement": (
                "candidate diff static review against clean HEAD"
            ),
        },
        "duration_seconds": duration,
    }
    payload["deterministic_digest"] = _semantic_digest(payload)
    return payload


def write_candidate_patch_review_json(
    target: str | Path,
    output: str | Path,
    patch: str | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Review a candidate patch and write the complete deterministic report."""

    payload = review_candidate_patch(target, patch, **kwargs)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def _default_pipeline(target: Path) -> Any:
    options = StaticAnalysisOptions(
        max_files=100,
        selected_categories=frozenset({"security", "taint"}),
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        include_audit_cases=True,
        audit_mode=True,
        reportability=True,
        dedup_audit_cases=True,
        security_analysis_profile="patch_review",
    )
    return analyze_static_target(target, options)


def _focused_findings(
    result: Any,
    focus: Mapping[str, FocusContext],
) -> list[dict[str, Any]]:
    findings = [
        finding
        for finding in (getattr(result, "findings", ()) or ())
        if finding_is_focused(finding, focus)
        and str(getattr(finding, "cwe", "") or "").strip()
    ]
    cases_by_fingerprint: dict[str, set[str]] = {}
    for case in (getattr(result, "audit_cases", ()) or ()):
        fingerprint = str(
            getattr(case, "related_finding_fingerprint", "") or ""
        )
        verdict = _case_verdict(case)
        if fingerprint and verdict:
            cases_by_fingerprint.setdefault(fingerprint, set()).add(verdict)

    rows: dict[tuple[Any, ...], dict[str, Any]] = {}
    for finding in findings:
        metadata = getattr(finding, "metadata", {}) or {}
        dataflow = metadata.get("dataflow")
        if not isinstance(dataflow, Mapping):
            dataflow = {}
        verdicts = sorted(
            cases_by_fingerprint.get(
                str(getattr(finding, "fingerprint", "") or ""),
                set(),
            )
        )
        causal = bool(
            metadata.get("analysis_profile") == "patch_review"
            and dataflow.get("source")
            and dataflow.get("sink")
            and dataflow.get("missing_guarantees")
        )
        if causal and "weak_signal" not in verdicts:
            verdicts.append("weak_signal")
            verdicts.sort()
        row = {
            "cwe": str(getattr(finding, "cwe", "") or ""),
            "rule_id": str(getattr(finding, "rule_id", "") or ""),
            "title": str(getattr(finding, "title", "") or ""),
            "description": str(
                getattr(finding, "description", "") or ""
            ),
            "severity": str(getattr(finding, "severity", "") or ""),
            "confidence": round(
                float(getattr(finding, "confidence", 0.0) or 0.0),
                6,
            ),
            "file": _normalize_path(getattr(finding, "file", "")),
            "line": getattr(finding, "line", None),
            "end_line": getattr(finding, "end_line", None),
            "function": str(metadata.get("function_name") or ""),
            "class": str(metadata.get("class_name") or ""),
            "evidence": str(getattr(finding, "evidence", "") or ""),
            "dataflow": {
                key: dataflow[key]
                for key in (
                    "source",
                    "sink",
                    "missing_guarantees",
                    "sanitizers",
                    "guarantees",
                )
                if key in dataflow
            },
            "verdicts": verdicts,
            "actionable": bool(
                causal or set(verdicts).intersection(SURFACED_VERDICTS)
            ),
        }
        key = (
            row["cwe"],
            row["rule_id"],
            row["file"],
            row["line"],
            row["function"],
            row["class"],
        )
        rows.setdefault(key, row)
    return sorted(
        rows.values(),
        key=lambda item: (
            item["file"],
            item["line"] or 0,
            item["cwe"],
            item["rule_id"],
        ),
    )


def _finding_identity(row: Mapping[str, Any]) -> tuple[str, ...]:
    dataflow = row.get("dataflow")
    sink = ""
    if isinstance(dataflow, Mapping):
        sink = str(dataflow.get("sink") or "")
    return (
        str(row.get("cwe") or ""),
        str(row.get("rule_id") or ""),
        str(row.get("file") or ""),
        str(row.get("class") or ""),
        str(row.get("function") or ""),
        sink,
    )


def _render_feedback(findings: Iterable[Mapping[str, Any]]) -> str:
    rows = list(findings)
    if not rows:
        return (
            "BELIEF found no actionable security-boundary finding in the "
            "candidate Python diff. This is static evidence only; rerun the "
            "project's functional and security tests before finishing."
        )
    lines = [
        (
            "BELIEF found actionable security-boundary risks in the candidate "
            "diff. Re-review and repair them without looking up an upstream "
            "fix, then rerun the relevant tests:"
        )
    ]
    for row in rows:
        dataflow = row.get("dataflow")
        missing = []
        if isinstance(dataflow, Mapping):
            raw_missing = dataflow.get("missing_guarantees", [])
            if isinstance(raw_missing, (list, tuple, set)):
                missing = [str(value) for value in raw_missing]
            elif raw_missing:
                missing = [str(raw_missing)]
        location = str(row.get("file") or "")
        if row.get("line") is not None:
            location += f":{row['line']}"
        scope = str(row.get("function") or "")
        detail = "; ".join(missing) or str(
            row.get("description") or row.get("title") or ""
        )
        classification = str(row.get("classification") or "candidate")
        lines.append(
            f"- [{row.get('cwe')}] {location}"
            f"{f' ({scope})' if scope else ''}: "
            f"{classification}; missing security guarantee: {detail}"
        )
    lines.append(
        "Keep the implementation minimal and preserve the requested "
        "functional behavior."
    )
    return "\n".join(lines)


def _source_for_state(
    root: Path,
    diff_file: DiffFile,
    state: str,
) -> str | None:
    if state == "vulnerable":
        relative = diff_file.old_path
        if not relative:
            return None
        result = _git_completed(root, "cat-file", "blob", f"HEAD:{relative}")
        if result.returncode:
            return None
        return result.stdout.decode("utf-8", errors="strict")

    relative = diff_file.new_path
    if not relative:
        return None
    candidate = root / Path(*PurePosixPath(relative).parts)
    if candidate.is_symlink():
        raise ValueError(f"candidate Python file must not be a symlink: {relative}")
    if not candidate.exists():
        return None
    resolved = candidate.resolve(strict=True)
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(
            f"candidate Python file escapes repository root: {relative}"
        ) from exc
    if not resolved.is_file():
        return None
    return resolved.read_text(encoding="utf-8")


def _is_test_path(value: str) -> bool:
    path = PurePosixPath(value)
    parts = {part.lower() for part in path.parts[:-1]}
    name = path.name.lower()
    return bool(
        any(part.startswith("test") for part in parts)
        or name.startswith("test_")
        or name.endswith("_test.py")
    )


def _repository_root(target: str | Path) -> Path:
    root = Path(target).resolve()
    if not root.is_dir():
        raise ValueError(f"candidate target is not a directory: {root}")
    result = _git_completed(root, "rev-parse", "--show-toplevel")
    if result.returncode:
        _raise_git_error(result, "resolve repository root")
    resolved = Path(
        result.stdout.decode("utf-8", errors="strict").strip()
    ).resolve()
    if resolved != root:
        raise ValueError(
            "candidate target must be the Git repository root: "
            f"expected {resolved}, got {root}"
        )
    return root


def _safe_relative_path(value: str) -> str:
    normalized = str(value).replace("\\", "/")
    path = PurePosixPath(normalized)
    if (
        not normalized
        or path.is_absolute()
        or ".." in path.parts
        or any(part in {"", "."} for part in path.parts)
    ):
        raise ValueError(f"unsafe Git path: {value}")
    return path.as_posix()


def _safe_destination(root: Path, relative: str) -> Path:
    normalized = _safe_relative_path(relative)
    destination = root.joinpath(*PurePosixPath(normalized).parts)
    resolved_root = root.resolve()
    resolved_destination = destination.resolve()
    try:
        resolved_destination.relative_to(resolved_root)
    except ValueError as exc:
        raise ValueError(f"unsafe materialization path: {relative}") from exc
    return destination


def _normalize_path(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def _case_verdict(case: Any) -> str:
    metadata = getattr(case, "metadata", {}) or {}
    reportability = metadata.get("reportability")
    if isinstance(reportability, Mapping):
        return str(reportability.get("verdict") or "")
    return str(getattr(case, "status", "") or "")


def _git(
    root: Path,
    *arguments: str,
    decode: bool = True,
) -> str | bytes:
    result = _git_completed(root, *arguments)
    if result.returncode:
        _raise_git_error(result, " ".join(arguments[:2]))
    if not decode:
        return result.stdout
    return result.stdout.decode("utf-8", errors="replace")


def _git_completed(
    root: Path,
    *arguments: str,
) -> subprocess.CompletedProcess[bytes]:
    env = dict(os.environ)
    env.update(_GIT_ENV_OVERRIDES)
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=30,
    )


def _raise_git_error(
    result: subprocess.CompletedProcess[bytes],
    operation: str,
) -> None:
    error = result.stderr.decode("utf-8", errors="replace").strip()
    raise ValueError(f"Git failed to {operation}: {error or result.returncode}")


def _semantic_digest(payload: Mapping[str, Any]) -> str:
    semantic = {
        key: value
        for key, value in payload.items()
        if key not in {"target", "duration_seconds", "deterministic_digest"}
    }
    encoded = json.dumps(
        semantic,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


__all__ = [
    "CANDIDATE_PATCH_REVIEW_SCHEMA_VERSION",
    "collect_worktree_patch",
    "review_candidate_patch",
    "write_candidate_patch_review_json",
]
