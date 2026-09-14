"""Deterministic negative-control gate for BELIEF native security detectors."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from ..bridges.download_destination_bridge import scan_source as scan_download_destination
from ..bridges.orm_identifier_bridge import scan_source as scan_orm_identifier
from ..bridges.path_traversal_bridge import scan_source as scan_path_boundary


NATIVE_NEGATIVE_CONTROL_SCHEMA_VERSION = "belief.native_negative_control.v1"
DEFAULT_EXCLUDED_DIRECTORIES = frozenset(
    {"idlelib", "lib2to3", "site-packages", "test", "tests"}
)
DEFAULT_DETECTORS: Mapping[str, Callable[[str, str], list[dict[str, Any]]]] = {
    "download_destination": scan_download_destination,
    "orm_identifier": scan_orm_identifier,
    "path_boundary": scan_path_boundary,
}


@dataclass(frozen=True)
class NegativeControlLimits:
    max_files: int = 2_000
    max_file_bytes: int = 1_048_576
    max_total_bytes: int = 67_108_864
    high_confidence: float = 0.8
    max_high_confidence_file_rate: float = 0.005
    max_samples: int = 20

    def __post_init__(self) -> None:
        if self.max_files < 1 or self.max_file_bytes < 1 or self.max_total_bytes < 1:
            raise ValueError("negative-control byte and file limits must be positive")
        if not 0.0 <= self.high_confidence <= 1.0:
            raise ValueError("high_confidence must be between 0 and 1")
        if not 0.0 <= self.max_high_confidence_file_rate <= 1.0:
            raise ValueError("max_high_confidence_file_rate must be between 0 and 1")
        if self.max_samples < 0:
            raise ValueError("max_samples must be non-negative")


def evaluate_native_negative_control(
    root: str | Path,
    *,
    limits: NegativeControlLimits | None = None,
    detectors: Mapping[str, Callable[[str, str], list[dict[str, Any]]]] | None = None,
    excluded_directories: Sequence[str] = tuple(DEFAULT_EXCLUDED_DIRECTORIES),
) -> dict[str, Any]:
    """Scan a presumed-safe Python tree and apply a precision/crash budget.

    This is a regression signal, not a claim that the corpus is vulnerability-free.
    Findings remain candidates and the returned samples are intentionally bounded.
    """

    active_limits = limits or NegativeControlLimits()
    active_detectors = dict(detectors or DEFAULT_DETECTORS)
    corpus_root = Path(root).resolve(strict=True)
    if not corpus_root.is_dir():
        raise ValueError("negative-control root must be a directory")
    if not active_detectors:
        raise ValueError("at least one detector is required")

    excluded = frozenset(str(value) for value in excluded_directories if str(value))
    files = tuple(
        path
        for path in sorted(corpus_root.rglob("*.py"), key=lambda item: item.as_posix())
        if not excluded.intersection(path.relative_to(corpus_root).parts)
    )
    if not files:
        raise ValueError("negative-control corpus contains no Python files")
    if len(files) > active_limits.max_files:
        raise ValueError("negative-control corpus exceeds max_files")

    detector_rows: dict[str, dict[str, Any]] = {
        name: {
            "crash_count": 0,
            "finding_count": 0,
            "high_confidence_finding_count": 0,
            "high_confidence_files": set(),
            "samples": [],
        }
        for name in sorted(active_detectors)
    }
    total_bytes = 0
    corpus_errors: list[dict[str, str]] = []

    for path in files:
        logical_path = path.relative_to(corpus_root).as_posix()
        try:
            raw = path.read_bytes()
        except OSError as exc:
            corpus_errors.append({"file": logical_path, "error": type(exc).__name__})
            continue
        if len(raw) > active_limits.max_file_bytes:
            corpus_errors.append({"file": logical_path, "error": "file_too_large"})
            continue
        total_bytes += len(raw)
        if total_bytes > active_limits.max_total_bytes:
            raise ValueError("negative-control corpus exceeds max_total_bytes")
        try:
            source = raw.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            corpus_errors.append({"file": logical_path, "error": type(exc).__name__})
            continue

        for detector_name in sorted(active_detectors):
            row = detector_rows[detector_name]
            scanner = active_detectors[detector_name]
            try:
                findings = scanner(source, logical_path)
                if not isinstance(findings, list) or any(
                    not isinstance(item, dict) for item in findings
                ):
                    raise TypeError("detector returned an invalid result")
            except Exception as exc:  # every crash is a gate failure and recorded
                row["crash_count"] += 1
                if len(row["samples"]) < active_limits.max_samples:
                    row["samples"].append(
                        {
                            "file": logical_path,
                            "kind": "crash",
                            "exception_type": type(exc).__name__,
                        }
                    )
                continue

            row["finding_count"] += len(findings)
            high_confidence = [
                finding
                for finding in findings
                if _confidence(finding) >= active_limits.high_confidence
            ]
            row["high_confidence_finding_count"] += len(high_confidence)
            if high_confidence:
                row["high_confidence_files"].add(logical_path)
            for finding in high_confidence:
                if len(row["samples"]) >= active_limits.max_samples:
                    break
                row["samples"].append(
                    {
                        "file": logical_path,
                        "kind": "finding",
                        "line": _positive_int(finding.get("line")),
                        "rule_id": str(finding.get("rule_id") or ""),
                    }
                )

    high_confidence_files: set[str] = set()
    crash_count = 0
    normalized_detectors: dict[str, dict[str, Any]] = {}
    for detector_name, raw_row in sorted(detector_rows.items()):
        flagged_files = set(raw_row.pop("high_confidence_files"))
        high_confidence_files.update(flagged_files)
        crash_count += int(raw_row["crash_count"])
        normalized_detectors[detector_name] = {
            **raw_row,
            "high_confidence_file_count": len(flagged_files),
            "high_confidence_file_rate": len(flagged_files) / len(files),
        }

    aggregate_rate = len(high_confidence_files) / len(files)
    passed = (
        not corpus_errors
        and crash_count == 0
        and aggregate_rate <= active_limits.max_high_confidence_file_rate
    )
    return {
        "schema_version": NATIVE_NEGATIVE_CONTROL_SCHEMA_VERSION,
        "status": "PASS" if passed else "FAIL",
        "claim_boundary": (
            "Regression gate over a presumed-safe corpus; it does not establish "
            "absence or presence of vulnerabilities."
        ),
        "root": str(corpus_root),
        "file_count": len(files),
        "total_bytes": total_bytes,
        "thresholds": {
            "high_confidence": active_limits.high_confidence,
            "max_high_confidence_file_rate": (
                active_limits.max_high_confidence_file_rate
            ),
            "max_crash_count": 0,
        },
        "metrics": {
            "corpus_error_count": len(corpus_errors),
            "crash_count": crash_count,
            "high_confidence_file_count": len(high_confidence_files),
            "high_confidence_file_rate": aggregate_rate,
        },
        "corpus_errors": corpus_errors[: active_limits.max_samples],
        "detectors": normalized_detectors,
    }


def _confidence(finding: Mapping[str, Any]) -> float:
    value = finding.get("confidence", 0.0)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("detector confidence must be numeric")
    confidence = float(value)
    if not 0.0 <= confidence <= 1.0:
        raise ValueError("detector confidence must be between 0 and 1")
    return confidence


def _positive_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


__all__ = [
    "DEFAULT_DETECTORS",
    "DEFAULT_EXCLUDED_DIRECTORIES",
    "NATIVE_NEGATIVE_CONTROL_SCHEMA_VERSION",
    "NegativeControlLimits",
    "evaluate_native_negative_control",
]
