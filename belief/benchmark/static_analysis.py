"""Real, deterministic static-analysis ground-truth benchmark.

Unlike the metadata-only MVP, this runner invokes a Python analysis callable
for every fixture and compares the returned audit cases with declared ground
truth.  It never executes fixtures and never shells out to the BELIEF CLI.
"""

from __future__ import annotations

import hashlib
import json
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping


STATIC_ANALYSIS_BENCHMARK_SCHEMA_VERSION = "belief.static_analysis_benchmark.v1"
STATIC_ANALYSIS_MODE = "static_analysis_ground_truth_v1"
STATIC_ANALYSIS_CATEGORIES = ("idor_bola", "path_traversal")
STATIC_ANALYSIS_VARIANTS = (
    "ambiguous",
    "false_positive_trap",
    "protected",
    "vulnerable",
)
STATIC_ANALYSIS_VERDICTS = {
    "reportable_candidate",
    "needs_manual_validation",
    "weak_signal",
    "likely_false_positive",
    "protected_by_guard",
}
_REQUIRED_CASE_FIELDS = {"id", "category", "variant", "target", "expected"}
_REQUIRED_EXPECTED_FIELDS = {
    "verdict",
    "vulnerability_type",
    "route",
    "source",
    "sink",
    "guard",
    "file",
    "relevant_lines",
    "root_cause",
}
_DETECTION_VERDICTS = {"reportable_candidate", "needs_manual_validation"}


@dataclass(frozen=True)
class StaticAnalysisThresholds:
    """Acceptance thresholds for the real static-analysis benchmark."""

    minimum_verdict_accuracy: float = 0.75
    minimum_vulnerable_detection_rate: float = 0.75
    maximum_protected_false_positive_rate: float = 0.0
    minimum_expected_no_case_accuracy: float = 0.75

    def __post_init__(self) -> None:
        for name, value in asdict(self).items():
            normalized = float(value)
            if not 0.0 <= normalized <= 1.0:
                raise ValueError(f"{name} must be between 0.0 and 1.0")
            object.__setattr__(self, name, normalized)

    def to_dict(self) -> dict[str, float]:
        return {key: float(value) for key, value in asdict(self).items()}


DEFAULT_STATIC_ANALYSIS_THRESHOLDS = StaticAnalysisThresholds()
StaticAnalysisPipeline = Callable[[Path], Any]


def load_static_analysis_cases(root: str | Path) -> list[dict[str, Any]]:
    """Load and validate the complete eight-case ground-truth matrix."""

    benchmark_root = Path(root)
    if not benchmark_root.exists() or not benchmark_root.is_dir():
        raise ValueError(
            f"benchmark root does not exist or is not a directory: {benchmark_root}"
        )

    cases: list[dict[str, Any]] = []
    for cases_file in sorted(benchmark_root.rglob("cases.yml")):
        for raw_case in _parse_ground_truth_yml(cases_file):
            cases.append(_validate_static_case(raw_case, cases_file, benchmark_root))

    expected_matrix = {
        (category, variant)
        for category in STATIC_ANALYSIS_CATEGORIES
        for variant in STATIC_ANALYSIS_VARIANTS
    }
    actual_matrix = {(case["category"], case["variant"]) for case in cases}
    if len(cases) != len(expected_matrix) or actual_matrix != expected_matrix:
        missing = sorted(expected_matrix - actual_matrix)
        extra = sorted(actual_matrix - expected_matrix)
        details = []
        if missing:
            details.append(f"missing={missing}")
        if extra:
            details.append(f"extra={extra}")
        if len(cases) != len(actual_matrix):
            details.append("duplicate category/variant entries")
        suffix = f": {'; '.join(details)}" if details else ""
        raise ValueError(f"benchmark must contain exactly the eight required cases{suffix}")

    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("benchmark case ids must be unique")
    return sorted(cases, key=lambda case: (case["category"], case["variant"], case["id"]))


def load_static_analysis_thresholds(path: str | Path) -> StaticAnalysisThresholds:
    """Load the documented flat threshold YAML format without optional dependencies."""

    threshold_path = Path(path)
    if not threshold_path.exists() or not threshold_path.is_file():
        raise ValueError(f"threshold file does not exist: {threshold_path}")
    values: dict[str, Any] = {}
    for line_number, raw_line in enumerate(
        threshold_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if raw_line != raw_line.lstrip():
            raise ValueError(f"{threshold_path}:{line_number}: thresholds must be flat")
        key, value = _split_key_value(threshold_path, line_number, stripped)
        values[key] = _parse_scalar(value)

    allowed = set(asdict(DEFAULT_STATIC_ANALYSIS_THRESHOLDS))
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise ValueError(f"{threshold_path}: unknown threshold fields: {', '.join(unknown)}")
    merged = DEFAULT_STATIC_ANALYSIS_THRESHOLDS.to_dict()
    merged.update(values)
    try:
        return StaticAnalysisThresholds(**merged)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{threshold_path}: invalid thresholds: {exc}") from exc


def evaluate_static_analysis_benchmark(
    root: str | Path,
    pipeline: StaticAnalysisPipeline,
    *,
    thresholds: StaticAnalysisThresholds | Mapping[str, float] | str | Path | None = None,
    clock: Callable[[], float] = time.perf_counter,
) -> dict[str, Any]:
    """Analyze all eight fixtures through ``pipeline`` and compare real outputs.

    ``pipeline`` is called directly once per fixture with its absolute
    :class:`~pathlib.Path`.  The result may expose ``audit_cases`` as an
    attribute or mapping key, or may itself be an iterable of audit cases.
    """

    benchmark_root = Path(root).resolve()
    configured_thresholds = _coerce_thresholds(thresholds)
    started = clock()
    rows = []
    for case in load_static_analysis_cases(benchmark_root):
        target = (benchmark_root / case["target"]).resolve()
        analysis_succeeded = True
        pipeline_error = ""
        try:
            result = pipeline(target)
            actual_cases = _extract_audit_cases(result)
        except Exception as exc:  # benchmark errors are evidence, never successes
            analysis_succeeded = False
            pipeline_error = f"{type(exc).__name__}: {exc}"
            actual_cases = []
        rows.append(
            _compare_case(
                case,
                actual_cases,
                benchmark_root,
                analysis_succeeded=analysis_succeeded,
                pipeline_error=pipeline_error,
            )
        )

    duration = max(0.0, float(clock() - started))
    metrics = _summarize_static_metrics(rows)
    threshold_evaluation = _evaluate_thresholds(metrics, configured_thresholds)
    passed = all(item["passed"] for item in threshold_evaluation.values())
    payload: dict[str, Any] = {
        "schema_version": STATIC_ANALYSIS_BENCHMARK_SCHEMA_VERSION,
        "mode": STATIC_ANALYSIS_MODE,
        "target": benchmark_root.as_posix(),
        "case_count": len(rows),
        "metrics": metrics,
        "thresholds": configured_thresholds.to_dict(),
        "threshold_evaluation": threshold_evaluation,
        "thresholds_passed": passed,
        "status": "passed" if passed else "failed",
        "exit_code": 0 if passed else 1,
        "cases": rows,
        "duration_seconds": round(duration, 6),
    }
    payload["deterministic_digest"] = _semantic_digest(payload)
    payload["metrics"]["deterministic_digest"] = payload["deterministic_digest"]
    payload["metrics"]["duration_seconds"] = payload["duration_seconds"]
    return payload


def write_static_analysis_benchmark_json(
    root: str | Path,
    output: str | Path,
    pipeline: StaticAnalysisPipeline,
    *,
    thresholds: StaticAnalysisThresholds | Mapping[str, float] | str | Path | None = None,
) -> dict[str, Any]:
    """Run the real benchmark and write its stable JSON representation."""

    payload = evaluate_static_analysis_benchmark(root, pipeline, thresholds=thresholds)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _coerce_thresholds(
    thresholds: StaticAnalysisThresholds | Mapping[str, float] | str | Path | None,
) -> StaticAnalysisThresholds:
    if thresholds is None:
        return DEFAULT_STATIC_ANALYSIS_THRESHOLDS
    if isinstance(thresholds, StaticAnalysisThresholds):
        return thresholds
    if isinstance(thresholds, (str, Path)):
        return load_static_analysis_thresholds(thresholds)
    if isinstance(thresholds, Mapping):
        defaults = DEFAULT_STATIC_ANALYSIS_THRESHOLDS.to_dict()
        unknown = sorted(set(thresholds) - set(defaults))
        if unknown:
            raise ValueError(f"unknown threshold fields: {', '.join(unknown)}")
        defaults.update({str(key): value for key, value in thresholds.items()})
        return StaticAnalysisThresholds(**defaults)
    raise TypeError("thresholds must be a mapping, path, StaticAnalysisThresholds, or None")


def _extract_audit_cases(result: Any) -> list[Any]:
    if result is None:
        return []
    if isinstance(result, Mapping):
        raw_cases = result.get("audit_cases", [])
    elif hasattr(result, "audit_cases"):
        raw_cases = getattr(result, "audit_cases")
    elif isinstance(result, Iterable) and not isinstance(result, (str, bytes)):
        raw_cases = result
    else:
        raise TypeError("pipeline result must expose audit_cases or be an iterable")
    if raw_cases is None:
        return []
    if isinstance(raw_cases, Mapping) or isinstance(raw_cases, (str, bytes)):
        raise TypeError("audit_cases must be an iterable of case objects")
    return list(raw_cases)


def _compare_case(
    expected_case: dict[str, Any],
    actual_cases: list[Any],
    root: Path,
    *,
    analysis_succeeded: bool,
    pipeline_error: str,
) -> dict[str, Any]:
    expected = dict(expected_case["expected"])
    observed_cases = [_observed_case(item, root) for item in actual_cases]
    observed_cases.sort(key=_stable_json)
    best = _select_best_case(expected, observed_cases)
    expected_no_case = bool(expected.get("expected_no_audit_case", False))
    no_case_observed = not observed_cases

    verdict_matched = bool(
        not expected_no_case
        and analysis_succeeded
        and best is not None
        and best.get("verdict") == expected.get("verdict")
    )

    field_matches = _field_matches(expected, best) if best is not None else {
        key: False for key in _REQUIRED_EXPECTED_FIELDS
    }
    if expected_no_case:
        field_matches["expected_no_audit_case"] = analysis_succeeded and no_case_observed
    matched = bool(
        analysis_succeeded
        and (
            no_case_observed
            if expected_no_case
            else best is not None and all(field_matches.values())
        )
    )

    row = {
        "id": expected_case["id"],
        "category": expected_case["category"],
        "variant": expected_case["variant"],
        "target": expected_case["target"],
        "expected": expected,
        "observed": best,
        "observed_audit_case_count": len(observed_cases),
        "observed_audit_cases": observed_cases,
        "field_matches": dict(sorted(field_matches.items())),
        "matched": matched,
        "verdict_matched": verdict_matched,
        "analysis_succeeded": analysis_succeeded,
    }
    if pipeline_error:
        row["pipeline_error"] = pipeline_error
    return row


def _observed_case(case: Any, root: Path) -> dict[str, Any]:
    if isinstance(case, Mapping):
        raw = dict(case)
    elif hasattr(case, "to_dict") and callable(case.to_dict):
        raw = dict(case.to_dict())
    else:
        raw = {
            name: getattr(case, name)
            for name in (
                "case_id",
                "case_type",
                "status",
                "file",
                "line",
                "source",
                "sink",
                "guarantees",
                "sanitizers",
                "reason",
                "route_context",
                "metadata",
                "structured_dataflow",
            )
            if hasattr(case, name)
        }

    metadata = raw.get("metadata") if isinstance(raw.get("metadata"), Mapping) else {}
    reportability = (
        metadata.get("reportability")
        if isinstance(metadata.get("reportability"), Mapping)
        else {}
    )
    route_context = raw.get("route_context")
    if not isinstance(route_context, Mapping):
        route_context = {}
    structured = raw.get("structured_dataflow")
    if not isinstance(structured, Mapping):
        structured = metadata.get("structured_dataflow", {})
    if not isinstance(structured, Mapping):
        structured = {}

    file_value = str(raw.get("file") or structured.get("file") or "")
    relevant_lines = _observed_lines(raw, structured)
    guards = _observed_guards(raw, metadata, reportability, structured)
    return {
        "case_id": str(raw.get("case_id") or ""),
        "verdict": str(raw.get("verdict") or reportability.get("verdict") or ""),
        "vulnerability_type": str(
            raw.get("vulnerability_type") or raw.get("case_type") or ""
        ),
        "route": str(
            raw.get("route")
            or route_context.get("path")
            or route_context.get("route")
            or metadata.get("route")
            or metadata.get("path")
            or ""
        ),
        "source": str(
            raw.get("source")
            or _nested_text(structured, "source", "expression", "symbol")
        ),
        "sink": str(
            raw.get("sink")
            or _nested_text(structured, "sink", "expression", "symbol")
        ),
        "guard": guards,
        "file": _relative_or_posix(file_value, root),
        "relevant_lines": relevant_lines,
        "root_cause": str(raw.get("root_cause") or raw.get("reason") or ""),
        "status": str(raw.get("status") or ""),
    }


def _observed_lines(raw: Mapping[str, Any], structured: Mapping[str, Any]) -> list[int]:
    lines: set[int] = set()
    for value in (raw.get("line"), structured.get("source_line"), structured.get("sink_line")):
        if isinstance(value, int) and value > 0:
            lines.add(value)
    explicit = raw.get("relevant_lines")
    if isinstance(explicit, Iterable) and not isinstance(explicit, (str, bytes, Mapping)):
        for value in explicit:
            if isinstance(value, int) and value > 0:
                lines.add(value)
    for key in ("source", "sink"):
        node = structured.get(key)
        if isinstance(node, Mapping) and isinstance(node.get("line"), int):
            lines.add(node["line"])
    ordered_nodes = structured.get("ordered_nodes")
    if isinstance(ordered_nodes, Iterable) and not isinstance(
        ordered_nodes, (str, bytes, Mapping)
    ):
        for node in ordered_nodes:
            if isinstance(node, Mapping) and isinstance(node.get("line"), int):
                lines.add(node["line"])
    return sorted(lines)


def _observed_guards(
    raw: Mapping[str, Any],
    *containers: Mapping[str, Any],
) -> list[str]:
    guards: list[str] = []
    for value in (raw.get("guard"), raw.get("guarantees"), raw.get("sanitizers")):
        guards.extend(_guard_items(value))
    for container in containers:
        for key in ("guard", "guards", "guard_applicability"):
            value = container.get(key)
            guards.extend(_guard_items(value))
    return sorted(dict.fromkeys(item for item in guards if item))


def _select_best_case(
    expected: Mapping[str, Any], observed_cases: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if not observed_cases:
        return None

    def rank(observed: dict[str, Any]) -> tuple[int, str]:
        score = 0
        if _text_matches(expected.get("vulnerability_type"), observed["vulnerability_type"]):
            score += 16
        if _file_matches(expected.get("file"), observed["file"]):
            score += 8
        if _text_matches(expected.get("route"), observed["route"]):
            score += 4
        if _text_matches(expected.get("source"), observed["source"]):
            score += 2
        if _text_matches(expected.get("sink"), observed["sink"]):
            score += 1
        return (-score, _stable_json(observed))

    return min(observed_cases, key=rank)


def _field_matches(
    expected: Mapping[str, Any], observed: Mapping[str, Any]
) -> dict[str, bool]:
    matches = {
        "verdict": str(expected.get("verdict") or "") == str(observed.get("verdict") or ""),
        "vulnerability_type": _text_matches(
            expected.get("vulnerability_type"), observed.get("vulnerability_type")
        ),
        "route": _text_matches(expected.get("route"), observed.get("route")),
        "source": _text_matches(expected.get("source"), observed.get("source")),
        "sink": _text_matches(expected.get("sink"), observed.get("sink")),
        "guard": _text_matches(expected.get("guard"), observed.get("guard")),
        "file": _file_matches(expected.get("file"), observed.get("file")),
        "relevant_lines": set(expected.get("relevant_lines") or []).issubset(
            set(observed.get("relevant_lines") or [])
        ),
        "root_cause": _text_matches(expected.get("root_cause"), observed.get("root_cause")),
    }
    return matches


def _summarize_static_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    matched = sum(1 for row in rows if row["verdict_matched"])
    vulnerable = [row for row in rows if row["variant"] == "vulnerable"]
    protected = [row for row in rows if row["variant"] == "protected"]
    expected_no_case = [
        row for row in rows if bool(row["expected"].get("expected_no_audit_case", False))
    ]
    metrics = {
        "case_count": total,
        "matched_verdict_count": matched,
        "verdict_accuracy": _rate(matched, total),
        "vulnerable_case_detection_rate": _rate(
            sum(1 for row in vulnerable if _detected(row)), len(vulnerable)
        ),
        "protected_case_false_positive_rate": _rate(
            sum(1 for row in protected if _detected(row)), len(protected)
        ),
        "expected_no_case_accuracy": _rate(
            sum(
                1
                for row in expected_no_case
                if row["analysis_succeeded"] and row["observed_audit_case_count"] == 0
            ),
            len(expected_no_case),
        ),
    }
    by_category: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        by_category[row["category"]].append(row)
    metrics["category_breakdown"] = {
        category: _category_metrics(category_rows)
        for category, category_rows in sorted(by_category.items())
    }
    return metrics


def _category_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(rows)
    matched = sum(1 for row in rows if row["verdict_matched"])
    vulnerable = [row for row in rows if row["variant"] == "vulnerable"]
    protected = [row for row in rows if row["variant"] == "protected"]
    no_case = [row for row in rows if row["expected"].get("expected_no_audit_case")]
    return {
        "case_count": total,
        "matched_verdict_count": matched,
        "verdict_accuracy": _rate(matched, total),
        "vulnerable_case_detection_rate": _rate(
            sum(1 for row in vulnerable if _detected(row)), len(vulnerable)
        ),
        "protected_case_false_positive_rate": _rate(
            sum(1 for row in protected if _detected(row)), len(protected)
        ),
        "expected_no_case_accuracy": _rate(
            sum(
                1
                for row in no_case
                if row["analysis_succeeded"] and row["observed_audit_case_count"] == 0
            ),
            len(no_case),
        ),
    }


def _detected(row: Mapping[str, Any]) -> bool:
    if not row.get("analysis_succeeded"):
        return False
    observed_cases = row.get("observed_audit_cases")
    if not isinstance(observed_cases, Iterable):
        return False
    expected = row.get("expected")
    expected_type = expected.get("vulnerability_type") if isinstance(expected, Mapping) else ""
    return any(
        isinstance(case, Mapping)
        and case.get("verdict") in _DETECTION_VERDICTS
        and _text_matches(expected_type, case.get("vulnerability_type"))
        for case in observed_cases
    )


def _evaluate_thresholds(
    metrics: Mapping[str, Any], thresholds: StaticAnalysisThresholds
) -> dict[str, dict[str, Any]]:
    checks = {
        "minimum_verdict_accuracy": (
            "verdict_accuracy",
            ">=",
            thresholds.minimum_verdict_accuracy,
        ),
        "minimum_vulnerable_detection_rate": (
            "vulnerable_case_detection_rate",
            ">=",
            thresholds.minimum_vulnerable_detection_rate,
        ),
        "maximum_protected_false_positive_rate": (
            "protected_case_false_positive_rate",
            "<=",
            thresholds.maximum_protected_false_positive_rate,
        ),
        "minimum_expected_no_case_accuracy": (
            "expected_no_case_accuracy",
            ">=",
            thresholds.minimum_expected_no_case_accuracy,
        ),
    }
    evaluated = {}
    for threshold_name, (metric_name, comparator, expected) in checks.items():
        actual = float(metrics[metric_name])
        passed = actual >= expected if comparator == ">=" else actual <= expected
        evaluated[threshold_name] = {
            "metric": metric_name,
            "actual": actual,
            "comparator": comparator,
            "threshold": float(expected),
            "passed": passed,
        }
    return evaluated


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
    encoded = json.dumps(semantic, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _parse_ground_truth_yml(path: Path) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    expected: dict[str, Any] | None = None
    current_list_key: str | None = None

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()

        if indent == 0 and stripped.startswith("- "):
            if current is not None:
                cases.append(current)
            current = {}
            expected = None
            current_list_key = None
            key, value = _split_key_value(path, line_number, stripped[2:].strip())
            current[key] = _parse_scalar(value)
            continue
        if current is None:
            raise ValueError(f"{path}:{line_number}: case entry must start with '- '")
        if indent == 2:
            key, value = _split_key_value(path, line_number, stripped)
            if key == "expected" and value == "":
                expected = {}
                current["expected"] = expected
                current_list_key = None
            elif value == "":
                raise ValueError(f"{path}:{line_number}: only expected may be a root mapping")
            else:
                current[key] = _parse_scalar(value)
                current_list_key = None
            continue
        if indent == 4 and expected is not None:
            key, value = _split_key_value(path, line_number, stripped)
            if value == "":
                expected[key] = []
                current_list_key = key
            else:
                expected[key] = _parse_scalar(value)
                current_list_key = None
            continue
        if indent == 6 and stripped.startswith("- ") and current_list_key and expected is not None:
            expected[current_list_key].append(_parse_scalar(stripped[2:].strip()))
            continue
        raise ValueError(f"{path}:{line_number}: unsupported cases.yml structure")

    if current is not None:
        cases.append(current)
    return cases


def _validate_static_case(raw: dict[str, Any], cases_file: Path, root: Path) -> dict[str, Any]:
    missing = sorted(_REQUIRED_CASE_FIELDS - set(raw))
    if missing:
        raise ValueError(f"{cases_file}: case is missing required fields: {', '.join(missing)}")
    expected = raw.get("expected")
    if not isinstance(expected, dict):
        raise ValueError(f"{cases_file}: expected must be a mapping")
    missing_expected = sorted(_REQUIRED_EXPECTED_FIELDS - set(expected))
    if missing_expected:
        raise ValueError(
            f"{cases_file}: expected is missing required fields: {', '.join(missing_expected)}"
        )

    category = str(raw["category"])
    variant = str(raw["variant"])
    if category not in STATIC_ANALYSIS_CATEGORIES:
        raise ValueError(f"{cases_file}: unsupported category: {category}")
    if variant not in STATIC_ANALYSIS_VARIANTS:
        raise ValueError(f"{cases_file}: unsupported variant: {variant}")
    verdict = str(expected["verdict"])
    if verdict not in STATIC_ANALYSIS_VERDICTS:
        raise ValueError(f"{cases_file}: invalid expected verdict: {verdict}")
    if not isinstance(expected["relevant_lines"], list) or not all(
        isinstance(line, int) and line > 0 for line in expected["relevant_lines"]
    ):
        raise ValueError(f"{cases_file}: expected.relevant_lines must contain positive integers")
    expected_no_case = expected.get("expected_no_audit_case", False)
    if not isinstance(expected_no_case, bool):
        raise ValueError(f"{cases_file}: expected.expected_no_audit_case must be a boolean")

    target = str(raw["target"])
    target_path = (root / target).resolve()
    try:
        target_path.relative_to(root.resolve())
    except ValueError as exc:
        raise ValueError(f"{cases_file}: target escapes benchmark root: {target}") from exc
    if not target_path.exists() or not target_path.is_file():
        raise ValueError(f"{cases_file}: target file does not exist: {target}")

    expected_file = str(expected["file"])
    if Path(expected_file).as_posix() != Path(target).as_posix():
        raise ValueError(f"{cases_file}: expected.file must equal target")
    normalized_expected = {
        key: value if key == "relevant_lines" else str(value)
        for key, value in expected.items()
        if key != "expected_no_audit_case"
    }
    normalized_expected["relevant_lines"] = list(expected["relevant_lines"])
    if "expected_no_audit_case" in expected:
        normalized_expected["expected_no_audit_case"] = expected_no_case
    return {
        "id": str(raw["id"]),
        "category": category,
        "variant": variant,
        "target": Path(target).as_posix(),
        "expected": normalized_expected,
    }


def _split_key_value(path: Path, line_number: int, text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"{path}:{line_number}: expected 'key: value'")
    key, value = text.split(":", 1)
    if not key.strip():
        raise ValueError(f"{path}:{line_number}: empty key")
    return key.strip(), value.strip()


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.isdigit() or value.startswith("-") and value[1:].isdigit():
        return int(value)
    try:
        return float(value)
    except ValueError:
        pass
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    return value


def _text_matches(expected: Any, observed: Any) -> bool:
    expected_text = _normalized_text(expected)
    observed_text = _normalized_text(observed)
    if not expected_text:
        return not observed_text
    return expected_text in observed_text


def _file_matches(expected: Any, observed: Any) -> bool:
    expected_path = str(expected or "").replace("\\", "/").lower().strip("/")
    observed_path = str(observed or "").replace("\\", "/").lower().strip("/")
    return bool(expected_path) and (
        observed_path == expected_path or observed_path.endswith(f"/{expected_path}")
    )


def _normalized_text(value: Any) -> str:
    if isinstance(value, Mapping):
        value = list(value.values())
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        value = " ".join(str(item) for item in value)
    return " ".join(str(value or "").lower().replace("_", " ").split())


def _relative_or_posix(value: str, root: Path) -> str:
    if not value:
        return ""
    path = Path(value)
    try:
        return path.resolve().relative_to(root).as_posix()
    except (OSError, ValueError):
        return path.as_posix()


def _nested_text(
    mapping: Mapping[str, Any],
    key: str,
    *nested_keys: str,
) -> str:
    nested = mapping.get(key)
    if not isinstance(nested, Mapping):
        return ""
    return str(next((nested.get(item) for item in nested_keys if nested.get(item)), ""))


def _guard_items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        items: list[str] = []
        for key in (
            "category",
            "type",
            "guard_type",
            "expression",
            "reason",
            "blockers",
        ):
            items.extend(_guard_items(value.get(key)))
        return items
    if isinstance(value, Iterable):
        return [item for nested in value for item in _guard_items(nested)]
    return [str(value)]


def _string_items(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [str(item) for item in value.values() if item is not None]
    if isinstance(value, Iterable):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _rate(count: int, total: int) -> float:
    return round(count / total, 6) if total else 0.0


__all__ = [
    "DEFAULT_STATIC_ANALYSIS_THRESHOLDS",
    "STATIC_ANALYSIS_BENCHMARK_SCHEMA_VERSION",
    "STATIC_ANALYSIS_CATEGORIES",
    "STATIC_ANALYSIS_MODE",
    "STATIC_ANALYSIS_VARIANTS",
    "STATIC_ANALYSIS_VERDICTS",
    "StaticAnalysisPipeline",
    "StaticAnalysisThresholds",
    "evaluate_static_analysis_benchmark",
    "load_static_analysis_cases",
    "load_static_analysis_thresholds",
    "write_static_analysis_benchmark_json",
]
