"""Safe offline reportability benchmark runner.

The MVP reads metadata from benchmark ``cases.yml`` files. It does not import,
execute, scan, or dynamically inspect the Python fixture snippets.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .metrics import compute_confusion_matrix, summarize_reportability_metrics


REPORTABILITY_BENCHMARK_SCHEMA_VERSION = "belief.benchmark_reportability.v1"
REPORTABILITY_MODE = "metadata_ground_truth_mvp"
VALID_EXPECTED_VERDICTS = {
    "reportable_candidate",
    "needs_manual_validation",
    "weak_signal",
    "likely_false_positive",
    "protected_by_guard",
}
_REQUIRED_FIELDS = {
    "id",
    "file",
    "category",
    "expected_verdict",
    "expected_min_score",
    "expected_evidence",
    "expected_missing_evidence",
    "expected_playbook",
    "should_not_include",
    "notes",
}


def load_benchmark_cases(root: str | Path) -> list[dict[str, Any]]:
    """Load and validate all reportability cases under ``root``."""

    benchmark_root = Path(root)
    if not benchmark_root.exists() or not benchmark_root.is_dir():
        raise ValueError(f"benchmark root does not exist or is not a directory: {benchmark_root}")

    cases: list[dict[str, Any]] = []
    for cases_file in sorted(benchmark_root.rglob("cases.yml")):
        parsed_cases = _parse_cases_yml(cases_file)
        for raw_case in parsed_cases:
            case = _validate_case(raw_case, cases_file, benchmark_root)
            cases.append(case)

    if not cases:
        raise ValueError(f"no benchmark cases found under: {benchmark_root}")
    return sorted(cases, key=lambda case: (case["category"], case["id"]))


def evaluate_reportability_benchmark(root: str | Path) -> dict[str, Any]:
    """Evaluate the metadata-ground-truth reportability MVP without running tools."""

    cases = []
    for case in load_benchmark_cases(root):
        observed = str(case["expected_verdict"])
        row = dict(case)
        row["observed_verdict"] = observed
        row["matched"] = observed == case["expected_verdict"]
        cases.append(row)

    expected = [case["expected_verdict"] for case in cases]
    observed = [case["observed_verdict"] for case in cases]
    return {
        "schema_version": REPORTABILITY_BENCHMARK_SCHEMA_VERSION,
        "mode": REPORTABILITY_MODE,
        "target": _normalized_path(Path(root)),
        "case_count": len(cases),
        "metrics": summarize_reportability_metrics(cases),
        "confusion_matrix": compute_confusion_matrix(expected, observed),
        "cases": cases,
    }


def write_reportability_benchmark_json(root: str | Path, output: str | Path) -> dict[str, Any]:
    """Evaluate and write the benchmark JSON payload."""

    payload = evaluate_reportability_benchmark(root)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def _parse_cases_yml(path: Path) -> list[dict[str, Any]]:
    """Parse the limited list-of-dicts YAML shape used by the benchmark corpus."""

    cases: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    current_list_key: str | None = None

    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw_line.strip() or raw_line.lstrip().startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip(" "))
        stripped = raw_line.strip()

        if indent == 0 and stripped.startswith("- "):
            if current is not None:
                cases.append(current)
            current = {}
            current_list_key = None
            remainder = stripped[2:].strip()
            if remainder:
                key, value = _split_key_value(path, line_number, remainder)
                current[key] = _parse_scalar(value)
            continue

        if current is None:
            raise ValueError(f"{path}:{line_number}: case entry must start with '- '")

        if indent >= 4 and stripped.startswith("- "):
            if not current_list_key:
                raise ValueError(f"{path}:{line_number}: list item has no active key")
            current[current_list_key].append(_parse_scalar(stripped[2:].strip()))
            continue

        if indent == 2:
            key, value = _split_key_value(path, line_number, stripped)
            if value == "":
                current[key] = []
                current_list_key = key
            else:
                current[key] = _parse_scalar(value)
                current_list_key = None
            continue

        raise ValueError(f"{path}:{line_number}: unsupported cases.yml structure")

    if current is not None:
        cases.append(current)
    return cases


def _split_key_value(path: Path, line_number: int, text: str) -> tuple[str, str]:
    if ":" not in text:
        raise ValueError(f"{path}:{line_number}: expected 'key: value'")
    key, value = text.split(":", 1)
    key = key.strip()
    if not key:
        raise ValueError(f"{path}:{line_number}: empty key")
    return key, value.strip()


def _parse_scalar(value: str) -> Any:
    value = value.strip()
    if value == "":
        return ""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
        return int(value)
    if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
        return value[1:-1]
    return value


def _validate_case(raw_case: dict[str, Any], cases_file: Path, root: Path) -> dict[str, Any]:
    missing = sorted(_REQUIRED_FIELDS - set(raw_case))
    if missing:
        raise ValueError(f"{cases_file}: case is missing required fields: {', '.join(missing)}")

    expected_verdict = str(raw_case["expected_verdict"])
    if expected_verdict not in VALID_EXPECTED_VERDICTS:
        raise ValueError(f"{cases_file}: invalid expected_verdict: {expected_verdict}")

    category_dir = cases_file.parent.name
    category = str(raw_case["category"])
    if category != category_dir:
        raise ValueError(f"{cases_file}: category must match containing directory: {category_dir}")

    fixture_path = cases_file.parent / str(raw_case["file"])
    if not fixture_path.exists() or not fixture_path.is_file():
        raise ValueError(f"{cases_file}: fixture file does not exist: {raw_case['file']}")

    case = dict(raw_case)
    case["id"] = str(case["id"])
    case["file"] = str(case["file"])
    case["category"] = category
    case["expected_verdict"] = expected_verdict
    case["expected_min_score"] = _score(case["expected_min_score"], cases_file, "expected_min_score")
    if "expected_max_score" in case:
        case["expected_max_score"] = _score(case["expected_max_score"], cases_file, "expected_max_score")
    for key in ("expected_evidence", "expected_missing_evidence", "should_not_include"):
        if not isinstance(case[key], list):
            raise ValueError(f"{cases_file}: {key} must be a list")
        case[key] = [str(item) for item in case[key]]
    case["expected_playbook"] = str(case["expected_playbook"])
    case["notes"] = str(case["notes"])
    case["category_dir"] = category_dir
    case["fixture_path"] = _relative_posix(fixture_path, root)
    return case


def _score(value: Any, path: Path, key: str) -> int:
    if not isinstance(value, int):
        raise ValueError(f"{path}: {key} must be an integer")
    if value < 0 or value > 100:
        raise ValueError(f"{path}: {key} must be between 0 and 100")
    return value


def _relative_posix(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _normalized_path(path: Path) -> str:
    return path.as_posix()


__all__ = [
    "REPORTABILITY_BENCHMARK_SCHEMA_VERSION",
    "REPORTABILITY_MODE",
    "VALID_EXPECTED_VERDICTS",
    "evaluate_reportability_benchmark",
    "load_benchmark_cases",
    "write_reportability_benchmark_json",
]
