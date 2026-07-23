from pathlib import Path

import pytest

from belief.benchmark.static_analysis import (
    STATIC_ANALYSIS_BENCHMARK_SCHEMA_VERSION,
    STATIC_ANALYSIS_MODE,
    StaticAnalysisThresholds,
    evaluate_static_analysis_benchmark,
    load_static_analysis_cases,
    load_static_analysis_thresholds,
)


ROOT = Path(__file__).resolve().parents[1]
BENCHMARK_ROOT = ROOT / "benchmark_static_analysis"


_OBSERVED = {
    "path_traversal/vulnerable.py": {
        "verdict": "needs_manual_validation",
        "case_type": "path_traversal_possible",
        "route": "/files",
        "source": "request.args['path']",
        "sink": "open(path)",
        "guard": [],
        "line": 6,
        "relevant_lines": [5, 6],
        "reason": "externally controlled path reaches a file-read sink without containment",
    },
    "path_traversal/protected.py": {
        "verdict": "protected_by_guard",
        "case_type": "path_traversal_possible",
        "route": "/files/safe",
        "source": "request.args['path']",
        "sink": "open(candidate)",
        "guard": ["path_containment_guard"],
        "line": 13,
        "relevant_lines": [9, 11, 13],
        "reason": "resolved candidate is confined to the allowed directory before file read",
    },
    "path_traversal/ambiguous.py": {
        "verdict": "needs_manual_validation",
        "case_type": "path_traversal_possible",
        "route": "/files/delegated",
        "source": "request.args['path']",
        "sink": "open(candidate)",
        "guard": ["unresolved_helper"],
        "line": 7,
        "relevant_lines": [5, 6, 7],
        "reason": "unresolved helper prevents a local proof of path containment",
    },
    "idor_bola/vulnerable.py": {
        "verdict": "needs_manual_validation",
        "case_type": "idor_bola_possible",
        "route": "/documents/<document_id>",
        "source": "document_id",
        "sink": "Document.query.filter_by(id=document_id)",
        "guard": ["authentication_guard"],
        "line": 6,
        "relevant_lines": [5, 6, 7],
        "reason": "externally controlled resource id is loaded without owner or tenant binding",
    },
    "idor_bola/protected.py": {
        "verdict": "protected_by_guard",
        "case_type": "idor_bola_possible",
        "route": "/documents/<document_id>/safe",
        "source": "document_id",
        "sink": "Document.query.filter_by(id=document_id, owner_id=current_user.id)",
        "guard": ["ownership_guard"],
        "line": 6,
        "relevant_lines": [5, 6, 7],
        "reason": "resource lookup is bound to the current owner before sensitive return",
    },
    "idor_bola/ambiguous.py": {
        "verdict": "needs_manual_validation",
        "case_type": "idor_bola_possible",
        "route": "/documents/<document_id>/delegated",
        "source": "document_id",
        "sink": "Document.query.filter_by(id=document_id)",
        "guard": ["unresolved_helper"],
        "line": 6,
        "relevant_lines": [5, 6, 7, 8],
        "reason": "delegated authorization cannot be proven from the local source",
    },
}


def _successful_pipeline(target: Path):
    relative = target.relative_to(BENCHMARK_ROOT).as_posix()
    if relative.endswith("false_positive_trap.py"):
        return {"audit_cases": []}
    observed = dict(_OBSERVED[relative])
    verdict = observed.pop("verdict")
    route = observed.pop("route")
    observed["file"] = str(target)
    observed["route_context"] = {"path": route}
    observed["metadata"] = {"reportability": {"verdict": verdict}}
    return {"audit_cases": [observed]}


@pytest.fixture(scope="module")
def real_pipeline_payload():
    from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target

    options = StaticAnalysisOptions(
        selected_categories=frozenset({"security", "taint"}),
        include_hypotheses=True,
        include_guarantees=True,
        include_dataflow=True,
        show_dataflow=True,
        include_audit_cases=True,
        audit_mode=True,
        include_routes=True,
        reportability=True,
    )
    return evaluate_static_analysis_benchmark(
        BENCHMARK_ROOT,
        lambda target: analyze_static_target(target, options),
        thresholds=BENCHMARK_ROOT / "thresholds.yml",
    )


def test_real_corpus_is_exactly_two_categories_by_four_variants():
    cases = load_static_analysis_cases(BENCHMARK_ROOT)

    assert len(cases) == 8
    assert {(case["category"], case["variant"]) for case in cases} == {
        (category, variant)
        for category in ("path_traversal", "idor_bola")
        for variant in ("vulnerable", "protected", "ambiguous", "false_positive_trap")
    }
    assert sum(bool(case["expected"].get("expected_no_audit_case")) for case in cases) == 2
    assert all((BENCHMARK_ROOT / case["target"]).is_file() for case in cases)


def test_real_benchmark_invokes_python_pipeline_once_per_fixture():
    calls = []

    def pipeline(target):
        calls.append(target)
        return _successful_pipeline(target)

    payload = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, pipeline)

    assert len(calls) == 8
    assert all(isinstance(target, Path) and target.is_absolute() for target in calls)
    assert payload["schema_version"] == STATIC_ANALYSIS_BENCHMARK_SCHEMA_VERSION
    assert payload["mode"] == STATIC_ANALYSIS_MODE
    assert payload["case_count"] == 8
    assert payload["metrics"]["matched_verdict_count"] == 6
    assert payload["metrics"]["verdict_accuracy"] == 0.75
    assert payload["metrics"]["vulnerable_case_detection_rate"] == 1.0
    assert payload["metrics"]["protected_case_false_positive_rate"] == 0.0
    assert payload["metrics"]["expected_no_case_accuracy"] == 1.0
    assert payload["thresholds_passed"] is True
    assert payload["exit_code"] == 0


@pytest.mark.parametrize(
    ("category", "variant"),
    [
        ("path_traversal", "vulnerable"),
        ("path_traversal", "protected"),
        ("path_traversal", "ambiguous"),
        ("path_traversal", "false_positive_trap"),
        ("idor_bola", "vulnerable"),
        ("idor_bola", "protected"),
        ("idor_bola", "ambiguous"),
        ("idor_bola", "false_positive_trap"),
    ],
)
def test_each_required_static_analysis_case_is_evaluated(category, variant):
    payload = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, _successful_pipeline)
    row = next(
        case
        for case in payload["cases"]
        if case["category"] == category and case["variant"] == variant
    )

    assert row["analysis_succeeded"] is True
    assert row["matched"] is True


@pytest.mark.security
@pytest.mark.parametrize(
    ("category", "variant"),
    [
        ("path_traversal", "vulnerable"),
        ("path_traversal", "protected"),
        ("path_traversal", "ambiguous"),
        ("path_traversal", "false_positive_trap"),
        ("idor_bola", "vulnerable"),
        ("idor_bola", "protected"),
        ("idor_bola", "ambiguous"),
        ("idor_bola", "false_positive_trap"),
    ],
)
def test_real_pipeline_matches_each_ground_truth_variant(
    real_pipeline_payload,
    category,
    variant,
):
    row = next(
        case
        for case in real_pipeline_payload["cases"]
        if case["category"] == category and case["variant"] == variant
    )

    assert row["analysis_succeeded"] is True
    assert "pipeline_error" not in row
    if row["expected"].get("expected_no_audit_case"):
        assert row["matched"] is True
        assert row["field_matches"]["expected_no_audit_case"] is True
    else:
        assert row["verdict_matched"] is True
        assert row["field_matches"]["vulnerability_type"] is True
        assert row["field_matches"]["file"] is True
        assert row["field_matches"]["source"] is True
        assert row["field_matches"]["sink"] is True


def test_real_pipeline_passes_documented_thresholds(real_pipeline_payload):
    metrics = real_pipeline_payload["metrics"]

    assert metrics["case_count"] == 8
    assert metrics["matched_verdict_count"] == 6
    assert metrics["verdict_accuracy"] == 0.75
    assert metrics["vulnerable_case_detection_rate"] == 1.0
    assert metrics["protected_case_false_positive_rate"] == 0.0
    assert metrics["expected_no_case_accuracy"] == 1.0
    assert real_pipeline_payload["thresholds_passed"] is True
    assert real_pipeline_payload["exit_code"] == 0


def test_observed_verdict_comes_from_pipeline_not_ground_truth():
    def weak_pipeline(target):
        if target.name == "vulnerable.py" and target.parent.name == "path_traversal":
            case = _successful_pipeline(target)["audit_cases"][0]
            case["metadata"]["reportability"]["verdict"] = "weak_signal"
            return {"audit_cases": [case]}
        return _successful_pipeline(target)

    payload = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, weak_pipeline)
    row = next(case for case in payload["cases"] if case["id"] == "path-traversal-vulnerable")

    assert row["expected"]["verdict"] == "needs_manual_validation"
    assert row["observed"]["verdict"] == "weak_signal"
    assert row["matched"] is False
    assert payload["metrics"]["matched_verdict_count"] == 5


def test_row_match_requires_detailed_ground_truth_fields_not_only_verdict():
    def differently_explained_pipeline(target):
        result = _successful_pipeline(target)
        if target.name == "vulnerable.py" and target.parent.name == "path_traversal":
            result["audit_cases"][0]["reason"] = "different observed root cause"
        return result

    payload = evaluate_static_analysis_benchmark(
        BENCHMARK_ROOT,
        differently_explained_pipeline,
    )
    row = next(case for case in payload["cases"] if case["id"] == "path-traversal-vulnerable")

    assert row["verdict_matched"] is True
    assert row["field_matches"]["root_cause"] is False
    assert row["matched"] is False


def test_pipeline_failure_cannot_satisfy_expected_no_case():
    def broken_pipeline(_target):
        raise RuntimeError("synthetic analysis failure")

    payload = evaluate_static_analysis_benchmark(
        BENCHMARK_ROOT,
        broken_pipeline,
        thresholds=StaticAnalysisThresholds(
            minimum_verdict_accuracy=0.0,
            minimum_vulnerable_detection_rate=0.0,
            maximum_protected_false_positive_rate=1.0,
            minimum_expected_no_case_accuracy=1.0,
        ),
    )

    assert payload["metrics"]["expected_no_case_accuracy"] == 0.0
    assert payload["thresholds_passed"] is False
    assert payload["exit_code"] == 1
    assert all(case["pipeline_error"].startswith("RuntimeError:") for case in payload["cases"])


def test_digest_excludes_runtime_duration():
    first_times = iter([10.0, 11.0])
    second_times = iter([20.0, 29.0])

    first = evaluate_static_analysis_benchmark(
        BENCHMARK_ROOT, _successful_pipeline, clock=lambda: next(first_times)
    )
    second = evaluate_static_analysis_benchmark(
        BENCHMARK_ROOT, _successful_pipeline, clock=lambda: next(second_times)
    )

    assert first["duration_seconds"] == 1.0
    assert second["duration_seconds"] == 9.0
    assert first["deterministic_digest"] == second["deterministic_digest"]
    assert (
        first["metrics"]["deterministic_digest"]
        == second["metrics"]["deterministic_digest"]
    )


def test_threshold_file_is_loaded_and_failed_thresholds_request_nonzero_exit():
    thresholds = load_static_analysis_thresholds(BENCHMARK_ROOT / "thresholds.yml")

    assert thresholds == StaticAnalysisThresholds()

    def no_findings(_target):
        return {"audit_cases": []}

    payload = evaluate_static_analysis_benchmark(
        BENCHMARK_ROOT,
        no_findings,
        thresholds=BENCHMARK_ROOT / "thresholds.yml",
    )

    assert payload["metrics"]["vulnerable_case_detection_rate"] == 0.0
    assert payload["thresholds_passed"] is False
    assert payload["status"] == "failed"
    assert payload["exit_code"] == 1
    assert (
        payload["threshold_evaluation"]["minimum_vulnerable_detection_rate"]["passed"]
        is False
    )


def test_category_breakdown_is_complete_and_stably_ordered():
    payload = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, _successful_pipeline)

    breakdown = payload["metrics"]["category_breakdown"]
    assert list(breakdown) == ["idor_bola", "path_traversal"]
    assert all(category["case_count"] == 4 for category in breakdown.values())
    assert all(category["verdict_accuracy"] == 0.75 for category in breakdown.values())


def test_any_reportable_case_on_protected_fixture_counts_as_false_positive():
    def pipeline(target):
        result = _successful_pipeline(target)
        if target.name == "protected.py" and target.parent.name == "idor_bola":
            extra = dict(result["audit_cases"][0])
            extra["case_id"] = "unexpected-reportable-case"
            extra["metadata"] = {"reportability": {"verdict": "reportable_candidate"}}
            result["audit_cases"].append(extra)
        return result

    payload = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, pipeline)

    assert payload["metrics"]["protected_case_false_positive_rate"] == 0.5
    assert payload["thresholds_passed"] is False


def test_unrelated_reportable_type_does_not_count_as_vulnerable_detection():
    def pipeline(target):
        result = _successful_pipeline(target)
        relative = target.relative_to(BENCHMARK_ROOT).as_posix()
        if relative in {"path_traversal/vulnerable.py", "idor_bola/vulnerable.py"}:
            unrelated = dict(result["audit_cases"][0])
            unrelated["case_type"] = "command_injection_possible"
            unrelated["metadata"] = {"reportability": {"verdict": "reportable_candidate"}}
            return {"audit_cases": [unrelated]}
        return result

    payload = evaluate_static_analysis_benchmark(BENCHMARK_ROOT, pipeline)

    assert payload["metrics"]["vulnerable_case_detection_rate"] == 0.0
