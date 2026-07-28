"""Eight-case local benchmark for plan and execution evidence quality."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .execution_models import (
    ValidationContractError,
    ValidationExecutionContext,
)
from .plan_models import canonical_digest, clean_text
from .plans import build_validation_plan
from .runner import run_validation_plan_bundle


LOCAL_VALIDATION_BENCHMARK_SCHEMA_VERSION = (
    "belief.local_validation_benchmark.v1"
)
LOCAL_VALIDATION_BENCHMARK_CORPUS_SCHEMA_VERSION = (
    "belief.local_validation_benchmark_corpus.v1"
)

_EXPECTED_CASES = {
    ("path_traversal_possible", "vulnerable"),
    ("path_traversal_possible", "protected"),
    ("path_traversal_possible", "ambiguous"),
    ("path_traversal_possible", "trap"),
    ("idor_bola_possible", "vulnerable"),
    ("idor_bola_possible", "protected"),
    ("idor_bola_possible", "ambiguous"),
    ("idor_bola_possible", "trap"),
}
_GROUND_TRUTHS = {"vulnerable", "safe", "ambiguous"}
_PREDICTIONS = {"positive", "negative", "abstain"}


def run_local_validation_benchmark(
    corpus_path: str | Path,
) -> dict[str, Any]:
    """Run the frozen local corpus twice and verify semantic stability."""

    corpus, cases = load_local_validation_benchmark_corpus(corpus_path)
    first = _run_once(cases, corpus_digest=canonical_digest(corpus))
    second = _run_once(cases, corpus_digest=canonical_digest(corpus))
    stable = first == second
    stages = _stage_metrics(cases, first)
    payload: dict[str, Any] = {
        "schema_version": LOCAL_VALIDATION_BENCHMARK_SCHEMA_VERSION,
        "corpus": {
            "schema_version": corpus["schema_version"],
            "sha256": canonical_digest(corpus),
            "case_count": len(cases),
            "families": [
                "idor_bola_possible",
                "path_traversal_possible",
            ],
            "variants": [
                "ambiguous",
                "protected",
                "trap",
                "vulnerable",
            ],
        },
        "boundaries": {
            "local_only": True,
            "susvibes_artifacts_opened": False,
            "reserved_holdout_opened": False,
            "network_used": False,
            "subprocess_used": False,
            "docker_used": False,
            "external_system_used": False,
            "secpass_claimed": False,
            "leaderboard_comparison_claimed": False,
        },
        "stages": stages,
        "validation_metrics": first["metrics"],
        "semantic_stability": {
            "identical_repeated_execution": stable,
            "first_digest": first["deterministic_digest"],
            "second_digest": second["deterministic_digest"],
        },
        "case_results": _case_results(cases, first),
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_local_validation_benchmark(
    output: str | Path,
    *,
    corpus_path: str | Path,
) -> dict[str, Any]:
    """Create a benchmark report without replacing an existing artifact."""

    payload = run_local_validation_benchmark(corpus_path)
    destination = Path(output)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8") as handle:
            handle.write(
                json.dumps(payload, indent=2, sort_keys=True) + "\n"
            )
    except FileExistsError as exc:
        raise ValidationContractError(
            f"refusing to overwrite local validation benchmark: {destination}"
        ) from exc
    return payload


def load_local_validation_benchmark_corpus(
    path: str | Path,
) -> tuple[dict[str, Any], tuple[dict[str, str], ...]]:
    """Load the exact transparent eight-case corpus."""

    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValidationContractError(
            f"invalid local validation benchmark corpus: {exc}"
        ) from exc
    if not isinstance(payload, dict) or payload.get(
        "schema_version"
    ) != LOCAL_VALIDATION_BENCHMARK_CORPUS_SCHEMA_VERSION:
        raise ValidationContractError(
            "unsupported local validation benchmark corpus"
        )
    rows = payload.get("cases")
    if not isinstance(rows, list) or len(rows) != 8:
        raise ValidationContractError(
            "local validation benchmark requires exactly eight cases"
        )
    expected_fields = {
        "adapter",
        "benchmark_case_id",
        "case_type",
        "ground_truth",
        "static_status",
        "variant",
    }
    cases: list[dict[str, str]] = []
    for row in rows:
        if (
            not isinstance(row, Mapping)
            or set(row) != expected_fields
            or any(
                not isinstance(row[field], str) or not clean_text(row[field])
                for field in expected_fields
            )
        ):
            raise ValidationContractError(
                "local validation benchmark case is invalid"
            )
        normalized = {
            field: clean_text(row[field])
            for field in expected_fields
        }
        if normalized["ground_truth"] not in _GROUND_TRUTHS:
            raise ValidationContractError(
                "local validation benchmark ground truth is invalid"
            )
        cases.append(normalized)
    identities = {
        (case["case_type"], case["variant"])
        for case in cases
    }
    if identities != _EXPECTED_CASES:
        raise ValidationContractError(
            "local validation benchmark matrix is incomplete"
        )
    ids = [case["benchmark_case_id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValidationContractError(
            "local validation benchmark has duplicate case ids"
        )
    return payload, tuple(cases)


def _run_once(
    cases: Sequence[Mapping[str, str]],
    *,
    corpus_digest: str,
) -> dict[str, Any]:
    plans = []
    contexts = {}
    for case in cases:
        plan = build_validation_plan(_audit_case(case))
        plans.append(plan)
        context = ValidationExecutionContext.for_plan(
            plan,
            fixture_id=case["benchmark_case_id"],
            adapter=case["adapter"],
            source_revision=f"benchmark-corpus-sha256:{corpus_digest}",
            config={
                "benchmark_variant": case["variant"],
                "production_data": False,
            },
        )
        contexts[plan.plan_id] = context
    return run_validation_plan_bundle(
        plans,
        contexts=contexts,
        source_bundle_digest=corpus_digest,
    )


def _audit_case(case: Mapping[str, str]) -> dict[str, Any]:
    return {
        "case_id": case["benchmark_case_id"],
        "case_type": case["case_type"],
        "status": case["static_status"],
        "review_priority": "high",
        "file": (
            "local_path_fixture.py"
            if case["case_type"] == "path_traversal_possible"
            else "local_idor_fixture.py"
        ),
        "line": 1,
        "rule_id": "BELIEF_LOCAL_VALIDATION_BENCHMARK",
        "cwe": (
            "CWE-22"
            if case["case_type"] == "path_traversal_possible"
            else "CWE-639"
        ),
        "source": "controlled_fixture_input",
        "sink": "local_fixture_sink",
        "missing_guarantees": ["local_oracle_not_observed"],
        "route_context": {
            "framework": "direct_python_fixture",
            "route": f"/{case['benchmark_case_id']}",
        },
        "structured_dataflow": {
            "schema_version": "belief.dataflow_evidence.v1",
            "source": {"symbol": "controlled_fixture_input"},
            "sink": {"symbol": "local_fixture_sink"},
            "ordered_nodes": [
                {"symbol": "controlled_fixture_input"},
                {"symbol": "local_fixture_sink"},
            ],
            "guard_applicability": {
                "applicable": case["static_status"] == "protected",
            },
        },
        "metadata": {
            "local_benchmark_variant": case["variant"],
        },
    }


def _stage_metrics(
    cases: Sequence[Mapping[str, str]],
    result_bundle: Mapping[str, Any],
) -> dict[str, Any]:
    result_by_id = {
        str(result["subject_id"]): str(result["outcome"])
        for result in result_bundle["results"]
    }
    static_predictions = {
        case["benchmark_case_id"]: (
            "negative"
            if case["static_status"]
            in {"protected", "false_positive_likely"}
            else "positive"
        )
        for case in cases
    }
    plan_predictions = {
        case["benchmark_case_id"]: (
            "negative"
            if case["static_status"]
            in {"protected", "false_positive_likely"}
            else "abstain"
        )
        for case in cases
    }
    result_predictions = {
        case_id: _outcome_prediction(outcome)
        for case_id, outcome in result_by_id.items()
    }
    execution_metrics = result_bundle["metrics"]
    return {
        "static_only": _classification_metrics(
            cases,
            static_predictions,
            evidence_gap_resolution_rate=0.0,
            functional_regression_count=0,
        ),
        "after_validation_plan": _classification_metrics(
            cases,
            plan_predictions,
            evidence_gap_resolution_rate=0.0,
            functional_regression_count=0,
        ),
        "after_validation_result": _classification_metrics(
            cases,
            result_predictions,
            evidence_gap_resolution_rate=float(
                execution_metrics["evidence_gap_resolution_rate"]
            ),
            functional_regression_count=sum(
                result["metadata"]["execution"]["baseline_passed"] is False
                and next(
                    case["variant"]
                    for case in cases
                    if case["benchmark_case_id"]
                    == result["subject_id"]
                )
                != "ambiguous"
                for result in result_bundle["results"]
            ),
        ),
    }


def _classification_metrics(
    cases: Sequence[Mapping[str, str]],
    predictions: Mapping[str, str],
    *,
    evidence_gap_resolution_rate: float,
    functional_regression_count: int,
) -> dict[str, Any]:
    values = []
    for case in cases:
        prediction = predictions.get(
            case["benchmark_case_id"],
            "abstain",
        )
        if prediction not in _PREDICTIONS:
            raise ValidationContractError(
                "local validation benchmark prediction is invalid"
            )
        values.append((case["ground_truth"], prediction))
    known = [
        item for item in values if item[0] != "ambiguous"
    ]
    true_positive = sum(
        truth == "vulnerable" and prediction == "positive"
        for truth, prediction in known
    )
    false_positive = sum(
        truth == "safe" and prediction == "positive"
        for truth, prediction in known
    )
    true_negative = sum(
        truth == "safe" and prediction == "negative"
        for truth, prediction in known
    )
    false_negative = sum(
        truth == "vulnerable" and prediction != "positive"
        for truth, prediction in known
    )
    predicted_positive = true_positive + false_positive
    actual_positive = sum(
        truth == "vulnerable" for truth, _prediction in known
    )
    abstentions = sum(
        prediction == "abstain" for _truth, prediction in values
    )
    return {
        "known_ground_truth_count": len(known),
        "true_positive_count": true_positive,
        "false_positive_count": false_positive,
        "true_negative_count": true_negative,
        "false_negative_count": false_negative,
        "precision": round(
            true_positive / predicted_positive,
            6,
        )
        if predicted_positive
        else 0.0,
        "recall": round(
            true_positive / actual_positive,
            6,
        )
        if actual_positive
        else 0.0,
        "protected_false_positive_count": false_positive,
        "abstention_count": abstentions,
        "abstention_rate": round(abstentions / len(values), 6),
        "evidence_gap_resolution_rate": round(
            evidence_gap_resolution_rate,
            6,
        ),
        "functional_regression_count": functional_regression_count,
    }


def _outcome_prediction(outcome: str) -> str:
    if outcome == "bypassed":
        return "positive"
    if outcome in {"enforced", "false_positive"}:
        return "negative"
    return "abstain"


def _case_results(
    cases: Sequence[Mapping[str, str]],
    result_bundle: Mapping[str, Any],
) -> list[dict[str, Any]]:
    results = {
        result["subject_id"]: result
        for result in result_bundle["results"]
    }
    output = []
    for case in cases:
        result = results[case["benchmark_case_id"]]
        output.append({
            "benchmark_case_id": case["benchmark_case_id"],
            "case_type": case["case_type"],
            "variant": case["variant"],
            "ground_truth": case["ground_truth"],
            "static_status": case["static_status"],
            "validation_strategy": result["metadata"][
                "validation_strategy"
            ],
            "validation_outcome": result["outcome"],
            "baseline_passed": result["metadata"]["execution"][
                "baseline_passed"
            ],
            "oracle_evaluated_count": result["metadata"]["execution"][
                "oracle_evaluated_count"
            ],
            "limitations": result["metadata"]["limitations"],
        })
    return output


__all__ = [
    "LOCAL_VALIDATION_BENCHMARK_CORPUS_SCHEMA_VERSION",
    "LOCAL_VALIDATION_BENCHMARK_SCHEMA_VERSION",
    "load_local_validation_benchmark_corpus",
    "run_local_validation_benchmark",
    "write_local_validation_benchmark",
]
