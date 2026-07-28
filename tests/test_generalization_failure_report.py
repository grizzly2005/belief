"""Contracts for evaluator-only generalization failure reports."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from belief.generalization.failure_report import (
    GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION,
    FailureCaseAttribution,
    load_generalization_failure_report,
    validate_generalization_failure_report,
    write_generalization_failure_report,
)


pytestmark = pytest.mark.security


def _digest(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _payload():
    category = "guard_not_recognized"
    payload = {
        "schema_version": GENERALIZATION_FAILURE_REPORT_SCHEMA_VERSION,
        "mode": "evaluator_only_development_failure_attribution",
        "development_cohort": {
            "name": "canary",
            "case_count": 1,
            "ordered_ids_sha256": "1" * 64,
        },
        "inputs": {
            "dataset_name": "dataset.jsonl",
            "dataset_sha256": "2" * 64,
            "manifest_name": "manifest.json",
            "manifest_sha256": "3" * 64,
            "manifest_digest": "4" * 64,
            "baseline_name": "baseline.json",
            "baseline_sha256": "5" * 64,
            "baseline_digest": "6" * 64,
            "reviewer_source_sha256": "7" * 64,
            "manual_attribution_sha256": "8" * 64,
        },
        "baseline_metrics": {
            "case_count": 1,
            "paired_warning_discrimination_count": 0,
        },
        "case_count": 1,
        "cases": [
            {
                "development_case_number": 1,
                "id": "development-case",
                "project": "example/project",
                "commit": "9" * 40,
                "cwe_ids": ["CWE-1"],
                "cve_id": "",
                "outcome": "both_silent",
                "primary_category": category,
                "first_failed_stage": "guard_modeling",
                "blocked_stages": ["semantic_comparison", "verdict"],
                "available_evidence": ["candidate analysis"],
                "missing_evidence": ["same-value guard effect"],
                "files": ["package/module.py"],
                "functions": ["def parse(value):"],
                "security_patch_sha256": "a" * 64,
                "semantic_primitive": "same_value_bound_guard",
                "root_cause_identity": "b" * 64,
                "general_fix_possible": True,
                "overfit_risk": "medium",
                "estimated_cost": "medium",
                "baseline_observation": {
                    "analysis_succeeded": True,
                    "vulnerable_warned": False,
                    "secure_warning_false_positive": False,
                    "paired_warning_discriminated": False,
                    "vulnerable_actionable_count": 0,
                    "secure_actionable_count": 0,
                    "errors": [],
                },
            }
        ],
        "aggregate": {
            "category_frequency": {category: 1},
            "outcome_frequency": {"both_silent": 1},
            "clusters": [
                {
                    "category": category,
                    "case_count": 1,
                    "project_count": 1,
                    "cwe_count": 1,
                    "evaluable_case_count": 1,
                    "paired_gain_ceiling_count": 1,
                    "general_fix_candidate_count": 1,
                    "transversality_score": 1,
                    "semantic_primitives": ["same_value_bound_guard"],
                }
            ],
            "top_three_categories": [category],
            "top_three_case_count": 1,
            "top_three_project_union_count": 1,
            "top_three_cwe_union_count": 1,
        },
        "boundaries": {
            "development_cases_only": True,
            "reserved_test_case_ids_emitted_or_used": False,
            "reserved_test_case_details_inspected": False,
            "reference_security_delta_used_by_evaluator": True,
            "reference_security_delta_forwarded_to_reviewer": False,
            "benchmark_labels_forwarded_to_reviewer": False,
            "manual_attribution_is_production_rule_input": False,
            "report_is_static_secpass_equivalent": False,
        },
    }
    payload["deterministic_digest"] = _digest(payload)
    return payload


def test_failure_case_attribution_rejects_unknown_category():
    with pytest.raises(ValueError, match="unknown generalization"):
        FailureCaseAttribution(
            primary_category="project_specific_guess",
            first_failed_stage="guard_modeling",
            blocked_stages=("verdict",),
            available_evidence=("candidate analysis",),
            missing_evidence=("guard effect",),
            semantic_primitive="same_value_guard",
            general_fix_possible=True,
            overfit_risk="medium",
            estimated_cost="medium",
        )


def test_failure_report_validates_complete_schema():
    payload = _payload()

    validated = validate_generalization_failure_report(
        payload,
        expected_case_count=1,
        expected_development_ids_sha256="1" * 64,
    )

    assert validated == payload
    assert validated is not payload


def test_failure_report_rejects_tampered_category_aggregate():
    payload = _payload()
    payload["aggregate"]["category_frequency"][
        "guard_not_recognized"
    ] = 2
    payload["deterministic_digest"] = _digest(
        {
            key: value
            for key, value in payload.items()
            if key != "deterministic_digest"
        }
    )

    with pytest.raises(ValueError, match="category frequency mismatch"):
        validate_generalization_failure_report(payload)


def test_failure_report_rejects_reserved_boundary_claim():
    payload = _payload()
    payload["boundaries"][
        "reserved_test_case_details_inspected"
    ] = True
    payload["deterministic_digest"] = _digest(
        {
            key: value
            for key, value in payload.items()
            if key != "deterministic_digest"
        }
    )

    with pytest.raises(ValueError, match="boundary must be false"):
        validate_generalization_failure_report(payload)


def test_failure_report_rejects_digest_tampering():
    payload = _payload()
    payload["cases"][0]["semantic_primitive"] = "changed_after_digest"

    with pytest.raises(ValueError, match="digest mismatch"):
        validate_generalization_failure_report(payload)


def test_failure_report_writer_is_create_only(tmp_path: Path):
    output = tmp_path / "failure-report.json"
    payload = _payload()
    payload.pop("deterministic_digest")

    written = write_generalization_failure_report(payload, output)
    loaded = load_generalization_failure_report(output)

    assert loaded == written
    original = output.read_bytes()
    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_generalization_failure_report(payload, output)
    assert output.read_bytes() == original


def test_failure_report_loader_rejects_non_object(tmp_path: Path):
    output = tmp_path / "failure-report.json"
    output.write_text("[]\n", encoding="utf-8")

    with pytest.raises(ValueError, match="must be an object"):
        load_generalization_failure_report(output)


def test_validation_does_not_mutate_input():
    payload = _payload()
    original = copy.deepcopy(payload)

    validate_generalization_failure_report(payload)

    assert payload == original
