from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "research" / "experiment-classification-v1.json"

EXPECTED_ROLES = {
    "internal_sanity",
    "public_development",
    "reserved_test",
    "external_blind",
}
EXPECTED_PROVENANCE = {
    "parsed_as_provided",
    "parsed_after_dedent",
    "parsed_after_bounded_recovery",
    "unparseable",
}


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _experiments_by_id(payload: dict[str, object]) -> dict[str, dict[str, object]]:
    experiments = payload["experiments"]
    assert isinstance(experiments, list)
    assert all(isinstance(experiment, dict) for experiment in experiments)
    return {str(experiment["experiment_id"]): experiment for experiment in experiments}


def test_manifest_is_classification_only_and_has_expected_experiments() -> None:
    payload = _manifest()

    assert payload["schema_version"] == "belief.research_experiment_classification.v1"
    assert payload["classification_only"] is True
    assert payload["existing_results_rerun"] is False
    assert payload["existing_results_overwritten"] is False
    assert payload["research_commits_integrated_into_core"] is False
    assert payload["reserved_cohort_opened"] is False
    assert payload["susvibes_holdout_opened"] is False
    assert set(payload["allowed_roles"]) == EXPECTED_ROLES
    assert set(payload["parser_recovery_provenance_vocabulary"]) == EXPECTED_PROVENANCE

    experiments = _experiments_by_id(payload)
    assert set(experiments) == {
        "web-synthetic-development-v2",
        "cyberseceval-v1-first-exposure",
        "cyberseceval-v2-public-tuned",
        "seccodebench-python-safety-preflight",
    }


def test_claim_eligibility_is_conservative() -> None:
    payload = _manifest()
    experiments = _experiments_by_id(payload)

    for experiment in experiments.values():
        assert experiment["role"] in EXPECTED_ROLES
        assert experiment["secpass_comparable"] is False
        assert experiment["external_blind"] is False
        assert experiment["dynamic_execution"] is False
        assert experiment["external_validation_claim_allowed"] is False
        if experiment["precision_eligible"]:
            assert experiment["negative_controls_present"] is True

    first_exposure = experiments["cyberseceval-v1-first-exposure"]
    assert first_exposure["interpretation_class"] == (
        "first_exposure_positive_only_sensitivity"
    )
    assert first_exposure["negative_controls_present"] is False
    assert first_exposure["precision_eligible"] is False

    tuned = experiments["cyberseceval-v2-public-tuned"]
    assert tuned["interpretation_class"] == "tuned_public_third_party_development_result"
    assert tuned["tuning_occurred_before_result"] is True
    assert tuned["negative_controls_present"] is False
    assert tuned["precision_eligible"] is False


def test_artifact_boundaries_record_missing_or_contradictory_evidence() -> None:
    experiments = _experiments_by_id(_manifest())

    synthetic = experiments["web-synthetic-development-v2"]
    assert synthetic["journal_declared_case_count"] == 48
    assert synthetic["verified_artifact_case_count"] == 32
    assert synthetic["case_count_consistent"] is False
    assert synthetic["precision_eligibility_scope"] == (
        "committed_32_case_development_artifact_only"
    )

    preflight = experiments["seccodebench-python-safety-preflight"]
    assert preflight["interpretation_class"] == "safety_preflight_only"
    assert preflight["artifact_status"] == (
        "branch_created_no_seccodebench_artifact_recorded"
    )
    assert preflight["verified_artifact_case_count"] == 0
    for field in (
        "artifact_commit",
        "artifact_path",
        "artifact_schema_version",
        "artifact_digest",
    ):
        assert preflight[field] is None


def test_parser_recovery_provenance_uses_exact_vocabulary() -> None:
    experiments = _experiments_by_id(_manifest())

    for experiment in experiments.values():
        provenance = set(experiment["parser_recovery_provenance"])
        mapping = set(experiment["parser_recovery_mapping"].values())
        assert provenance <= EXPECTED_PROVENANCE
        assert mapping <= EXPECTED_PROVENANCE
        assert mapping <= provenance

    assert set(
        experiments["cyberseceval-v2-public-tuned"]["parser_recovery_provenance"]
    ) == EXPECTED_PROVENANCE


def test_technical_conclusions_exclude_disallowed_claims_and_comparisons() -> None:
    experiments = _experiments_by_id(_manifest())
    conclusions = "\n".join(
        str(experiment[field])
        for experiment in experiments.values()
        for field in ("interpretation_class", "claim_boundary")
    ).lower()

    for disallowed in (
        "external validation",
        "generalization proved",
        "benchmark victory",
        "secpass comparison",
        "fable",
        "kimi",
    ):
        assert disallowed not in conclusions
