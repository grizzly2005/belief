"""Contracts for merging completed BELIEF SusVibes batch runs."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    load_experiment_cohort,
    write_susvibes_experiment_manifest,
)
from belief.benchmark.susvibes_predictions import (
    write_merged_susvibes_predictions,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]


def _experiment(
    tmp_path: Path,
) -> tuple[Path, Path, list[str], dict[str, str]]:
    dataset = tmp_path / "susvibes_dataset.jsonl"
    rows = [
        {
            "instance_id": f"owner__project_{index:040x}",
            "project": f"owner/project{index}",
            "base_commit": f"{index + 1:040x}",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": [f"CWE-{20 + index}"],
            "language": "python",
            "image_name": f"example/image:{index}",
            "problem_statement": f"Implement feature {index}.",
        }
        for index in range(5)
    ]
    dataset.write_text(
        "".join(
            json.dumps(row, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )
    manifest = tmp_path / "experiment.json"
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit="a" * 40,
        smoke_size=1,
        canary_size=3,
        batch_size=2,
    )
    ids, selection = load_experiment_cohort(
        manifest,
        "full",
        dataset=dataset,
    )
    return dataset, manifest, ids, selection


def _write_batch(
    run_dir: Path,
    *,
    ids: list[str],
    all_ids: list[str],
    selection: dict[str, str],
    model: str = "claude-fable-5",
    suspected: int = 0,
    verified_preflight: bool = True,
    schema_version: int = 2,
    feedback_mode: str = "belief",
    max_stop_blocks: int = 1,
) -> Path:
    run_dir.mkdir()
    start_index = all_ids.index(ids[0])
    assert all_ids[start_index:start_index + len(ids)] == ids
    assert schema_version in {2, 3}
    model_name = (
        f"claude-code-baseline/{model}"
        if feedback_mode == "none"
        else f"belief-claude-hook/{model}"
    )
    records = []
    tasks = []
    for index, instance_id in enumerate(ids):
        patch = (
            "diff --git a/app.py b/app.py\n"
            f"+SAFE_{instance_id[-4:]} = {index}\n"
        )
        record = {
            "instance_id": instance_id,
            "model_name_or_path": model_name,
            "model_patch": patch,
        }
        records.append(record)
        tasks.append({
            "instance_id": instance_id,
            "image_name": f"example/{instance_id}",
            "problem_statement_sha256": "1" * 64,
            "agent_visible_fields": [
                "image_name",
                "instance_id",
                "problem_statement",
            ],
        })
        task_dir = run_dir / instance_id
        task_dir.mkdir()
        patch_bytes = patch.encode("utf-8")
        (task_dir / "result.json").write_text(
            json.dumps({
                "schema_version": (
                    f"belief.susvibes_agent_result.v{schema_version}"
                ),
                "instance_id": instance_id,
                "model": model,
                **(
                    {
                        "feedback_mode": feedback_mode,
                        "max_stop_blocks": max_stop_blocks,
                        "belief_feedback": {
                            "enabled": feedback_mode == "belief",
                            "configured_max_blocks": max_stop_blocks,
                            "review_count": 0,
                            "state_count": 0,
                            "feedback_block_count": 0,
                            "feedback_delivered": False,
                            "terminal_statuses": [],
                        },
                    }
                    if schema_version == 3
                    else {}
                ),
                "model_identity_status": "matched",
                "automatic_model_fallback_configured": False,
                "claude_code_version": "2.1.218",
                "claude_code_version_observed": "2.1.218",
                "agent_return_code": 0,
                "agent_success": True,
                "agent_stream": {
                    "valid_json_event_count": 1,
                    "invalid_json_line_count": 0,
                    "assistant_models_observed": [model],
                    "stop_reasons_observed": ["end_turn"],
                    "model_refusal_observed": False,
                    "refusal_categories_observed": [],
                    "api_retry_event_count": 0,
                    "result_event_count": 1,
                    "result_subtypes_observed": ["success"],
                    "result_error_observed": False,
                    **(
                        {
                            "result_accounting": {
                                "total_cost_usd": 0.1,
                                "duration_ms": 1000,
                                "duration_api_ms": 800,
                                "num_turns": 1,
                                "usage": {
                                    "input_tokens": 100,
                                    "output_tokens": 20,
                                },
                                "invalid_fields": [],
                            },
                        }
                        if schema_version == 3
                        else {}
                    ),
                },
                "policy_violation_suspected": index < suspected,
                "model_patch_sha256": hashlib.sha256(
                    patch_bytes
                ).hexdigest(),
                "model_patch_bytes": len(patch_bytes),
                "prediction": record,
            }, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    predictions = run_dir / "predictions.jsonl"
    predictions.write_text(
        "".join(
            json.dumps(record, sort_keys=True) + "\n"
            for record in records
        ),
        encoding="utf-8",
    )
    task_digest = hashlib.sha256(
        json.dumps(
            ids,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()
    (run_dir / "plan.json").write_text(
        json.dumps({
            "schema_version": (
                f"belief.susvibes_agent_plan.v{schema_version}"
            ),
            **(
                {
                    "mode": (
                        "claude_code_without_belief_feedback"
                        if feedback_mode == "none"
                        else "claude_code_with_belief_stop_hook"
                    ),
                    "feedback_mode": feedback_mode,
                }
                if schema_version == 3
                else {}
            ),
            "results_dir": str(run_dir.resolve()),
            "dataset_sha256": selection["dataset_sha256"],
            "susvibes_commit": selection["susvibes_commit"],
            "selection": selection,
            "preflight": {
                "status": (
                    "verified_ready"
                    if verified_preflight
                    else "not_required_for_dry_run"
                ),
                "report_sha256": "2" * 64,
                "report_digest": "3" * 64,
                "cohort": "full",
                "cohort_case_count": len(all_ids),
                "start_index": start_index,
                "num_instances": len(ids),
                "selected_instance_ids_sha256": task_digest,
                **(
                    {
                        "feedback_mode": feedback_mode,
                        "max_stop_blocks": max_stop_blocks,
                    }
                    if schema_version == 3
                    else {}
                ),
            },
            "model": model,
            "model_selection": {
                "requested_model": model,
                "claude_cli_argument": "--model",
                "automatic_fallback_configured": False,
            },
            "claude_code_version": "2.1.218",
            "max_stop_blocks": max_stop_blocks,
            "task_count": len(ids),
            "tasks": tasks,
            "boundaries": {
                "benchmark_oracle_forwarded": False,
                "reference_patch_forwarded": False,
                "hidden_tests_forwarded": False,
                "workspace_git_history_removed": True,
                "git_history_lookup_blocked": True,
                "web_tools_blocked": True,
                "builtin_tool_allowlist_enforced": True,
                "mcp_servers_enabled": False,
                "browser_integration_enabled": False,
                "session_persistence_enabled": False,
                "automatic_model_fallback_configured": False,
                **(
                    {
                        "belief_stop_hook_enabled": (
                            feedback_mode == "belief"
                        ),
                    }
                    if schema_version == 3
                    else {}
                ),
            },
        }, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (run_dir / "summary.json").write_text(
        json.dumps({
            "schema_version": (
                f"belief.susvibes_agent_run.v{schema_version}"
            ),
            "task_count": len(ids),
            "successful_agent_runs": len(ids),
            "model_identity_verified_runs": len(ids),
            "model_refusal_observed_count": 0,
            "api_retry_event_count": 0,
            "automatic_model_fallback_configured": False,
            **(
                {
                    "feedback_mode": feedback_mode,
                    "max_stop_blocks": max_stop_blocks,
                    "belief_feedback_review_count": 0,
                    "belief_feedback_block_count": 0,
                    "belief_feedback_delivered_runs": 0,
                    "accounting": {
                        "reported_total_cost_usd": round(
                            0.1 * len(ids),
                            12,
                        ),
                        "cost_reported_task_count": len(ids),
                        "input_tokens": 100 * len(ids),
                        "output_tokens": 20 * len(ids),
                        "cache_creation_input_tokens": 0,
                        "cache_read_input_tokens": 0,
                        "invalid_accounting_task_count": 0,
                    },
                }
                if schema_version == 3
                else {}
            ),
            "policy_violation_suspected_count": suspected,
            "predictions": str(predictions.resolve()),
        }, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return run_dir


def test_merge_validates_batches_and_restores_frozen_order(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    first = _write_batch(
        tmp_path / "batch-1",
        ids=ids[:2],
        all_ids=ids,
        selection=selection,
    )
    second = _write_batch(
        tmp_path / "batch-2",
        ids=ids[2:],
        all_ids=ids,
        selection=selection,
        suspected=1,
    )
    output = tmp_path / "merged" / "predictions.jsonl"
    provenance = tmp_path / "merged" / "provenance.json"

    payload = write_merged_susvibes_predictions(
        output,
        provenance,
        experiment_manifest=manifest,
        dataset=dataset,
        cohort="full",
        run_dirs=[second, first],
    )

    records = [
        json.loads(line)
        for line in output.read_text(encoding="utf-8").splitlines()
    ]
    assert [record["instance_id"] for record in records] == ids
    assert payload["coverage"]["complete"] is True
    assert payload["coverage"]["missing_case_count"] == 0
    assert payload["output"]["prediction_count"] == 5
    assert payload["quality_flags"][
        "policy_violation_suspected_count"
    ] == 1
    assert payload["quality_flags"][
        "anti_cheating_adjudication_required"
    ] is True
    assert payload["quality_flags"]["suspected_cases_removed"] is False
    assert payload["quality_flags"][
        "model_identity_verified_run_count"
    ] == 5
    assert payload["quality_flags"]["model_refusal_observed_count"] == 0
    assert payload["quality_flags"]["api_retry_event_count"] == 0
    assert payload["quality_flags"][
        "automatic_model_fallback_configured"
    ] is False
    assert payload["output"]["predictions_sha256"] == hashlib.sha256(
        output.read_bytes()
    ).hexdigest()
    assert json.loads(provenance.read_text(encoding="utf-8")) == payload


def test_merge_accepts_explicit_no_feedback_arm(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    baseline = _write_batch(
        tmp_path / "baseline",
        ids=ids,
        all_ids=ids,
        selection=selection,
        schema_version=3,
        feedback_mode="none",
        max_stop_blocks=0,
    )

    payload = write_merged_susvibes_predictions(
        tmp_path / "baseline-predictions.jsonl",
        tmp_path / "baseline-provenance.json",
        experiment_manifest=manifest,
        dataset=dataset,
        cohort="full",
        run_dirs=[baseline],
    )

    assert payload["execution"]["feedback_mode"] == "none"
    assert payload["execution"]["max_stop_blocks"] == 0
    assert payload["execution"]["model_name_or_path"].startswith(
        "claude-code-baseline/"
    )


def test_merge_rejects_duplicate_predictions(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    first = _write_batch(
        tmp_path / "batch-1",
        ids=ids[:2],
        all_ids=ids,
        selection=selection,
    )
    duplicate = _write_batch(
        tmp_path / "batch-duplicate",
        ids=ids[:2],
        all_ids=ids,
        selection=selection,
    )

    with pytest.raises(ValueError, match="duplicate prediction"):
        write_merged_susvibes_predictions(
            tmp_path / "predictions.jsonl",
            tmp_path / "provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[first, duplicate],
            require_complete=False,
        )


def test_merge_rejects_missing_by_default_and_labels_partial(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    first = _write_batch(
        tmp_path / "batch-1",
        ids=ids[:2],
        all_ids=ids,
        selection=selection,
    )

    with pytest.raises(ValueError, match="3 missing"):
        write_merged_susvibes_predictions(
            tmp_path / "rejected.jsonl",
            tmp_path / "rejected-provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[first],
        )

    payload = write_merged_susvibes_predictions(
        tmp_path / "partial.jsonl",
        tmp_path / "partial-provenance.json",
        experiment_manifest=manifest,
        dataset=dataset,
        cohort="full",
        run_dirs=[first],
        require_complete=False,
    )
    assert payload["coverage"]["complete"] is False
    assert payload["coverage"]["missing_case_count"] == 3
    assert payload["coverage"]["required_complete"] is False


def test_merge_rejects_mixed_models_and_dry_run_plans(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    first = _write_batch(
        tmp_path / "batch-1",
        ids=ids[:2],
        all_ids=ids,
        selection=selection,
    )
    mixed = _write_batch(
        tmp_path / "batch-mixed",
        ids=ids[2:],
        all_ids=ids,
        selection=selection,
        model="different-model",
    )
    with pytest.raises(ValueError, match="inconsistent execution settings"):
        write_merged_susvibes_predictions(
            tmp_path / "mixed.jsonl",
            tmp_path / "mixed-provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[first, mixed],
        )

    dry = _write_batch(
        tmp_path / "batch-dry",
        ids=ids[2:],
        all_ids=ids,
        selection=selection,
        verified_preflight=False,
    )
    with pytest.raises(ValueError, match="verified ready preflight"):
        write_merged_susvibes_predictions(
            tmp_path / "dry.jsonl",
            tmp_path / "dry-provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[first, dry],
        )


def test_merge_rejects_result_tampering(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    batch = _write_batch(
        tmp_path / "batch",
        ids=ids,
        all_ids=ids,
        selection=selection,
    )
    result_path = batch / ids[0] / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["model_patch_sha256"] = "0" * 64
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="patch hash mismatch"):
        write_merged_susvibes_predictions(
            tmp_path / "predictions.jsonl",
            tmp_path / "provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[batch],
        )


def test_merge_rejects_model_identity_drift_and_fallback(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    drifted = _write_batch(
        tmp_path / "batch-drifted",
        ids=ids,
        all_ids=ids,
        selection=selection,
    )
    result_path = drifted / ids[0] / "result.json"
    result = json.loads(result_path.read_text(encoding="utf-8"))
    result["agent_stream"]["assistant_models_observed"] = [
        "claude-sonnet-5"
    ]
    result_path.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="observed model mismatch"):
        write_merged_susvibes_predictions(
            tmp_path / "drifted.jsonl",
            tmp_path / "drifted-provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[drifted],
        )

    fallback = _write_batch(
        tmp_path / "batch-fallback",
        ids=ids,
        all_ids=ids,
        selection=selection,
    )
    summary_path = fallback / "summary.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    summary["automatic_model_fallback_configured"] = True
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="configured model fallback"):
        write_merged_susvibes_predictions(
            tmp_path / "fallback.jsonl",
            tmp_path / "fallback-provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[fallback],
        )


def test_merge_outputs_are_create_only(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    batch = _write_batch(
        tmp_path / "batch",
        ids=ids,
        all_ids=ids,
        selection=selection,
    )
    output = tmp_path / "predictions.jsonl"
    output.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_merged_susvibes_predictions(
            output,
            tmp_path / "provenance.json",
            experiment_manifest=manifest,
            dataset=dataset,
            cohort="full",
            run_dirs=[batch],
        )

    assert output.read_text(encoding="utf-8") == "preserve\n"


def test_merge_cli_creates_complete_predictions(tmp_path):
    dataset, manifest, ids, selection = _experiment(tmp_path)
    first = _write_batch(
        tmp_path / "batch-1",
        ids=ids[:2],
        all_ids=ids,
        selection=selection,
    )
    second = _write_batch(
        tmp_path / "batch-2",
        ids=ids[2:],
        all_ids=ids,
        selection=selection,
    )
    output = tmp_path / "merged.jsonl"
    provenance = tmp_path / "merged-provenance.json"

    completed = subprocess.run(
        [
            sys.executable,
            "scripts/merge_susvibes_predictions.py",
            "--experiment-manifest",
            str(manifest),
            "--dataset",
            str(dataset),
            "--cohort",
            "full",
            "--run-dir",
            str(first),
            "--run-dir",
            str(second),
            "--output",
            str(output),
            "--provenance-output",
            str(provenance),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    assert summary["prediction_count"] == 5
    assert summary["complete"] is True
    assert output.is_file()
    assert provenance.is_file()
