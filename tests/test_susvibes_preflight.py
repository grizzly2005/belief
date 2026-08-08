"""Contracts for the read-only SusVibes agent preflight."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from belief.benchmark.susvibes_experiment import (
    write_susvibes_experiment_manifest,
)
from belief.benchmark.susvibes_preflight import (
    load_ready_susvibes_agent_preflight,
    run_susvibes_agent_preflight,
    write_susvibes_agent_preflight,
)


pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update({
        "GIT_AUTHOR_EMAIL": "preflight@example.invalid",
        "GIT_AUTHOR_NAME": "BELIEF preflight",
        "GIT_COMMITTER_EMAIL": "preflight@example.invalid",
        "GIT_COMMITTER_NAME": "BELIEF preflight",
    })
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        env=env,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8",
        errors="replace",
    )
    return completed.stdout.decode("utf-8", errors="replace").strip()


def test_fable_target_snapshot_pins_compatible_cli_release():
    payload = json.loads(
        (
            ROOT
            / "benchmark_susvibes"
            / "claude_code_target_2026-07-23.json"
        ).read_text(encoding="utf-8")
    )

    assert payload["package"] == "@anthropic-ai/claude-code"
    assert payload["version"] == "2.1.218"
    assert payload["fable_5_minimum_version"] == "2.1.170"
    assert payload["npm_dist_integrity"].startswith("sha512-")


def _fixture(
    tmp_path: Path,
) -> tuple[Path, Path, Path, Path, Path]:
    root = tmp_path / "susvibes"
    harness = root / "evaluation_harness" / "claude_code"
    harness.mkdir(parents=True)
    (harness / "placeholder.py").write_text(
        "# official harness fixture\n",
        encoding="utf-8",
    )
    dataset_dir = root / "datasets" / "default"
    dataset_dir.mkdir(parents=True)
    dataset = dataset_dir / "susvibes_dataset.jsonl"
    dataset.write_text(
        json.dumps({
            "instance_id": "example__project_deadbeef",
            "project": "example/project",
            "base_commit": "a" * 40,
            "language": "python",
            "image_name": "example/susvibes:fixture",
            "problem_statement": "Implement a safe asset reader.",
            "security_patch": "diff --git a/app.py b/app.py\n",
            "cwe_ids": ["CWE-22"],
        }, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    _git(root, "init", "--quiet")
    _git(root, "add", ".")
    _git(root, "commit", "--quiet", "-m", "pinned fixture")
    commit = _git(root, "rev-parse", "HEAD")

    manifest = tmp_path / "experiment.json"
    write_susvibes_experiment_manifest(
        dataset,
        manifest,
        susvibes_commit=commit,
        smoke_size=1,
        canary_size=1,
        batch_size=1,
    )
    runner = tmp_path / "runner.py"
    runner.write_text("# pinned runner\n", encoding="utf-8")
    results = tmp_path / "isolated-results"
    return root, dataset, manifest, runner, results


def _ready_kwargs(
    tmp_path: Path,
) -> tuple[dict[str, object], tuple[Path, Path, Path, Path, Path]]:
    fixture = _fixture(tmp_path)
    root, dataset, manifest, runner, results = fixture
    kwargs: dict[str, object] = {
        "susvibes_root": root,
        "dataset": dataset,
        "experiment_manifest": manifest,
        "cohort": "smoke",
        "results_dir": results,
        "model": "claude-fable-5",
        "claude_version": "2.1.218",
        "minimum_free_gib": 1.0,
        "acknowledge_agent_network": True,
        "acknowledge_scoped_credential": True,
        "environment": {
            "ANTHROPIC_API_KEY": "never-write-this-secret"
        },
        "docker_probe": lambda: (True, "27.0.0|x86_64"),
        "disk_free_probe": lambda _path: 500 * 1024 ** 3,
        "runner_path": runner,
    }
    return kwargs, fixture


def test_ready_preflight_is_bound_and_never_reports_secret(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, dataset, manifest, runner, results = fixture

    payload = run_susvibes_agent_preflight(**kwargs)

    assert payload["ready_for_execution"] is True
    assert payload["required_failures"] == []
    assert payload["binding"]["susvibes_commit"] == _git(
        root,
        "rev-parse",
        "HEAD",
    )
    assert payload["binding"]["selected_case_count"] == 1
    assert payload["binding"]["cohort_case_count"] == 1
    assert payload["binding"]["start_index"] == 0
    assert payload["binding"]["requested_num_instances"] == 1
    assert payload["binding"]["feedback_mode"] == "belief"
    assert payload["binding"]["max_stop_blocks"] == 1
    assert payload["binding"]["scoped_credential_acknowledged"] is True
    assert payload["boundaries"]["docker_started"] is False
    assert payload["comparability"]["susvibes_secpass_measured"] is False
    warnings = [
        check["id"]
        for check in payload["checks"]
        if check["status"] == "warning"
    ]
    assert warnings == ["provider_model_availability"]
    provider_check = next(
        check
        for check in payload["checks"]
        if check["id"] == "provider_model_availability"
    )
    assert provider_check["evidence"]["published_model_id_verified"] is True
    assert (
        provider_check["evidence"]["live_credential_access_verified"]
        is False
    )
    serialized = json.dumps(payload)
    assert "never-write-this-secret" not in serialized
    assert "ANTHROPIC_API_KEY" in serialized

    report = tmp_path / "ready-preflight.json"
    written = write_susvibes_agent_preflight(report, **kwargs)
    provenance = load_ready_susvibes_agent_preflight(
        report,
        susvibes_root=root,
        dataset=dataset,
        experiment_manifest=manifest,
        cohort="smoke",
        results_dir=results,
        model="claude-fable-5",
        claude_version="2.1.218",
        runner_path=runner,
        scoped_credential_acknowledged=True,
    )
    assert provenance["report_digest"] == written["report_digest"]
    assert len(provenance["report_sha256"]) == 64


def test_ready_preflight_binds_true_no_feedback_control(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, dataset, manifest, runner, results = fixture
    kwargs.update({
        "feedback_mode": "none",
        "max_stop_blocks": 0,
    })
    report = tmp_path / "baseline-preflight.json"

    written = write_susvibes_agent_preflight(report, **kwargs)
    provenance = load_ready_susvibes_agent_preflight(
        report,
        susvibes_root=root,
        dataset=dataset,
        experiment_manifest=manifest,
        cohort="smoke",
        results_dir=results,
        model="claude-fable-5",
        claude_version="2.1.218",
        runner_path=runner,
        feedback_mode="none",
        max_stop_blocks=0,
        scoped_credential_acknowledged=True,
    )

    assert written["binding"]["feedback_mode"] == "none"
    assert written["binding"]["max_stop_blocks"] == 0
    assert provenance["feedback_mode"] == "none"
    with pytest.raises(ValueError, match="feedback_mode|max_stop_blocks"):
        load_ready_susvibes_agent_preflight(
            report,
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=manifest,
            cohort="smoke",
            results_dir=results,
            model="claude-fable-5",
            claude_version="2.1.218",
            runner_path=runner,
            feedback_mode="belief",
            max_stop_blocks=1,
            scoped_credential_acknowledged=True,
        )


def test_preflight_reports_all_environment_blockers(tmp_path):
    kwargs, _fixture_paths = _ready_kwargs(tmp_path)
    kwargs.update({
        "acknowledge_agent_network": False,
        "acknowledge_scoped_credential": False,
        "environment": {},
        "docker_probe": lambda: (False, "daemon stopped"),
        "disk_free_probe": lambda _path: 512,
    })

    payload = run_susvibes_agent_preflight(**kwargs)

    assert payload["ready_for_execution"] is False
    assert payload["status"] == "not_ready"
    assert set(payload["required_failures"]) >= {
        "workspace_storage",
        "docker_daemon_ready",
        "container_agent_credentials",
        "explicit_agent_network_acknowledgement",
        "explicit_scoped_credential_acknowledgement",
    }
    assert payload["comparability"]["preflight_is_benchmark_result"] is False


def test_preflight_rejects_results_inside_pinned_checkout(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, _dataset, _manifest, _runner, _results = fixture
    kwargs["results_dir"] = root / "generated-results"

    payload = run_susvibes_agent_preflight(**kwargs)

    assert payload["ready_for_execution"] is False
    assert "results_outside_pinned_checkout" in payload[
        "required_failures"
    ]


def test_preflight_rejects_unsafe_model_identifier(tmp_path):
    kwargs, _fixture_paths = _ready_kwargs(tmp_path)
    kwargs["model"] = "claude-model\nINJECTED=value"

    payload = run_susvibes_agent_preflight(**kwargs)

    assert payload["ready_for_execution"] is False
    assert "exact_model_identifier" in payload["required_failures"]


def test_preflight_rejects_claude_code_too_old_for_fable_5(tmp_path):
    kwargs, _fixture_paths = _ready_kwargs(tmp_path)
    kwargs["claude_version"] = "2.1.83"

    payload = run_susvibes_agent_preflight(**kwargs)

    assert payload["ready_for_execution"] is False
    assert "fable_5_claude_code_compatibility" in payload[
        "required_failures"
    ]


def test_ready_report_rechecks_current_storage(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, dataset, manifest, runner, results = fixture
    kwargs["minimum_free_gib"] = 1_000_000_000.0
    kwargs["disk_free_probe"] = (
        lambda _path: 2_000_000_000 * 1024 ** 3
    )
    report = tmp_path / "ready-preflight.json"
    write_susvibes_agent_preflight(report, **kwargs)

    with pytest.raises(ValueError, match="storage readiness changed"):
        load_ready_susvibes_agent_preflight(
            report,
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=manifest,
            cohort="smoke",
            results_dir=results,
            model="claude-fable-5",
            claude_version="2.1.218",
            runner_path=runner,
            scoped_credential_acknowledged=True,
        )


def test_ready_report_rejects_tampering_and_input_drift(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, dataset, manifest, runner, results = fixture
    report = tmp_path / "ready-preflight.json"
    write_susvibes_agent_preflight(report, **kwargs)
    payload = json.loads(report.read_text(encoding="utf-8"))
    payload["binding"]["model"] = "different-model"
    report.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="digest mismatch"):
        load_ready_susvibes_agent_preflight(
            report,
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=manifest,
            cohort="smoke",
            results_dir=results,
            model="claude-fable-5",
            claude_version="2.1.218",
            runner_path=runner,
            scoped_credential_acknowledged=True,
        )


def test_ready_report_rejects_dirty_checkout(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, dataset, manifest, runner, results = fixture
    report = tmp_path / "ready-preflight.json"
    write_susvibes_agent_preflight(report, **kwargs)
    (root / "local-change.txt").write_text(
        "must invalidate readiness\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="worktree is dirty"):
        load_ready_susvibes_agent_preflight(
            report,
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=manifest,
            cohort="smoke",
            results_dir=results,
            model="claude-fable-5",
            claude_version="2.1.218",
            runner_path=runner,
            scoped_credential_acknowledged=True,
        )


def test_ready_report_is_bound_to_exact_execution_slice(tmp_path):
    kwargs, fixture = _ready_kwargs(tmp_path)
    root, dataset, manifest, runner, results = fixture
    report = tmp_path / "ready-preflight.json"
    write_susvibes_agent_preflight(report, **kwargs)

    with pytest.raises(
        ValueError,
        match="requested_num_instances",
    ):
        load_ready_susvibes_agent_preflight(
            report,
            susvibes_root=root,
            dataset=dataset,
            experiment_manifest=manifest,
            cohort="smoke",
            start_index=0,
            num_instances=2,
            results_dir=results,
            model="claude-fable-5",
            claude_version="2.1.218",
            runner_path=runner,
            scoped_credential_acknowledged=True,
        )


def test_preflight_writer_refuses_to_overwrite(tmp_path):
    kwargs, _fixture_paths = _ready_kwargs(tmp_path)
    report = tmp_path / "preflight.json"
    report.write_text("preserve\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        write_susvibes_agent_preflight(report, **kwargs)

    assert report.read_text(encoding="utf-8") == "preserve\n"
