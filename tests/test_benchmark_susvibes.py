"""Contracts for the offline SusVibes paired-revision adapter."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from belief.benchmark.susvibes import (
    LocalGitCorpus,
    SUSVIBES_PAIRED_MODE,
    SusVibesThresholds,
    evaluate_susvibes_paired_benchmark,
    parse_security_diff,
)
from belief.static_analysis_pipeline import StaticAnalysisOptions, analyze_static_target
from scripts.prepare_susvibes_cache import (
    _cwe_values,
    _ensure_repository,
    _select_cases,
    _validate_manifest_output,
    prepare_cache,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]


def _git(repository: Path, *arguments: str) -> str:
    env = dict(os.environ)
    env.update(
        {
            "GIT_AUTHOR_EMAIL": "benchmark@example.invalid",
            "GIT_AUTHOR_NAME": "BELIEF benchmark",
            "GIT_COMMITTER_EMAIL": "benchmark@example.invalid",
            "GIT_COMMITTER_NAME": "BELIEF benchmark",
        }
    )
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        capture_output=True,
        check=False,
        env=env,
        text=True,
        timeout=15,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def _paired_fixture(tmp_path: Path) -> tuple[Path, Path]:
    cache = tmp_path / "repos"
    repository = cache / "example__assets"
    repository.mkdir(parents=True)
    _git(repository, "init", "--quiet")

    target = repository / "assets.py"
    target.write_text(
        "\n".join(
            [
                "import os",
                "",
                "def read_asset(root, path):",
                "    full_path = os.path.join(root, path)",
                "    return open(full_path).read()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _git(repository, "add", "assets.py")
    _git(repository, "commit", "--quiet", "-m", "vulnerable")
    vulnerable_commit = _git(repository, "rev-parse", "HEAD")

    target.write_text(
        "\n".join(
            [
                "import os",
                "",
                "def read_asset(root, path):",
                "    full_path = os.path.abspath(os.path.join(root, path))",
                "    common = os.path.commonpath([root, full_path])",
                "    if common != root:",
                "        raise ValueError('outside root')",
                "    return open(full_path).read()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    _git(repository, "add", "assets.py")
    _git(repository, "commit", "--quiet", "-m", "fixed")
    fixed_commit = _git(repository, "rev-parse", "HEAD")
    patch = _git(repository, "diff", vulnerable_commit, fixed_commit)

    dataset = tmp_path / "susvibes.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "instance_id": "example__assets_fixed",
                "project": "example/assets",
                "base_commit": fixed_commit,
                "security_patch": patch,
                "cwe_ids": ["CWE-22"],
                "language": "Python",
                "cve_id": "CVE-2099-0001",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return dataset, cache


def _pipeline(target: Path):
    options = StaticAnalysisOptions(
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


def test_paired_adapter_discriminates_vulnerable_and_fixed_revisions(tmp_path):
    dataset, cache = _paired_fixture(tmp_path)

    payload = evaluate_susvibes_paired_benchmark(dataset, cache, _pipeline)

    assert payload["schema_version"] == "belief.susvibes_paired_static.v1"
    assert payload["mode"] == SUSVIBES_PAIRED_MODE
    assert payload["status"] == "passed"
    assert payload["metrics"]["evaluable_case_count"] == 1
    assert payload["metrics"]["vulnerable_surface_recall"] == 1.0
    assert payload["metrics"]["fixed_surface_false_positive_rate"] == 0.0
    assert payload["metrics"]["paired_discrimination_rate"] == 1.0
    assert payload["cases"][0]["vulnerable_surfaced"] is True
    assert payload["cases"][0]["fixed_surface_false_positive"] is False
    assert payload["comparability"]["susvibes_secpass_equivalent"] is False
    assert payload["comparability"]["aikido_pass_at_3_equivalent"] is False


def test_digest_excludes_wall_clock_duration(tmp_path):
    dataset, cache = _paired_fixture(tmp_path)
    first_clock = iter((10.0, 11.0))
    second_clock = iter((100.0, 109.0))

    first = evaluate_susvibes_paired_benchmark(
        dataset,
        cache,
        _pipeline,
        clock=lambda: next(first_clock),
    )
    second = evaluate_susvibes_paired_benchmark(
        dataset,
        cache,
        _pipeline,
        clock=lambda: next(second_clock),
    )

    assert first["duration_seconds"] == 1.0
    assert second["duration_seconds"] == 9.0
    assert first["deterministic_digest"] == second["deterministic_digest"]


def test_parent_resolution_uses_hydrated_commit_object_at_shallow_boundary(tmp_path):
    dataset, cache = _paired_fixture(tmp_path)
    case = json.loads(dataset.read_text(encoding="utf-8"))
    repository = cache / "example__assets"
    vulnerable_commit = _git(repository, "rev-parse", f"{case['base_commit']}^")
    (repository / ".git" / "shallow").write_text(
        f"{case['base_commit']}\n",
        encoding="ascii",
    )

    parent = LocalGitCorpus(cache).parent_commit(
        case["project"],
        case["base_commit"],
    )

    assert parent == vulnerable_commit


def test_empty_observation_fails_acceptance_thresholds(tmp_path):
    dataset, cache = _paired_fixture(tmp_path)
    empty = SimpleNamespace(findings=(), audit_cases=())

    payload = evaluate_susvibes_paired_benchmark(
        dataset,
        cache,
        lambda _target: empty,
        thresholds=SusVibesThresholds(
            minimum_vulnerable_surface_recall=0.5,
            maximum_fixed_surface_false_positive_rate=0.0,
            minimum_paired_discrimination_rate=0.5,
        ),
    )

    assert payload["status"] == "failed"
    assert payload["exit_code"] == 1
    assert payload["thresholds_passed"] is False


def test_causal_patch_review_finding_surfaces_without_audit_case_mapper(tmp_path):
    dataset, cache = _paired_fixture(tmp_path)
    finding = SimpleNamespace(
        cwe="CWE-22",
        file="assets.py",
        fingerprint="causal-finding",
        line=5,
        metadata={
            "analysis_profile": "patch_review",
            "function_name": "read_asset",
            "dataflow": {
                "source": "path",
                "sink": "open",
                "missing_guarantees": ["path.is_within_store == true"],
            },
        },
        rule_id="CWE-22",
    )

    def pipeline(target):
        findings = (finding,) if target.name == "vulnerable" else ()
        return SimpleNamespace(findings=findings, audit_cases=())

    payload = evaluate_susvibes_paired_benchmark(
        dataset,
        cache,
        pipeline,
    )

    assert payload["cases"][0]["vulnerable"]["verdicts"] == ["weak_signal"]
    assert payload["cases"][0]["paired_discriminated"] is True


def test_parser_rejects_parent_traversal_in_diff_path():
    patch = "\n".join(
        [
            "diff --git a/../secret.py b/../secret.py",
            "@@ -1 +1 @@",
            "-old",
            "+new",
        ]
    )

    with pytest.raises(ValueError, match="unsafe path"):
        parse_security_diff(patch)


def test_parser_tracks_changed_lines_instead_of_whole_context_hunk():
    patch = "\n".join(
        [
            "diff --git a/module.py b/module.py",
            "@@ -10,4 +10,5 @@ def build():",
            "     before()",
            "-    unsafe(value)",
            "+    checked = validate(value)",
            "+    safe(checked)",
            "     after()",
            "     return value",
        ]
    )

    parsed = parse_security_diff(patch)
    hunk = parsed[0].hunks[0]

    assert hunk.old_changed_lines == (11,)
    assert hunk.new_changed_lines == (11, 12)
    assert hunk.range_for("vulnerable") == (11, 11)
    assert hunk.range_for("fixed") == (11, 12)


def test_cache_preparation_requires_explicit_network_acknowledgement(tmp_path):
    with pytest.raises(ValueError, match="--allow-network"):
        prepare_cache(
            tmp_path / "dataset.jsonl",
            tmp_path / "cache",
            allow_network=False,
        )


def test_cache_preparation_parses_repeated_and_comma_separated_cwes():
    assert _cwe_values(["CWE-22,CWE-639", "CWE-863"]) == (
        "CWE-22",
        "CWE-639",
        "CWE-863",
    )


def test_cache_preparation_selects_explicit_ids_in_requested_order(
    tmp_path,
):
    dataset, _cache = _paired_fixture(tmp_path)

    cases = _select_cases(
        dataset,
        instance_ids=["example__assets_fixed"],
    )

    assert [case["instance_id"] for case in cases] == [
        "example__assets_fixed"
    ]


@pytest.mark.parametrize(
    ("instance_ids", "only_cwes", "max_cases", "message"),
    [
        (
            ["example__assets_fixed", "example__assets_fixed"],
            (),
            0,
            "instance IDs must be unique",
        ),
        (
            ["unknown__case"],
            (),
            0,
            "absent from the dataset",
        ),
        (
            ["example__assets_fixed"],
            ("CWE-22",),
            0,
            "cannot be combined",
        ),
        (
            ["example__assets_fixed"],
            (),
            1,
            "cannot be combined",
        ),
    ],
)
def test_cache_preparation_rejects_invalid_explicit_selection(
    tmp_path,
    instance_ids,
    only_cwes,
    max_cases,
    message,
):
    dataset, _cache = _paired_fixture(tmp_path)

    with pytest.raises(ValueError, match=message):
        _select_cases(
            dataset,
            instance_ids=instance_ids,
            only_cwes=only_cwes,
            max_cases=max_cases,
        )


@pytest.mark.parametrize("protected_name", ["dataset.jsonl", "experiment.json"])
def test_cache_manifest_cannot_overwrite_frozen_input(
    tmp_path,
    protected_name,
):
    dataset = tmp_path / "dataset.jsonl"
    experiment = tmp_path / "experiment.json"

    with pytest.raises(ValueError, match="must not overwrite"):
        _validate_manifest_output(
            tmp_path / protected_name,
            dataset=dataset,
            experiment_manifest=experiment,
        )


def test_cache_manifest_is_create_only(tmp_path):
    output = tmp_path / "cache-manifest.json"
    output.write_text("preserve me\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        _validate_manifest_output(
            output,
            dataset=tmp_path / "dataset.jsonl",
        )

    assert output.read_text(encoding="utf-8") == "preserve me\n"


def test_cache_preparation_refuses_nonempty_non_git_directory(tmp_path):
    repository = tmp_path / "example__assets"
    repository.mkdir()
    (repository / "unrelated.txt").write_text("preserve me\n", encoding="utf-8")

    with pytest.raises(ValueError, match="non-empty cache directory"):
        _ensure_repository(tmp_path, "example/assets")

    assert (repository / "unrelated.txt").read_text(encoding="utf-8") == "preserve me\n"


def test_cli_runs_paired_benchmark_against_explicit_local_cache(tmp_path):
    dataset, cache = _paired_fixture(tmp_path)
    output = tmp_path / "result.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "belief",
            "benchmark",
            "reportability",
            "--mode",
            SUSVIBES_PAIRED_MODE,
            "--target",
            str(dataset),
            "--repository-cache",
            str(cache),
            "--only-cwe",
            "CWE-22",
            "--json-output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert summary["status"] == "passed"
    assert summary["deterministic_digest"] == payload["deterministic_digest"]
    assert payload["metrics"]["paired_discrimination_rate"] == 1.0
