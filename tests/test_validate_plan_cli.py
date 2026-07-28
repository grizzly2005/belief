"""CLI contracts for create-only, explicit local validation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from belief.validation.execution_models import (
    ValidationExecutionContext,
    write_validation_fixture_bundle,
)
from belief.validation.plans import (
    load_validation_plan_bundle,
    write_validation_plan_bundle,
)


pytestmark = pytest.mark.security

ROOT = Path(__file__).resolve().parents[1]


def _artifacts(tmp_path: Path) -> tuple[Path, Path]:
    audit_path = tmp_path / "audit.json"
    plan_path = tmp_path / "plans.json"
    fixture_path = tmp_path / "fixtures.json"
    audit_path.write_text(
        json.dumps({
            "schema_version": "belief.audit.v1",
            "target": "local-cli-fixture",
            "audit_cases": [{
                "case_id": "cli_path_case",
                "case_type": "path_traversal_possible",
                "status": "needs_review",
                "review_priority": "high",
                "source": "controlled_path",
                "sink": "fixture_read",
                "route_context": {"route": "/local"},
                "structured_dataflow": {
                    "source": {"symbol": "controlled_path"},
                    "sink": {"symbol": "fixture_read"},
                },
            }],
        }),
        encoding="utf-8",
    )
    write_validation_plan_bundle(audit_path, plan_path)
    _payload, plans = load_validation_plan_bundle(plan_path)
    context = ValidationExecutionContext.for_plan(
        plans[0],
        fixture_id="cli_vulnerable_fixture",
        adapter="path_join_unchecked",
        source_revision="cli-fixture-v1",
    )
    write_validation_fixture_bundle(fixture_path, [context])
    return plan_path, fixture_path


def _command(
    plan: Path,
    fixture: Path,
    output: Path,
    *,
    fail_on_bypass: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "belief.cli",
        "validate-plan",
        "--plan",
        str(plan),
        "--fixture",
        str(fixture),
        "--output",
        str(output),
    ]
    if fail_on_bypass:
        command.append("--fail-on-bypass")
    return command


def test_cli_returns_zero_for_bypass_without_explicit_failure_flag(
    tmp_path,
):
    plan, fixture = _artifacts(tmp_path)
    output = tmp_path / "results.json"

    completed = subprocess.run(
        _command(plan, fixture, output),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 0, completed.stderr
    summary = json.loads(completed.stdout)
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert summary["bypassed_count"] == 1
    assert payload["metrics"]["bypassed_count"] == 1
    assert payload["boundaries"]["network_used"] is False


def test_cli_fail_on_bypass_is_opt_in(tmp_path):
    plan, fixture = _artifacts(tmp_path)
    output = tmp_path / "results-fail.json"

    completed = subprocess.run(
        _command(
            plan,
            fixture,
            output,
            fail_on_bypass=True,
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 1
    assert output.is_file()


def test_cli_refuses_result_overwrite_as_contract_error(tmp_path):
    plan, fixture = _artifacts(tmp_path)
    output = tmp_path / "results.json"
    first = subprocess.run(
        _command(plan, fixture, output),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert first.returncode == 0

    second = subprocess.run(
        _command(plan, fixture, output),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert second.returncode == 2
    assert "refusing to overwrite" in second.stderr


def test_cli_requires_exact_fixture_binding(tmp_path):
    plan, _fixture = _artifacts(tmp_path)
    empty_fixture = tmp_path / "empty-fixtures.json"
    write_validation_fixture_bundle(empty_fixture, [])

    completed = subprocess.run(
        _command(
            plan,
            empty_fixture,
            tmp_path / "results.json",
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 2
    assert "fixture bindings do not match" in completed.stderr
