"""Regression tests for the non-executing C exploration-objective pilot."""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import pytest

from belief.exploration import (
    CConstraintError,
    EXPECTED_EXPLORATION_OUTPUTS,
    EXPLORATION_OBJECTIVE_SCHEMA_VERSION,
    ExplorationCompileError,
    ExplorationObjective,
    PathArtifact,
    PathArtifactImportError,
    PathStep,
    compile_validation_plan,
    export_c_reachability_probe,
    import_path_artifact,
    load_path_artifact,
    normalize_c_boolean_expression,
)
from belief.validation import (
    VALIDATION_REACHABILITY_SCHEMA_VERSION,
    ValidationOracle,
    ValidationPlan,
)

pytestmark = pytest.mark.security


def _plan(*, expression: str = "requested_id != owned_id") -> ValidationPlan:
    return ValidationPlan(
        subject_id="case_c_authorization_001",
        case_type="authorization_guard_missing",
        case_status="needs_validation",
        strategy="property_guided_path_boundary",
        objective="Determine whether the candidate condition reaches the sensitive call.",
        target={"file": "src/example.c", "line": 12},
        evidence_gaps=("missing_security_evidence",),
        oracles=(
            ValidationOracle(
                kind="reachability",
                expected="path or no-path artifact",
                failure_signal="inconclusive",
                evidence_to_capture=("ordered_path",),
            ),
        ),
        reachability_hints={
            "schema_version": VALIDATION_REACHABILITY_SCHEMA_VERSION,
            "language": "c",
            "function_context": {"name": "authorize_request"},
            "sink": {
                "file": "src/example.c",
                "line": 12,
                "symbol": "sensitive_operation",
            },
            "candidate_constraint": {
                "expression": expression,
                "logic": "c_boolean_expression_v1",
                "origin": "missing_security_evidence",
            },
        },
        safety={
            "authorized_scope_required": True,
            "network_mode": "forbidden",
            "destructive_actions_allowed": False,
        },
    )


def _objective() -> ExplorationObjective:
    return compile_validation_plan(_plan())


def _plausible_artifact(objective: ExplorationObjective) -> PathArtifact:
    return PathArtifact(
        objective_id=objective.objective_id,
        tool_id="synthetic_reachability_fixture",
        outcome="plausible_path_artifact",
        reason="A bounded synthetic entry-to-target path was supplied.",
        path=(
            PathStep(
                file="src/example.c",
                line=4,
                symbol="authorize_request",
                kind="entry",
            ),
            PathStep(
                file="src/example.c",
                line=8,
                symbol="authorization_branch",
                kind="branch",
            ),
            PathStep(
                file="src/example.c",
                line=12,
                symbol="sensitive_operation",
                kind="target",
            ),
        ),
    )


def test_validation_plan_compiles_to_deterministic_objective():
    first = compile_validation_plan(_plan())
    second = compile_validation_plan(_plan())

    assert first == second
    assert first.schema_version == EXPLORATION_OBJECTIVE_SCHEMA_VERSION
    assert first.objective_id.startswith("eo_")
    assert first.source_plan_id == _plan().plan_id
    assert first.expected_outputs == EXPECTED_EXPLORATION_OUTPUTS
    assert first.target.to_dict() == {
        "file": "src/example.c",
        "line": 12,
        "symbol": "sensitive_operation",
    }


def test_objective_round_trip_is_exact():
    original = _objective()

    restored = ExplorationObjective.from_dict(original.to_dict())

    assert restored == original
    assert restored.to_dict() == original.to_dict()


def test_objective_rejects_unknown_fields():
    payload = _objective().to_dict()
    payload["callable"] = "arbitrary"

    with pytest.raises(ValueError, match="unknown"):
        ExplorationObjective.from_dict(payload)


@pytest.mark.parametrize(
    "expression",
    [
        "requested_id != owned_id; system(1)",
        "check_access()",
        "value = 1",
        "value /* injected */ != 0",
        "value != \"secret\"",
        "value ? 1 : 0",
        "obj->field != 0",
        "{ value != 0; }",
        "if != 0",
        "value != 08",
    ],
)
def test_c_constraint_rejects_executable_or_unsupported_syntax(expression):
    with pytest.raises(CConstraintError):
        normalize_c_boolean_expression(expression)


def test_c_constraint_accepts_only_boolean_comparison_subset():
    normalized = normalize_c_boolean_expression(
        "!(requested_id == owned_id) && tenant_id != 0"
    )

    assert normalized == (
        "! ( requested_id == owned_id ) && tenant_id != 0"
    )


def test_compiler_requires_explicit_c_reachability_contract():
    payload = _plan().to_dict()
    payload["reachability_hints"]["language"] = "python"
    payload["plan_id"] = ""

    with pytest.raises(ExplorationCompileError, match="only explicit C"):
        compile_validation_plan(payload)


def test_compiler_does_not_derive_constraint_from_plan_prose():
    payload = _plan().to_dict()
    del payload["reachability_hints"]["candidate_constraint"]
    payload["plan_id"] = ""

    with pytest.raises(ExplorationCompileError, match="candidate_constraint"):
        compile_validation_plan(payload)


def test_c_export_is_deterministic_and_non_executing():
    objective = _objective()

    first = export_c_reachability_probe(objective).to_dict()
    second = export_c_reachability_probe(objective).to_dict()

    assert first == second
    assert first["compiled"] is False
    assert first["executed"] is False
    assert "if (requested_id != owned_id)" in first["source"]
    assert "BELIEF_REACHABILITY_TARGET();" in first["source"]
    assert "system(" not in first["source"]


def test_plausible_path_import_is_supported_but_not_vulnerability_proof():
    objective = _objective()
    artifact = _plausible_artifact(objective)

    restored, assessment = import_path_artifact(
        artifact.to_dict(),
        objective=objective,
    )

    assert restored == artifact
    assert assessment.interpretation == "supported"
    assert assessment.to_dict()["confirms_vulnerability"] is False


@pytest.mark.parametrize(
    ("outcome", "interpretation"),
    [
        ("no_plausible_path", "refuted"),
        ("inconclusive", "inconclusive"),
    ],
)
def test_non_path_artifact_interpretations(outcome, interpretation):
    objective = _objective()
    artifact = PathArtifact(
        objective_id=objective.objective_id,
        tool_id="synthetic_reachability_fixture",
        outcome=outcome,
        reason="Synthetic expected result.",
    )

    _, assessment = import_path_artifact(
        artifact.to_dict(),
        objective=objective,
    )

    assert assessment.interpretation == interpretation


def test_path_artifact_must_end_at_exact_objective_target():
    objective = _objective()
    artifact = _plausible_artifact(objective)
    payload = artifact.to_dict()
    payload["path"][-1]["line"] = 13
    payload["artifact_id"] = PathArtifact(
        objective_id=objective.objective_id,
        tool_id=payload["tool_id"],
        outcome=payload["outcome"],
        reason=payload["reason"],
        path=tuple(PathStep.from_dict(item) for item in payload["path"]),
    ).artifact_id

    with pytest.raises(PathArtifactImportError, match="target does not match"):
        import_path_artifact(payload, objective=objective)


def test_path_artifact_must_start_in_objective_target_file():
    objective = _objective()
    artifact = _plausible_artifact(objective)
    path = list(artifact.path)
    path[0] = PathStep(
        file="src/other.c",
        line=4,
        symbol="authorize_request",
        kind="entry",
    )
    mismatched = PathArtifact(
        objective_id=objective.objective_id,
        tool_id=artifact.tool_id,
        outcome=artifact.outcome,
        reason=artifact.reason,
        path=tuple(path),
    )

    with pytest.raises(PathArtifactImportError, match="entry does not match"):
        import_path_artifact(mismatched.to_dict(), objective=objective)


def test_path_artifact_file_uses_strict_json(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_text(
        '{"schema_version":"belief.path_artifact.v1",'
        '"schema_version":"belief.path_artifact.v1"}',
        encoding="utf-8",
    )

    with pytest.raises(PathArtifactImportError, match="duplicate"):
        load_path_artifact(path, objective=_objective())


def test_path_artifact_file_is_bounded(tmp_path):
    path = tmp_path / "artifact.json"
    path.write_bytes(b"{}" * 32)

    with pytest.raises(PathArtifactImportError, match="exceeds"):
        load_path_artifact(path, objective=_objective(), max_bytes=8)


def test_models_do_not_trigger_network_or_subprocess(monkeypatch):
    def reject_side_effect(*_args, **_kwargs):
        raise AssertionError("exploration contract attempted an external side effect")

    monkeypatch.setattr(socket.socket, "connect", reject_side_effect)
    monkeypatch.setattr(subprocess, "Popen", reject_side_effect)

    objective = _objective()
    probe = export_c_reachability_probe(objective)
    artifact = _plausible_artifact(objective)
    _, assessment = import_path_artifact(
        artifact.to_dict(),
        objective=objective,
    )

    assert probe.to_dict()["executed"] is False
    assert assessment.interpretation == "supported"


def test_published_schemas_track_runtime_contracts():
    root = Path(__file__).resolve().parents[1]
    objective_schema = json.loads(
        (root / "schemas" / "belief.exploration-objective.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    artifact_schema = json.loads(
        (root / "schemas" / "belief.path-artifact.v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    objective = _objective().to_dict()
    artifact = _plausible_artifact(_objective()).to_dict()

    assert objective_schema["properties"]["schema_version"]["const"] == (
        objective["schema_version"]
    )
    assert set(objective_schema["required"]) == set(objective)
    assert artifact_schema["properties"]["schema_version"]["const"] == (
        artifact["schema_version"]
    )
    assert set(artifact_schema["required"]) == set(artifact)
