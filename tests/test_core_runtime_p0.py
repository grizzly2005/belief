"""Targeted P0 coverage for BELIEF core runtime compatibility."""

from __future__ import annotations

import io
import json
import sys

import pytest

from belief.models import (
    AnalysisReport,
    Belief,
    JustificationCategory,
    LogicType,
    Predicate,
    Scope,
)
from belief.parser import CodeParser
from belief.pipeline import (
    ParsePhase,
    Phase,
    Pipeline,
    PipelineCheckpointError,
    PipelineState,
)


def test_legacy_taxonomy_is_migrated_without_upgrading_evidence():
    assert LogicType.parse("SEMANTIC") is LogicType.SEMANTIC
    assert LogicType.parse("contract") is LogicType.SEMANTIC

    belief = Belief.from_dict({
        "predicate": {"expression": "input is sanitized"},
        "scope": {"file_path": "app.py"},
        "justification": "C3_DOCUMENTED",
        "logic_type": "SEMANTIC",
    })

    assert belief.justification is JustificationCategory.C5_DOCUMENTED_CONVENTION
    assert belief.source_metadata["deserialization_diagnostics"][0]["code"] == (
        "legacy_justification_taxonomy_migrated"
    )
    assert belief.logic_type is LogicType.SEMANTIC


def test_cli_help_falls_back_on_ascii_stdout(monkeypatch):
    from belief import cli

    raw = io.BytesIO()
    ascii_stdout = io.TextIOWrapper(raw, encoding="ascii", errors="strict")
    monkeypatch.setattr(sys, "argv", ["belief", "--help"])
    monkeypatch.setattr(sys, "stdout", ascii_stdout)

    with pytest.raises(SystemExit) as exc:
        cli.main()

    assert exc.value.code == 0
    ascii_stdout.flush()
    help_text = raw.getvalue().decode("ascii")
    assert "BELIEF -" in help_text
    assert "->" in help_text


def test_parser_default_exclusions_and_explicit_target(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "keep.py").write_text("def keep():\n    return 1\n", encoding="utf-8")

    excluded_dirs = [
        ".git",
        "__pycache__",
        ".pytest_cache",
        "node_modules",
        "dist",
        "build",
        "vendor",
        "vendored",
        "adapted",
        "fastapi_adapted",
        "examples",
        "docs",
        "security_rules",
        "target_flaskjwt",
        "venv",
        "env",
        "archives",
        "generated",
    ]
    for name in excluded_dirs:
        folder = project / name
        folder.mkdir()
        (folder / "hidden.py").write_text("def hidden():\n    return 0\n", encoding="utf-8")

    nested_generated = project / "archives2" / "generated"
    nested_generated.mkdir(parents=True)
    (nested_generated / "hidden.py").write_text("def hidden_nested():\n    return 0\n", encoding="utf-8")

    parser = CodeParser(str(project))
    files = [path.name for path in parser._collect_python_files()]
    assert files == ["keep.py"]

    explicit = project / "target_flaskjwt"
    parser = CodeParser(str(explicit))
    explicit_files = [path.name for path in parser._collect_python_files()]
    assert explicit_files == ["hidden.py"]


def test_json_roundtrip_preserves_stable_identity_and_metadata(tmp_path):
    scope = Scope(file_path="src/auth.py", function_name="login", line_start=42)
    first = Belief(
        predicate=Predicate(expression="query uses parameter binding"),
        scope=scope,
        justification=JustificationCategory.C5_DOCUMENTED_CONVENTION,
        logic_type=LogicType.SEMANTIC,
        cwe="CWE-89",
        source_metadata={"source": "bandit", "rule_id": "B608"},
    )
    drifted_text = Belief(
        predicate=Predicate(expression="sql call is parameterized"),
        scope=scope,
        justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
        cwe="CWE-89",
    )

    assert first.canonical_key == drifted_text.canonical_key
    assert first.id == drifted_text.id

    restored = Belief.from_dict(first.to_dict())
    assert restored.id == first.id
    assert restored.canonical_key == first.canonical_key
    assert restored.cwe == "CWE-89"
    assert restored.source_metadata["source"] == "bandit"
    assert restored.logic_type is LogicType.SEMANTIC

    report = AnalysisReport(
        project_name="roundtrip",
        beliefs=[first],
        bridge_summary={"bandit": {"findings": 1, "errors": []}},
        source_metadata={"project_path": "src", "source": "test"},
    )
    path = tmp_path / "report.json"
    report.save(str(path))
    raw = json.loads(path.read_text(encoding="utf-8"))

    assert raw["beliefs"][0]["canonical_key"] == first.canonical_key
    assert raw["beliefs"][0]["cwe"] == "CWE-89"
    assert raw["bridge_summary"]["bandit"]["findings"] == 1
    assert raw["source_metadata"]["source"] == "test"

    loaded = AnalysisReport.load(str(path))
    assert loaded.beliefs[0].source_metadata["rule_id"] == "B608"
    assert loaded.bridge_summary["bandit"]["findings"] == 1
    assert loaded.source_metadata["project_path"] == "src"


def test_checkpoint_restores_real_parse_state(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("def handler():\n    return 1\n", encoding="utf-8")
    checkpoint_dir = tmp_path / "checkpoint"

    Pipeline([ParsePhase()], checkpoint_dir=str(checkpoint_dir)).run(str(project))
    resumed = Pipeline([ParsePhase()], checkpoint_dir=str(checkpoint_dir)).run(
        str(project),
        resume_from_checkpoint=True,
    )

    assert "parse" in resumed.completed_phases
    assert [func.name for func in resumed.functions] == ["handler"]
    assert hasattr(resumed, "_parser")
    assert any("handler" in key for key in resumed._parser.functions)


def test_checkpoint_resume_skips_phase_with_restored_beliefs(tmp_path):
    class SeedBeliefPhase(Phase):
        name = "seed"

        def __init__(self):
            self.ran = False

        def run(self, state: PipelineState) -> PipelineState:
            self.ran = True
            state.beliefs.append(
                Belief(
                    predicate=Predicate(expression="x > 0"),
                    scope=Scope(file_path="seed.py"),
                    justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                )
            )
            return state

    project = tmp_path / "project"
    project.mkdir()
    checkpoint_dir = tmp_path / "checkpoint"

    first_phase = SeedBeliefPhase()
    Pipeline([first_phase], checkpoint_dir=str(checkpoint_dir)).run(str(project))
    assert first_phase.ran

    resumed_phase = SeedBeliefPhase()
    resumed = Pipeline([resumed_phase], checkpoint_dir=str(checkpoint_dir)).run(
        str(project),
        resume_from_checkpoint=True,
    )

    assert not resumed_phase.ran
    assert len(resumed.beliefs) == 1
    assert resumed.beliefs[0].predicate.expression == "x > 0"


def test_incomplete_legacy_checkpoint_refuses_resume(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    checkpoint_dir = tmp_path / "checkpoint"
    checkpoint_dir.mkdir()
    (checkpoint_dir / "state.json").write_text(
        json.dumps({
            "project_path": str(project),
            "completed_phases": ["parse"],
            "n_beliefs": 1,
        }),
        encoding="utf-8",
    )

    with pytest.raises(PipelineCheckpointError, match="incomplete"):
        Pipeline([], checkpoint_dir=str(checkpoint_dir)).run(
            str(project),
            resume_from_checkpoint=True,
        )
