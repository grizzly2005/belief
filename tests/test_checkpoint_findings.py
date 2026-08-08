"""Checkpoint coverage for restored report findings."""

from __future__ import annotations

from belief.models import Belief, JustificationCategory, Predicate, Scope
from belief.pipeline import Phase, Pipeline, PipelineState, ReportPhase


class SeedSecurityBeliefPhase(Phase):
    name = "seed_security"

    def __init__(self):
        self.ran = False

    def run(self, state: PipelineState) -> PipelineState:
        self.ran = True
        state.beliefs.append(
            Belief(
                predicate=Predicate(
                    expression="dynamic_code.input.is_trusted == True",
                    natural_language="User input reaches eval().",
                ),
                scope=Scope(file_path="app.py", function_name="run", line_start=3),
                justification=JustificationCategory.C6_UNSUPPORTED_ASSUMPTION,
                cwe="CWE-95",
                source_metadata={"source": "security_patterns", "rule_id": "CWE-95"},
            )
        )
        return state


def test_checkpoint_resume_restores_report_findings(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    checkpoint_dir = tmp_path / "checkpoint"

    first_seed = SeedSecurityBeliefPhase()
    Pipeline([first_seed, ReportPhase()], checkpoint_dir=str(checkpoint_dir)).run(str(project))
    assert first_seed.ran

    resumed_seed = SeedSecurityBeliefPhase()
    resumed = Pipeline([resumed_seed, ReportPhase()], checkpoint_dir=str(checkpoint_dir)).run(
        str(project),
        resume_from_checkpoint=True,
    )

    assert not resumed_seed.ran
    assert resumed.report is not None
    assert len(resumed.report.findings) == 1
    assert resumed.report.findings[0].cwe == "CWE-95"
