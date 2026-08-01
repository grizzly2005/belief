"""Deterministic synthetic benchmark for exploration-objective contracts."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from belief.json_contracts import StrictJSONError, load_json_file, strict_json_dumps
from belief.validation.plan_models import canonical_digest

from .c_export import export_c_reachability_probe
from .models import (
    EXPECTED_EXPLORATION_OUTPUTS,
    EXPLORATION_INTERPRETATIONS,
    ExplorationObjective,
    PathArtifact,
    assess_path_artifact,
)

EXPLORATION_PILOT_CORPUS_SCHEMA_VERSION = (
    "belief.exploration_pilot_corpus.v1"
)
EXPLORATION_PILOT_BENCHMARK_SCHEMA_VERSION = (
    "belief.exploration_pilot_benchmark.v1"
)
MAX_EXPLORATION_PILOT_CORPUS_BYTES = 1024 * 1024

_CASE_ID = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_CASE_FIELDS = {
    "case_id",
    "objective",
    "path_artifact",
    "expected_interpretation",
}


class ExplorationBenchmarkError(ValueError):
    """Raised when the closed synthetic pilot corpus is invalid."""


@dataclass(frozen=True)
class ExplorationPilotCase:
    case_id: str
    objective: ExplorationObjective
    path_artifact: PathArtifact
    expected_interpretation: str

    def __post_init__(self) -> None:
        if not isinstance(self.case_id, str) or not _CASE_ID.fullmatch(self.case_id):
            raise ValueError("exploration pilot case_id is not canonical")
        if self.expected_interpretation not in EXPLORATION_INTERPRETATIONS:
            raise ValueError("unsupported expected exploration interpretation")
        # Validate the binding and the exact entry/target contract at load time.
        assess_path_artifact(self.objective, self.path_artifact)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "objective": self.objective.to_dict(),
            "path_artifact": self.path_artifact.to_dict(),
            "expected_interpretation": self.expected_interpretation,
        }


def load_exploration_pilot_corpus(
    path: str | Path,
    *,
    max_bytes: int = MAX_EXPLORATION_PILOT_CORPUS_BYTES,
) -> tuple[dict[str, Any], tuple[ExplorationPilotCase, ...]]:
    """Strictly load the exact three-case synthetic pilot corpus."""

    try:
        payload = load_json_file(path, max_bytes=max_bytes)
    except StrictJSONError as exc:
        raise ExplorationBenchmarkError(
            f"invalid exploration pilot corpus: {exc}"
        ) from exc
    try:
        if not isinstance(payload, Mapping) or set(payload) != {
            "schema_version",
            "cases",
        }:
            raise ValueError("exploration pilot corpus fields mismatch")
        if payload["schema_version"] != EXPLORATION_PILOT_CORPUS_SCHEMA_VERSION:
            raise ValueError("unsupported exploration pilot corpus schema")
        rows = payload["cases"]
        if not isinstance(rows, list) or len(rows) != 3:
            raise ValueError("exploration pilot corpus requires exactly three cases")

        cases: list[ExplorationPilotCase] = []
        for row in rows:
            if not isinstance(row, Mapping) or set(row) != _CASE_FIELDS:
                raise ValueError("exploration pilot case fields mismatch")
            objective_payload = row["objective"]
            artifact_payload = row["path_artifact"]
            if not isinstance(objective_payload, Mapping):
                raise ValueError("exploration pilot objective must be an object")
            if not isinstance(artifact_payload, Mapping):
                raise ValueError("exploration pilot path artifact must be an object")
            cases.append(
                ExplorationPilotCase(
                    case_id=row["case_id"],
                    objective=ExplorationObjective.from_dict(objective_payload),
                    path_artifact=PathArtifact.from_dict(artifact_payload),
                    expected_interpretation=row["expected_interpretation"],
                )
            )

        if len({case.case_id for case in cases}) != len(cases):
            raise ValueError("exploration pilot case_id values must be unique")
        if len({case.objective.objective_id for case in cases}) != len(cases):
            raise ValueError("exploration pilot objective_id values must be unique")
        if len({case.path_artifact.artifact_id for case in cases}) != len(cases):
            raise ValueError("exploration pilot artifact_id values must be unique")
        if {case.path_artifact.outcome for case in cases} != set(
            EXPECTED_EXPLORATION_OUTPUTS
        ):
            raise ValueError("exploration pilot must cover every artifact outcome")
        if {case.expected_interpretation for case in cases} != set(
            EXPLORATION_INTERPRETATIONS
        ):
            raise ValueError("exploration pilot must cover every expected label")
    except (TypeError, ValueError) as exc:
        raise ExplorationBenchmarkError(
            f"invalid exploration pilot corpus: {exc}"
        ) from exc

    canonical_payload = {
        "schema_version": payload["schema_version"],
        "cases": [case.to_dict() for case in cases],
    }
    return canonical_payload, tuple(cases)


def run_exploration_pilot_benchmark(path: str | Path) -> dict[str, Any]:
    """Compare imported path interpretations with the frozen expected labels."""

    corpus, cases = load_exploration_pilot_corpus(path)
    first = _evaluate_cases(cases)
    second = _evaluate_cases(cases)
    rows = first["case_results"]
    correct_count = sum(1 for row in rows if row["matched"])
    inconclusive_count = sum(
        1 for row in rows if row["observed_interpretation"] == "inconclusive"
    )
    case_count = len(rows)
    payload: dict[str, Any] = {
        "schema_version": EXPLORATION_PILOT_BENCHMARK_SCHEMA_VERSION,
        "mode": "synthetic_artifact_import_only",
        "corpus": {
            "schema_version": corpus["schema_version"],
            "sha256": canonical_digest(corpus),
            "case_count": case_count,
        },
        "metrics": {
            "case_count": case_count,
            "correct_count": correct_count,
            "accuracy": round(correct_count / case_count, 6),
            "supported_count": sum(
                1 for row in rows if row["observed_interpretation"] == "supported"
            ),
            "refuted_count": sum(
                1 for row in rows if row["observed_interpretation"] == "refuted"
            ),
            "inconclusive_count": inconclusive_count,
            "abstention_count": inconclusive_count,
            "abstention_rate": round(inconclusive_count / case_count, 6),
        },
        "semantic_stability": {
            "identical_repeated_evaluation": first == second,
            "first_digest": canonical_digest(first),
            "second_digest": canonical_digest(second),
        },
        "boundaries": {
            "synthetic_corpus": True,
            "artifact_import_only": True,
            "external_tool_executed": False,
            "external_code_executed": False,
            "network_used": False,
            "subprocess_used": False,
            "shell_used": False,
            "compiler_used": False,
            "dynamic_import_used": False,
            "duck_wire_compatibility_verified": False,
            "vulnerability_confirmation_claimed": False,
            "leaderboard_comparison_claimed": False,
        },
        "case_results": rows,
    }
    payload["deterministic_digest"] = canonical_digest(payload)
    return payload


def write_exploration_pilot_benchmark(
    output: str | Path,
    *,
    corpus_path: str | Path,
) -> dict[str, Any]:
    """Create a deterministic benchmark report without overwriting a file."""

    payload = run_exploration_pilot_benchmark(corpus_path)
    destination = Path(output)
    rendered = strict_json_dumps(payload, indent=2, sort_keys=True) + "\n"
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
    except FileExistsError as exc:
        raise ExplorationBenchmarkError(
            f"refusing to overwrite exploration pilot benchmark: {destination}"
        ) from exc
    return payload


def _evaluate_cases(cases: tuple[ExplorationPilotCase, ...]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for case in cases:
        assessment = assess_path_artifact(case.objective, case.path_artifact)
        probe = export_c_reachability_probe(case.objective)
        rows.append(
            {
                "case_id": case.case_id,
                "objective_id": case.objective.objective_id,
                "artifact_id": case.path_artifact.artifact_id,
                "artifact_outcome": case.path_artifact.outcome,
                "expected_interpretation": case.expected_interpretation,
                "observed_interpretation": assessment.interpretation,
                "matched": assessment.interpretation
                == case.expected_interpretation,
                "path_step_count": assessment.path_step_count,
                "probe_source_sha256": probe.source_sha256,
                "probe_compiled": False,
                "probe_executed": False,
                "confirms_vulnerability": False,
            }
        )
    return {"case_results": rows}


__all__ = [
    "EXPLORATION_PILOT_BENCHMARK_SCHEMA_VERSION",
    "EXPLORATION_PILOT_CORPUS_SCHEMA_VERSION",
    "MAX_EXPLORATION_PILOT_CORPUS_BYTES",
    "ExplorationBenchmarkError",
    "ExplorationPilotCase",
    "load_exploration_pilot_corpus",
    "run_exploration_pilot_benchmark",
    "write_exploration_pilot_benchmark",
]
