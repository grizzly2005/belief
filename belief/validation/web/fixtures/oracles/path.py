"""Path-boundary evaluator that only observes requests, responses, and state."""

from __future__ import annotations

from typing import Any, Iterable, Mapping

from ....evidence_policy import (
    FUNCTIONAL_BASELINE,
    OPTIONAL,
    PRIMARY_SECURITY,
    SECONDARY_SECURITY,
)
from ....worker.contracts import WorkerObservation
from ..apps.contracts import PathApplication
from ..apps.support import PUBLIC_MARKER, SENTINEL_MARKER


def evaluate_path_application(
    application: PathApplication,
    scenarios: Iterable[Mapping[str, Any]],
    *,
    include_symlink: bool,
) -> tuple[tuple[WorkerObservation, ...], tuple[str, ...]]:
    observations: list[WorkerObservation] = []
    limitations: list[str] = []
    for raw in scenarios:
        scenario = str(raw["scenario"])
        kind = str(raw["stimulus_kind"])
        label = str(raw["stimulus"])
        baseline = raw["baseline"] is True
        if kind == "absolute_outside":
            request_value = application.absolute_outside_stimulus
        elif kind == "symlink" and (
            not include_symlink or not application.symlink_supported
        ):
            limitation = (
                "symlink_disabled_by_test_parameters"
                if not include_symlink
                else "symlink_unavailable"
            )
            limitations.append(limitation)
            observations.append(WorkerObservation(
                scenario=scenario,
                stimulus=label,
                oracle="path_boundary_invariant",
                expected="A symlink may not resolve outside the allowed root.",
                actual={
                    "decision": "not_tested",
                    "symlink_supported": application.symlink_supported,
                },
                baseline=False,
                oracle_role=OPTIONAL,
                required_for_conclusion=False,
                oracle_evaluated=False,
                oracle_passed=None,
                limitations=(limitation,),
                cost_units=0,
            ))
            continue
        else:
            request_value = label
        response = application.request(request_value)
        observation, item_limitations = _evaluate_response(
            scenario=scenario,
            stimulus=label,
            response_status=response.status_code,
            body=response.body,
            baseline=baseline,
            required=raw["required"] is True,
        )
        observations.append(observation)
        limitations.extend(item_limitations)

    final = application.state()
    public_unchanged = final.get("public_marker") == PUBLIC_MARKER
    sentinel_unchanged = final.get("sentinel_marker") == SENTINEL_MARKER
    observations.append(WorkerObservation(
        scenario="filesystem_final_state",
        stimulus="fixture_state_after_path_requests",
        oracle="state_invariant",
        expected="The controlled fixture files remain unchanged.",
        actual={
            "public_unchanged": public_unchanged,
            "sentinel_unchanged": sentinel_unchanged,
        },
        baseline=False,
        oracle_role=SECONDARY_SECURITY,
        required_for_conclusion=True,
        oracle_evaluated=True,
        oracle_passed=public_unchanged and sentinel_unchanged,
        evidence=(
            f"public_unchanged:{str(public_unchanged).lower()}",
            f"sentinel_unchanged:{str(sentinel_unchanged).lower()}",
        ),
        cost_units=0,
    ))
    return tuple(observations), tuple(dict.fromkeys(limitations))


def _evaluate_response(
    *,
    scenario: str,
    stimulus: str,
    response_status: int,
    body: Mapping[str, Any],
    baseline: bool,
    required: bool,
) -> tuple[WorkerObservation, tuple[str, ...]]:
    actual = {
        "response_status": response_status,
        "decision": str(body.get("decision") or "unknown"),
        "marker": str(body.get("marker") or "none"),
        "resolved_path": str(
            body.get("resolved_path") or "not_observed"
        ),
        "sentinel_reached": body.get("marker") == "sentinel",
    }
    limitations: list[str] = []
    if baseline:
        evaluated = True
        passed: bool | None = (
            response_status == 200
            and body.get("marker") == "public"
            and body.get("resolved_path") == "allowed/public.txt"
        )
        oracle = "functional_baseline"
        expected = "The legitimate file remains readable under the allowed root."
    else:
        oracle = "path_boundary_invariant"
        expected = "The controlled path cannot read outside the allowed root."
        denied = (
            response_status in {403, 404}
            and body.get("marker") != "sentinel"
        )
        bypassed = (
            response_status == 200
            and body.get("marker") == "sentinel"
            and body.get("resolved_path") == "outside/sentinel.txt"
        )
        if denied:
            evaluated = True
            passed = True
        elif bypassed:
            evaluated = True
            passed = False
        else:
            evaluated = False
            passed = None
            limitations.append("unexpected_path_response")
    return (
        WorkerObservation(
            scenario=scenario,
            stimulus=stimulus,
            oracle=oracle,
            expected=expected,
            actual=actual,
            baseline=baseline,
            oracle_role=(
                FUNCTIONAL_BASELINE
                if baseline
                else OPTIONAL
                if not required
                else PRIMARY_SECURITY
            ),
            required_for_conclusion=required,
            oracle_evaluated=evaluated,
            oracle_passed=passed,
            evidence=(
                f"scenario:{scenario}",
                f"response_status:{response_status}",
                f"decision:{actual['decision']}",
                f"marker:{actual['marker']}",
                f"resolved_path:{actual['resolved_path']}",
            ),
            limitations=tuple(limitations),
        ),
        tuple(limitations),
    )


__all__ = ["evaluate_path_application"]
