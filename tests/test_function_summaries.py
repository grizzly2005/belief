"""Bounded inference tests for semantic function summaries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from belief.semantic import (
    FunctionSummaryLimits,
    SummaryKind,
    analyze_function_summaries,
)


pytestmark = pytest.mark.security


def _write(path: Path, source: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")


def _by_name(result):
    return {
        summary.qualified_name: summary
        for summary in result.summaries
    }


def _kinds(summary):
    return {effect.kind for effect in summary.effects}


def test_summary_inference_covers_composable_effect_kinds(tmp_path: Path):
    _write(
        tmp_path / "module.py",
        """
def identity(value):
    return value

def constant():
    return 3

def transform(value):
    return value.strip()

def validate(value):
    if len(value) > 10:
        raise ValueError("too large")
    return value

def source(request):
    return request.args.get("name")

def sink(path):
    return open(path)

def wrapper(value):
    return validate(value)

class Store:
    def put(self, value):
        self.value = value
        self.items.append(value)

    def get(self):
        return self.value

def extract(mapping, key):
    return mapping[key]

def no_effect():
    pass
""",
    )

    result = analyze_function_summaries(tmp_path)
    summaries = _by_name(result)

    assert {
        SummaryKind.IDENTITY,
        SummaryKind.PASSTHROUGH_ARGUMENT,
        SummaryKind.RETURN_FROM_PARAMETER,
    } <= _kinds(summaries["identity"])
    assert SummaryKind.CONSTANT in _kinds(summaries["constant"])
    assert SummaryKind.TRANSFORMED_ARGUMENT in _kinds(
        summaries["transform"]
    )
    assert {
        SummaryKind.VALIDATOR,
        SummaryKind.PREDICATE_GUARD,
        SummaryKind.ABORTIVE_GUARD,
    } <= _kinds(summaries["validate"])
    assert SummaryKind.SOURCE in _kinds(summaries["source"])
    assert SummaryKind.SINK in _kinds(summaries["sink"])
    assert SummaryKind.WRAPPER in _kinds(summaries["wrapper"])
    assert SummaryKind.RECEIVER_OR_FIELD_WRITE in _kinds(
        summaries["Store.put"]
    )
    assert SummaryKind.COLLECTION_INSERT in _kinds(
        summaries["Store.put"]
    )
    assert {
        SummaryKind.RECEIVER_OR_FIELD_READ,
        SummaryKind.RETURN_FROM_RECEIVER,
    } <= _kinds(summaries["Store.get"])
    assert SummaryKind.COLLECTION_EXTRACT in _kinds(
        summaries["extract"]
    )
    assert _kinds(summaries["no_effect"]) == {SummaryKind.UNKNOWN}
    assert not result.gaps
    assert result.target == "."
    assert str(tmp_path).replace("\\", "/") not in json_text(result.to_dict())


def test_wrapper_propagates_validator_effect_to_caller(tmp_path: Path):
    _write(
        tmp_path / "module.py",
        """
def validate(value):
    if not value:
        raise ValueError("missing")
    return value

def outer(candidate):
    return validate(candidate)
""",
    )

    result = analyze_function_summaries(tmp_path)
    outer = _by_name(result)["outer"]
    propagated = [
        effect
        for effect in outer.effects
        if effect.kind == SummaryKind.VALIDATOR and not effect.direct
    ]

    assert propagated
    assert propagated[0].parameter_index == 0
    assert propagated[0].via == ("validate",)


def test_call_graph_sort_handles_parameter_and_literal_bindings(
    tmp_path: Path,
):
    _write(
        tmp_path / "module.py",
        """
def validate(value):
    if not value:
        raise ValueError("missing")
    return value

def outer(candidate):
    validate(candidate)
    validate("constant")
""",
    )

    first = analyze_function_summaries(tmp_path)
    second = analyze_function_summaries(tmp_path)

    assert first.to_dict() == second.to_dict()
    assert _by_name(first)["outer"].callees == ("validate",)


def test_sanitizer_summary_tracks_whether_return_value_is_used(
    tmp_path: Path,
):
    _write(
        tmp_path / "module.py",
        """
def sanitize(value):
    return value.strip()

def ignored(candidate):
    sanitize(candidate)
    return candidate

def assigned(candidate):
    candidate = sanitize(candidate)
    return candidate
""",
    )

    result = analyze_function_summaries(tmp_path)
    summaries = _by_name(result)
    ignored = [
        effect
        for effect in summaries["ignored"].effects
        if effect.kind == SummaryKind.SANITIZER and not effect.direct
    ]
    assigned = [
        effect
        for effect in summaries["assigned"].effects
        if effect.kind == SummaryKind.SANITIZER and not effect.direct
    ]

    assert ignored
    assert all(effect.result_used is False for effect in ignored)
    assert assigned
    assert all(effect.result_used is True for effect in assigned)


def test_recursive_call_graph_uses_one_scc_and_stabilizes(tmp_path: Path):
    _write(
        tmp_path / "module.py",
        """
def left(value):
    if not value:
        return value
    return right(value)

def right(value):
    if not value:
        return value
    return left(value)
""",
    )

    result = analyze_function_summaries(tmp_path)
    metrics = dict(result.metrics)
    summaries = _by_name(result)

    assert metrics["recursive_scc_count"] == 1
    assert summaries["left"].scc_id == summaries["right"].scc_id
    assert not any(
        gap.code == "function_summary_fixpoint_limit_reached"
        for gap in result.gaps
    )


def test_file_function_and_edge_limits_emit_explicit_gaps(tmp_path: Path):
    _write(
        tmp_path / "a.py",
        """
def first(value):
    return second(value)

def second(value):
    return value
""",
    )
    _write(
        tmp_path / "b.py",
        """
def third(value):
    return value
""",
    )

    result = analyze_function_summaries(
        tmp_path,
        FunctionSummaryLimits(
            max_files=1,
            max_functions=1,
            max_call_edges=1,
            max_scc_iterations=2,
            max_summaries_per_function=1,
            max_call_depth=1,
        ),
    )
    codes = {gap.code for gap in result.gaps}

    assert "function_summary_file_limit_reached" in codes
    assert "function_summary_function_limit_reached" in codes
    assert "function_summary_per_function_limit_reached" in codes
    assert dict(result.metrics)["limit_hit_count"] >= 3


def test_parse_failure_is_a_gap_not_a_clean_result(tmp_path: Path):
    _write(tmp_path / "broken.py", "def broken(:\n    pass\n")

    result = analyze_function_summaries(tmp_path)

    assert not result.summaries
    assert [gap.code for gap in result.gaps] == [
        "function_summary_parse_failure"
    ]
    assert result.gaps[0].line == 1


def test_summary_analysis_is_deterministic(tmp_path: Path):
    _write(
        tmp_path / "module.py",
        """
def normalize(value):
    return value.strip()
""",
    )

    first = analyze_function_summaries(tmp_path)
    second = analyze_function_summaries(tmp_path)

    assert first.to_dict() == second.to_dict()
    assert first.deterministic_digest == second.deterministic_digest


def test_summary_scope_excludes_virtual_environment_artifacts(
    tmp_path: Path,
):
    _write(
        tmp_path / "app.py",
        "def app(value):\n    return value\n",
    )
    _write(
        tmp_path / ".venv-local" / "site-packages" / "foreign.py",
        "def foreign(value):\n    return value\n",
    )

    result = analyze_function_summaries(tmp_path)

    assert [summary.qualified_name for summary in result.summaries] == [
        "app"
    ]
    assert dict(result.metrics)["excluded_file_count"] == 1


def json_text(value) -> str:
    return json.dumps(value, sort_keys=True)
