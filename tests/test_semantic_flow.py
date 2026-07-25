"""Core contracts for deterministic semantic flow-state analysis."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from belief.semantic import SemanticFlowLimits, analyze_semantic_flow


pytestmark = pytest.mark.security


def _analyze(tmp_path: Path, source: str, **kwargs):
    target = tmp_path / "module.py"
    target.write_text(source, encoding="utf-8")
    return analyze_semantic_flow(tmp_path, **kwargs)


def _contract_ids(result) -> set[str]:
    return {concern.contract_id for concern in result.concerns}


def test_semantic_flow_emits_versioned_root_cause_concern(
    tmp_path: Path,
):
    result = _analyze(
        tmp_path,
        """
import zlib

def unpack(payload):
    return zlib.decompress(payload)
""",
    )

    assert "BELIEF-SEM-RESOURCE-BOUND" in _contract_ids(result)
    concern = result.concerns[0]
    payload = concern.to_dict()
    assert payload["schema_version"] == "belief.semantic_concern.v1"
    assert payload["root_cause"]["digest"] == concern.root_cause.digest
    assert payload["resource"]["symbol"] == "payload"
    assert result.target == "."
    assert str(tmp_path).replace("\\", "/") not in json.dumps(
        result.to_dict(),
        sort_keys=True,
    )


def test_semantic_flow_is_deterministic(tmp_path: Path):
    source = """
def go(target):
    return redirect(target)
"""

    first = _analyze(tmp_path, source)
    second = analyze_semantic_flow(tmp_path)

    assert first.to_dict() == second.to_dict()
    assert first.deterministic_digest == second.deterministic_digest


def test_semantic_flow_reports_parse_and_resource_limits(
    tmp_path: Path,
):
    (tmp_path / "a.py").write_text(
        "def ok(value):\n    return value\n",
        encoding="utf-8",
    )
    (tmp_path / "b.py").write_text(
        "def broken(:\n    pass\n",
        encoding="utf-8",
    )

    limited = analyze_semantic_flow(
        tmp_path,
        limits=SemanticFlowLimits(
            max_files=1,
            max_functions=1,
            max_ast_nodes=100,
            max_concerns_per_function=1,
            max_guards_per_function=1,
            max_transitions_per_function=1,
        ),
    )
    parsed = analyze_semantic_flow(tmp_path)

    assert {gap.code for gap in limited.gaps} >= {"semantic_flow_file_limit_reached"}
    assert {gap.code for gap in parsed.gaps} >= {"semantic_flow_parse_failure"}


def test_concern_can_be_normalized_to_finding(tmp_path: Path):
    result = _analyze(
        tmp_path,
        """
def go(target):
    return redirect(target)
""",
    )

    finding = result.concerns[0].to_finding()

    assert finding.source == "belief.semantic"
    assert finding.rule_id == result.concerns[0].contract_id
    assert finding.metadata["root_cause_identity"]["digest"]
    assert finding.metadata["dataflow"]["missing_guarantees"]


def test_semantic_flow_excludes_virtual_environment_artifacts(
    tmp_path: Path,
):
    (tmp_path / "app.py").write_text(
        "def app(value):\n    return value\n",
        encoding="utf-8",
    )
    foreign = tmp_path / ".venv-proof" / "site-packages"
    foreign.mkdir(parents=True)
    (foreign / "foreign.py").write_text(
        "def recurse(value):\n    return recurse(value)\n",
        encoding="utf-8",
    )

    result = analyze_semantic_flow(tmp_path)

    assert not result.concerns
    assert dict(result.metrics)["excluded_file_count"] == 1
