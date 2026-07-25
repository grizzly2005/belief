"""EvidenceGraph and semantic comparison contracts."""

from __future__ import annotations

from pathlib import Path

import pytest

from belief.semantic import analyze_semantic_flow
from belief.semantic.evidence import (
    EvidenceGraphLimits,
    SemanticClassification,
    build_evidence_graph,
    compare_semantic_flows,
)


pytestmark = pytest.mark.security


def _flow(tmp_path: Path, source: str):
    path = tmp_path / "module.py"
    path.write_text(source, encoding="utf-8")
    return analyze_semantic_flow(tmp_path)


def _classifications(comparison) -> set[SemanticClassification]:
    return {
        delta.classification
        for delta in comparison.deltas
    }


def test_evidence_graph_is_deterministic_and_referentially_valid(
    tmp_path: Path,
):
    flow = _flow(
        tmp_path,
        """
def go(target):
    return redirect(target)
""",
    )

    first = build_evidence_graph(flow, "candidate")
    second = build_evidence_graph(flow, "candidate")
    node_ids = {node.node_id for node in first.nodes}

    assert first.to_dict() == second.to_dict()
    assert first.deterministic_digest == second.deterministic_digest
    assert first.nodes
    assert first.edges
    assert all(
        edge.source in node_ids and edge.target in node_ids
        for edge in first.edges
    )


def test_semantic_comparison_classifies_resolved_and_introduced(
    tmp_path: Path,
):
    vulnerable = _flow(
        tmp_path,
        """
def go(target):
    return redirect(target)
""",
    )
    secure = _flow(
        tmp_path,
        """
def go(target):
    if not is_safe(target):
        raise ValueError("external")
    return redirect(target)
""",
    )

    resolved = compare_semantic_flows(vulnerable, secure)
    introduced = compare_semantic_flows(secure, vulnerable)

    assert _classifications(resolved) == {
        SemanticClassification.RESOLVED
    }
    assert resolved.passed is True
    assert _classifications(introduced) == {
        SemanticClassification.INTRODUCED
    }
    assert introduced.passed is False


def test_semantic_identity_survives_helper_and_parameter_rename(
    tmp_path: Path,
):
    baseline = _flow(
        tmp_path,
        """
def go(target):
    return redirect(target)
""",
    )
    candidate = _flow(
        tmp_path,
        """
def redirect_helper(destination):
    return redirect(destination)
""",
    )

    comparison = compare_semantic_flows(baseline, candidate)

    assert _classifications(comparison) == {
        SemanticClassification.RESIDUAL
    }
    assert comparison.passed is False


def test_semantic_comparison_marks_wrong_resource_as_shifted(
    tmp_path: Path,
):
    baseline = _flow(
        tmp_path,
        """
def go(target, other):
    return redirect(target)
""",
    )
    candidate = _flow(
        tmp_path,
        """
def go(target, other):
    return redirect(other)
""",
    )

    comparison = compare_semantic_flows(baseline, candidate)

    assert _classifications(comparison) == {
        SemanticClassification.SHIFTED
    }
    assert comparison.passed is False


def test_any_analysis_gap_is_inconclusive_and_never_passes(
    tmp_path: Path,
):
    complete = _flow(
        tmp_path,
        "def value():\n    return 1\n",
    )
    incomplete = _flow(
        tmp_path,
        "def broken(:\n    pass\n",
    )

    comparison = compare_semantic_flows(complete, incomplete)

    assert SemanticClassification.INCONCLUSIVE in _classifications(
        comparison
    )
    assert comparison.complete is False
    assert comparison.passed is False
    assert all(
        delta.actionable
        for delta in comparison.deltas
        if delta.classification
        == SemanticClassification.INCONCLUSIVE
    )


def test_evidence_graph_limits_create_explicit_gap(tmp_path: Path):
    flow = _flow(
        tmp_path,
        """
def go(target):
    return redirect(target)
""",
    )

    graph = build_evidence_graph(
        flow,
        "candidate",
        limits=EvidenceGraphLimits(max_nodes=1, max_edges=1),
    )

    assert "evidence_graph_node_limit_reached" in {
        gap.code for gap in graph.gaps
    }
    assert len(graph.nodes) == 1
    assert not graph.edges
