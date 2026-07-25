"""Deterministic evidence graphs and semantic before/after comparison."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .models import AnalysisGap
from .observations import SemanticConcern, SemanticFlowAnalysis


EVIDENCE_GRAPH_SCHEMA_VERSION = "belief.evidence_graph.v1"
SEMANTIC_COMPARISON_SCHEMA_VERSION = "belief.semantic_comparison.v1"


class SemanticClassification(str, Enum):
    RESOLVED = "resolved"
    RESIDUAL = "residual"
    INTRODUCED = "introduced"
    SHIFTED = "shifted"
    PARTIALLY_MITIGATED = "partially_mitigated"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class EvidenceGraphLimits:
    """Hard node and edge bounds for evidence graph construction."""

    max_nodes: int = 10_000
    max_edges: int = 20_000

    def __post_init__(self) -> None:
        for name, value in self.to_dict().items():
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise ValueError(f"{name} must be a positive integer")

    def to_dict(self) -> dict[str, int]:
        return {
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
        }


@dataclass(frozen=True)
class EvidenceNode:
    node_id: str
    kind: str
    state: str
    semantic_identity: str
    file: str = ""
    function: str = ""
    line: int | None = None
    attributes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("node ID", self.node_id),
            ("node kind", self.kind),
            ("node state", self.state),
            ("node semantic identity", self.semantic_identity),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be non-empty")
        if self.line is not None and (
            not isinstance(self.line, int)
            or isinstance(self.line, bool)
            or self.line <= 0
        ):
            raise ValueError("evidence node line must be positive")
        _validate_attributes(self.attributes)

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.state,
            self.kind,
            self.semantic_identity,
            self.file,
            self.function,
            self.line or 0,
            self.node_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind,
            "state": self.state,
            "semantic_identity": self.semantic_identity,
            "file": self.file,
            "function": self.function,
            "line": self.line,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceEdge:
    source: str
    target: str
    kind: str
    state: str
    attributes: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        for label, value in (
            ("edge source", self.source),
            ("edge target", self.target),
            ("edge kind", self.kind),
            ("edge state", self.state),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be non-empty")
        _validate_attributes(self.attributes)

    @property
    def edge_id(self) -> str:
        return _semantic_digest(
            {
                "source": self.source,
                "target": self.target,
                "kind": self.kind,
                "state": self.state,
                "attributes": dict(self.attributes),
            }
        )

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.state,
            self.kind,
            self.source,
            self.target,
            self.attributes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "state": self.state,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceGraph:
    target: str
    state: str
    nodes: tuple[EvidenceNode, ...]
    edges: tuple[EvidenceEdge, ...]
    gaps: tuple[AnalysisGap, ...]
    limits: EvidenceGraphLimits
    metrics: tuple[tuple[str, int], ...]
    flow_digest: str
    schema_version: str = field(
        default=EVIDENCE_GRAPH_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        if not self.target or not self.state:
            raise ValueError("evidence graph target and state are required")
        if tuple(sorted(self.nodes, key=lambda item: item.sort_key)) != (
            self.nodes
        ):
            raise ValueError("evidence graph nodes must be sorted")
        if tuple(sorted(self.edges, key=lambda item: item.sort_key)) != (
            self.edges
        ):
            raise ValueError("evidence graph edges must be sorted")
        node_ids = {node.node_id for node in self.nodes}
        if len(node_ids) != len(self.nodes):
            raise ValueError("evidence graph node IDs must be unique")
        if any(
            edge.source not in node_ids or edge.target not in node_ids
            for edge in self.edges
        ):
            raise ValueError("evidence graph edge references unknown node")
        if len({edge.edge_id for edge in self.edges}) != len(self.edges):
            raise ValueError("evidence graph edges must be unique")
        if tuple(
            sorted(self.gaps, key=lambda gap: gap.sort_key)
        ) != self.gaps:
            raise ValueError("evidence graph gaps must be sorted")
        if tuple(sorted(set(self.metrics))) != self.metrics:
            raise ValueError("evidence graph metrics must be sorted")
        _validate_digest(self.flow_digest, "flow digest")

    @property
    def deterministic_digest(self) -> str:
        return _semantic_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "state": self.state,
            "nodes": [node.to_dict() for node in self.nodes],
            "edges": [edge.to_dict() for edge in self.edges],
            "gaps": [gap.to_dict() for gap in self.gaps],
            "limits": self.limits.to_dict(),
            "metrics": dict(self.metrics),
            "flow_digest": self.flow_digest,
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._semantic_dict()
        payload["deterministic_digest"] = self.deterministic_digest
        return payload


@dataclass(frozen=True)
class SemanticDelta:
    classification: SemanticClassification
    identity: str
    reason: str
    actionable: bool
    baseline_concern: str = ""
    candidate_concern: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.classification, SemanticClassification):
            raise ValueError("delta classification is invalid")
        if not self.identity or not self.reason:
            raise ValueError("delta identity and reason are required")
        if not isinstance(self.actionable, bool):
            raise ValueError("delta actionable must be boolean")
        if (
            self.classification == SemanticClassification.RESOLVED
            and self.actionable
        ):
            raise ValueError("resolved delta cannot be actionable")
        if (
            self.classification
            == SemanticClassification.INCONCLUSIVE
            and not self.actionable
        ):
            raise ValueError("inconclusive delta must be actionable")

    @property
    def sort_key(self) -> tuple[str, ...]:
        return (
            self.classification.value,
            self.identity,
            self.baseline_concern,
            self.candidate_concern,
            self.reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "classification": self.classification.value,
            "identity": self.identity,
            "reason": self.reason,
            "actionable": self.actionable,
            "baseline_concern": self.baseline_concern,
            "candidate_concern": self.candidate_concern,
        }


@dataclass(frozen=True)
class SemanticComparison:
    baseline_graph_digest: str
    candidate_graph_digest: str
    deltas: tuple[SemanticDelta, ...]
    gaps: tuple[AnalysisGap, ...]
    complete: bool
    metrics: tuple[tuple[str, int], ...]
    schema_version: str = field(
        default=SEMANTIC_COMPARISON_SCHEMA_VERSION,
        init=False,
    )

    def __post_init__(self) -> None:
        _validate_digest(
            self.baseline_graph_digest,
            "baseline graph digest",
        )
        _validate_digest(
            self.candidate_graph_digest,
            "candidate graph digest",
        )
        if tuple(
            sorted(self.deltas, key=lambda item: item.sort_key)
        ) != self.deltas:
            raise ValueError("semantic deltas must be sorted")
        if tuple(
            sorted(self.gaps, key=lambda gap: gap.sort_key)
        ) != self.gaps:
            raise ValueError("semantic comparison gaps must be sorted")
        if tuple(sorted(set(self.metrics))) != self.metrics:
            raise ValueError("semantic comparison metrics must be sorted")
        if self.complete and any(
            delta.classification
            == SemanticClassification.INCONCLUSIVE
            for delta in self.deltas
        ):
            raise ValueError(
                "complete comparison cannot contain inconclusive deltas"
            )

    @property
    def passed(self) -> bool:
        return self.complete and not any(
            delta.actionable for delta in self.deltas
        )

    @property
    def deterministic_digest(self) -> str:
        return _semantic_digest(self._semantic_dict())

    def _semantic_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "baseline_graph_digest": self.baseline_graph_digest,
            "candidate_graph_digest": self.candidate_graph_digest,
            "deltas": [delta.to_dict() for delta in self.deltas],
            "gaps": [gap.to_dict() for gap in self.gaps],
            "complete": self.complete,
            "passed": self.passed,
            "metrics": dict(self.metrics),
        }

    def to_dict(self) -> dict[str, Any]:
        payload = self._semantic_dict()
        payload["deterministic_digest"] = self.deterministic_digest
        return payload


def build_evidence_graph(
    flow: SemanticFlowAnalysis,
    state: str,
    *,
    limits: EvidenceGraphLimits | None = None,
) -> EvidenceGraph:
    """Build a bounded graph from one semantic-flow observation."""

    configured = limits or EvidenceGraphLimits()
    nodes: dict[str, EvidenceNode] = {}
    edges: dict[str, EvidenceEdge] = {}
    gaps = set(flow.gaps)

    for concern in flow.concerns:
        concern_id = _node_id(
            state,
            "concern",
            concern.deterministic_digest,
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=concern_id,
                kind="concern",
                state=state,
                semantic_identity=concern.root_cause.digest,
                file=concern.file,
                function=concern.function,
                line=concern.line,
                attributes=(
                    ("category", concern.category),
                    ("contract_id", concern.contract_id),
                    ("cwe", concern.cwe),
                ),
            ),
        )
        related = (
            (
                "resource",
                concern.resource.semantic_key,
                "affects_resource",
            ),
            ("source", concern.source, "originates_from"),
            ("sink", concern.sink, "reaches_sink"),
        )
        for kind, identity, edge_kind in related:
            node_id = _node_id(state, kind, identity)
            _add_node(
                nodes,
                EvidenceNode(
                    node_id=node_id,
                    kind=kind,
                    state=state,
                    semantic_identity=identity,
                    file=concern.file,
                    function=concern.function,
                ),
            )
            _add_edge(
                edges,
                EvidenceEdge(
                    source=concern_id,
                    target=node_id,
                    kind=edge_kind,
                    state=state,
                ),
            )
        for missing in sorted(set(concern.missing_states)):
            node_id = _node_id(
                state,
                "missing_state",
                f"{concern.root_cause.digest}:{missing}",
            )
            _add_node(
                nodes,
                EvidenceNode(
                    node_id=node_id,
                    kind="missing_state",
                    state=state,
                    semantic_identity=missing,
                    file=concern.file,
                    function=concern.function,
                ),
            )
            _add_edge(
                edges,
                EvidenceEdge(
                    source=concern_id,
                    target=node_id,
                    kind="missing_guarantee",
                    state=state,
                ),
            )

    for guard in flow.guards:
        guard_id = _node_id(state, "guard", guard.guard_id)
        resource_id = _node_id(
            state,
            "resource",
            guard.resource.semantic_key,
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=guard_id,
                kind="guard",
                state=state,
                semantic_identity=guard.guard_id,
                line=guard.line,
                attributes=(
                    ("dominates_sink", str(guard.dominates_sink).lower()),
                    ("result_used", str(guard.result_used).lower()),
                    ("state_property", guard.state_property),
                    ("state_value", guard.state_value),
                ),
            ),
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=resource_id,
                kind="resource",
                state=state,
                semantic_identity=guard.resource.semantic_key,
            ),
        )
        _add_edge(
            edges,
            EvidenceEdge(
                source=guard_id,
                target=resource_id,
                kind="guards_resource",
                state=state,
            ),
        )

    for transition in flow.transitions:
        transition_id = _node_id(
            state,
            "transition",
            transition.transition_id,
        )
        resource_id = _node_id(
            state,
            "resource",
            transition.resource.semantic_key,
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=transition_id,
                kind="transition",
                state=state,
                semantic_identity=transition.transition_id,
                line=transition.line,
                attributes=(
                    ("after", transition.after.value),
                    ("before", transition.before.value),
                    ("kind", transition.kind),
                    ("result_used", str(transition.result_used).lower()),
                ),
            ),
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=resource_id,
                kind="resource",
                state=state,
                semantic_identity=transition.resource.semantic_key,
            ),
        )
        _add_edge(
            edges,
            EvidenceEdge(
                source=transition_id,
                target=resource_id,
                kind="transitions_resource",
                state=state,
            ),
        )

    ordered_nodes = sorted(nodes.values(), key=lambda item: item.sort_key)
    observed_node_count = len(ordered_nodes)
    if observed_node_count > configured.max_nodes:
        gaps.add(
            AnalysisGap(
                code="evidence_graph_node_limit_reached",
                stage="evidence_graph",
                reason="Evidence nodes beyond the hard limit were discarded",
                limit_name="max_nodes",
                limit_value=configured.max_nodes,
                observed_value=observed_node_count,
            )
        )
        ordered_nodes = ordered_nodes[: configured.max_nodes]
    selected_ids = {node.node_id for node in ordered_nodes}
    ordered_edges = sorted(
        (
            edge
            for edge in edges.values()
            if edge.source in selected_ids and edge.target in selected_ids
        ),
        key=lambda item: item.sort_key,
    )
    observed_edge_count = len(ordered_edges)
    if observed_edge_count > configured.max_edges:
        gaps.add(
            AnalysisGap(
                code="evidence_graph_edge_limit_reached",
                stage="evidence_graph",
                reason="Evidence edges beyond the hard limit were discarded",
                limit_name="max_edges",
                limit_value=configured.max_edges,
                observed_value=observed_edge_count,
            )
        )
        ordered_edges = ordered_edges[: configured.max_edges]

    metrics = {
        "edge_count": len(ordered_edges),
        "gap_count": len(gaps),
        "node_count": len(ordered_nodes),
        "observed_edge_count": observed_edge_count,
        "observed_node_count": observed_node_count,
    }
    return EvidenceGraph(
        target=flow.target,
        state=state,
        nodes=tuple(ordered_nodes),
        edges=tuple(ordered_edges),
        gaps=tuple(sorted(gaps, key=lambda gap: gap.sort_key)),
        limits=configured,
        metrics=tuple(sorted(metrics.items())),
        flow_digest=flow.deterministic_digest,
    )


def compare_semantic_flows(
    baseline: SemanticFlowAnalysis,
    candidate: SemanticFlowAnalysis,
    *,
    graph_limits: EvidenceGraphLimits | None = None,
) -> SemanticComparison:
    """Classify semantic root causes without line-based pairing."""

    baseline_graph = build_evidence_graph(
        baseline,
        "baseline",
        limits=graph_limits,
    )
    candidate_graph = build_evidence_graph(
        candidate,
        "candidate",
        limits=graph_limits,
    )
    baseline_groups = _concern_groups(baseline.concerns)
    candidate_groups = _concern_groups(candidate.concerns)
    deltas = []
    unmatched_baseline = []
    unmatched_candidate = []

    for identity in sorted(set(baseline_groups) | set(candidate_groups)):
        before = baseline_groups.get(identity, [])
        after = candidate_groups.get(identity, [])
        paired = min(len(before), len(after))
        for index in range(paired):
            deltas.append(
                _matched_delta(
                    identity,
                    before[index],
                    after[index],
                )
            )
        unmatched_baseline.extend(before[paired:])
        unmatched_candidate.extend(after[paired:])

    shifted_pairs, unmatched_baseline, unmatched_candidate = (
        _pair_shifted(unmatched_baseline, unmatched_candidate)
    )
    deltas.extend(shifted_pairs)
    for concern in unmatched_baseline:
        deltas.append(
            SemanticDelta(
                classification=SemanticClassification.RESOLVED,
                identity=concern.root_cause.digest,
                reason="Root cause is absent from the candidate state",
                actionable=False,
                baseline_concern=concern.deterministic_digest,
            )
        )
    for concern in unmatched_candidate:
        deltas.append(
            SemanticDelta(
                classification=SemanticClassification.INTRODUCED,
                identity=concern.root_cause.digest,
                reason="Root cause appears only in the candidate state",
                actionable=True,
                candidate_concern=concern.deterministic_digest,
            )
        )

    gaps = tuple(
        sorted(
            set(baseline_graph.gaps) | set(candidate_graph.gaps),
            key=lambda gap: gap.sort_key,
        )
    )
    for gap in gaps:
        deltas.append(
            SemanticDelta(
                classification=SemanticClassification.INCONCLUSIVE,
                identity=_semantic_digest(gap.to_dict()),
                reason=f"{gap.stage}: {gap.reason}",
                actionable=True,
            )
        )
    ordered = tuple(sorted(deltas, key=lambda item: item.sort_key))
    counts = Counter(delta.classification.value for delta in ordered)
    metrics = {
        "actionable_count": sum(delta.actionable for delta in ordered),
        "delta_count": len(ordered),
        "gap_count": len(gaps),
    }
    for classification, count in sorted(counts.items()):
        metrics[f"classification_{classification}"] = count
    return SemanticComparison(
        baseline_graph_digest=baseline_graph.deterministic_digest,
        candidate_graph_digest=candidate_graph.deterministic_digest,
        deltas=ordered,
        gaps=gaps,
        complete=not gaps,
        metrics=tuple(sorted(metrics.items())),
    )


def _matched_delta(
    identity: str,
    baseline: SemanticConcern,
    candidate: SemanticConcern,
) -> SemanticDelta:
    before = set(baseline.missing_states)
    after = set(candidate.missing_states)
    if after < before:
        classification = SemanticClassification.PARTIALLY_MITIGATED
        reason = "Some required security states were added, but gaps remain"
    else:
        classification = SemanticClassification.RESIDUAL
        reason = "The same semantic root cause remains in the candidate"
    return SemanticDelta(
        classification=classification,
        identity=identity,
        reason=reason,
        actionable=True,
        baseline_concern=baseline.deterministic_digest,
        candidate_concern=candidate.deterministic_digest,
    )


def _pair_shifted(
    baseline: list[SemanticConcern],
    candidate: list[SemanticConcern],
) -> tuple[
    list[SemanticDelta],
    list[SemanticConcern],
    list[SemanticConcern],
]:
    by_similarity: dict[
        tuple[str, str, str],
        list[SemanticConcern],
    ] = defaultdict(list)
    for concern in candidate:
        by_similarity[_similarity_key(concern)].append(concern)
    for values in by_similarity.values():
        values.sort(key=lambda item: item.sort_key)

    deltas = []
    remaining_baseline = []
    consumed = set()
    for concern in sorted(baseline, key=lambda item: item.sort_key):
        choices = [
            item
            for item in by_similarity.get(_similarity_key(concern), [])
            if item.deterministic_digest not in consumed
        ]
        if not choices:
            remaining_baseline.append(concern)
            continue
        selected = choices[0]
        consumed.add(selected.deterministic_digest)
        identity = _semantic_digest(
            {
                "baseline": concern.root_cause.digest,
                "candidate": selected.root_cause.digest,
            }
        )
        deltas.append(
            SemanticDelta(
                classification=SemanticClassification.SHIFTED,
                identity=identity,
                reason=(
                    "A related root cause remains but its resource, source, "
                    "or sink identity changed"
                ),
                actionable=True,
                baseline_concern=concern.deterministic_digest,
                candidate_concern=selected.deterministic_digest,
            )
        )
    remaining_candidate = [
        concern
        for concern in candidate
        if concern.deterministic_digest not in consumed
    ]
    return deltas, remaining_baseline, remaining_candidate


def _concern_groups(
    concerns: Iterable[SemanticConcern],
) -> dict[str, list[SemanticConcern]]:
    result: dict[str, list[SemanticConcern]] = defaultdict(list)
    for concern in concerns:
        result[concern.root_cause.digest].append(concern)
    for values in result.values():
        values.sort(key=lambda item: item.sort_key)
    return result


def _similarity_key(
    concern: SemanticConcern,
) -> tuple[str, str, str]:
    return (
        concern.file,
        concern.category,
        concern.root_cause.security_property,
    )


def _add_node(
    values: dict[str, EvidenceNode],
    node: EvidenceNode,
) -> None:
    values.setdefault(node.node_id, node)


def _add_edge(
    values: dict[str, EvidenceEdge],
    edge: EvidenceEdge,
) -> None:
    values.setdefault(edge.edge_id, edge)


def _node_id(state: str, kind: str, identity: str) -> str:
    return _semantic_digest(
        {
            "state": state,
            "kind": kind,
            "identity": identity,
        }
    )


def _validate_attributes(
    attributes: tuple[tuple[str, str], ...],
) -> None:
    if tuple(sorted(attributes)) != attributes:
        raise ValueError("evidence attributes must be sorted")
    if len({key for key, _ in attributes}) != len(attributes):
        raise ValueError("evidence attribute keys must be unique")
    if any(not key or not isinstance(value, str) for key, value in attributes):
        raise ValueError("evidence attributes must be text")


def _validate_digest(value: str, label: str) -> None:
    if (
        len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{label} must be a lowercase SHA-256")


def _semantic_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "EVIDENCE_GRAPH_SCHEMA_VERSION",
    "SEMANTIC_COMPARISON_SCHEMA_VERSION",
    "EvidenceEdge",
    "EvidenceGraph",
    "EvidenceGraphLimits",
    "EvidenceNode",
    "SemanticClassification",
    "SemanticComparison",
    "SemanticDelta",
    "build_evidence_graph",
    "compare_semantic_flows",
]
