"""Deterministic evidence graphs and semantic before/after comparison."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable

from .models import AnalysisGap, SummaryKind
from .observations import SemanticConcern, SemanticFlowAnalysis
from .summaries import FunctionSummaryAnalysis


EVIDENCE_GRAPH_SCHEMA_VERSION = (
    "belief.semantic_evidence_graph.v1"
)
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
    max_paths: int = 5_000

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
            "max_paths": self.max_paths,
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
    column: int | None = None
    symbol: str = ""
    value: str = ""
    call_context: str = ""
    proof_type: str = ""
    provenance: tuple[str, ...] = ()
    confidence: float | None = None
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
        _validate_optional_position(self.line, "line")
        _validate_optional_position(self.column, "column", zero=True)
        _validate_provenance(self.provenance)
        _validate_confidence(self.confidence)
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
            self.column if self.column is not None else -1,
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
            "column": self.column,
            "symbol": self.symbol,
            "value": self.value,
            "call_context": self.call_context,
            "proof_type": self.proof_type,
            "provenance": list(self.provenance),
            "confidence": self.confidence,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidenceEdge:
    source: str
    target: str
    kind: str
    state: str
    provenance: tuple[str, ...] = ()
    confidence: float | None = None
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
        _validate_provenance(self.provenance)
        _validate_confidence(self.confidence)
        _validate_attributes(self.attributes)

    @property
    def edge_id(self) -> str:
        return _semantic_digest(
            {
                "source": self.source,
                "target": self.target,
                "kind": self.kind,
                "state": self.state,
                "provenance": list(self.provenance),
                "confidence": self.confidence,
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
            self.provenance,
            self.confidence if self.confidence is not None else -1.0,
            self.attributes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source": self.source,
            "target": self.target,
            "kind": self.kind,
            "state": self.state,
            "provenance": list(self.provenance),
            "confidence": self.confidence,
            "attributes": dict(self.attributes),
        }


@dataclass(frozen=True)
class EvidencePath:
    path_id: str
    kind: str
    state: str
    node_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    complete: bool
    confidence: float | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("path ID", self.path_id),
            ("path kind", self.kind),
            ("path state", self.state),
        ):
            if not isinstance(value, str) or not value:
                raise ValueError(f"{label} must be non-empty")
        if len(self.node_ids) < 2:
            raise ValueError(
                "evidence path must contain at least two nodes"
            )
        if len(self.edge_ids) != len(self.node_ids) - 1:
            raise ValueError(
                "evidence path edges must connect consecutive nodes"
            )
        if any(not value for value in self.node_ids):
            raise ValueError("evidence path node IDs must be non-empty")
        if any(not value for value in self.edge_ids):
            raise ValueError("evidence path edge IDs must be non-empty")
        if not isinstance(self.complete, bool):
            raise ValueError("evidence path completeness must be boolean")
        _validate_confidence(self.confidence)

    @property
    def sort_key(self) -> tuple[Any, ...]:
        return (
            self.state,
            self.kind,
            self.node_ids,
            self.edge_ids,
            self.path_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id,
            "kind": self.kind,
            "state": self.state,
            "node_ids": list(self.node_ids),
            "edge_ids": list(self.edge_ids),
            "complete": self.complete,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class EvidenceGraph:
    target: str
    state: str
    nodes: tuple[EvidenceNode, ...]
    edges: tuple[EvidenceEdge, ...]
    paths: tuple[EvidencePath, ...]
    gaps: tuple[AnalysisGap, ...]
    limits: EvidenceGraphLimits
    metrics: tuple[tuple[str, int], ...]
    flow_digest: str
    summary_digest: str = ""
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
            sorted(self.paths, key=lambda item: item.sort_key)
        ) != self.paths:
            raise ValueError("evidence graph paths must be sorted")
        edges_by_id = {
            edge.edge_id: edge
            for edge in self.edges
        }
        edge_ids = set(edges_by_id)
        if len({path.path_id for path in self.paths}) != len(
            self.paths
        ):
            raise ValueError("evidence graph path IDs must be unique")
        if any(
            set(path.node_ids) - node_ids
            or set(path.edge_ids) - edge_ids
            for path in self.paths
        ):
            raise ValueError(
                "evidence graph path references unknown evidence"
            )
        if any(
            any(
                edges_by_id[edge_id].source
                != path.node_ids[index]
                or edges_by_id[edge_id].target
                != path.node_ids[index + 1]
                for index, edge_id in enumerate(
                    path.edge_ids
                )
            )
            for path in self.paths
        ):
            raise ValueError(
                "evidence graph path order is inconsistent"
            )
        if tuple(
            sorted(self.gaps, key=lambda gap: gap.sort_key)
        ) != self.gaps:
            raise ValueError("evidence graph gaps must be sorted")
        if tuple(sorted(set(self.metrics))) != self.metrics:
            raise ValueError("evidence graph metrics must be sorted")
        _validate_digest(self.flow_digest, "flow digest")
        if self.summary_digest:
            _validate_digest(
                self.summary_digest,
                "summary digest",
            )

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
            "paths": [path.to_dict() for path in self.paths],
            "gaps": [gap.to_dict() for gap in self.gaps],
            "limits": self.limits.to_dict(),
            "metrics": dict(self.metrics),
            "flow_digest": self.flow_digest,
            "summary_digest": self.summary_digest,
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
    summaries: FunctionSummaryAnalysis | None = None,
    limits: EvidenceGraphLimits | None = None,
) -> EvidenceGraph:
    """Build a bounded graph from one semantic-flow observation."""

    configured = limits or EvidenceGraphLimits()
    nodes: dict[str, EvidenceNode] = {}
    edges: dict[str, EvidenceEdge] = {}
    paths: dict[str, EvidencePath] = {}
    gaps = set(flow.gaps)
    if summaries is not None:
        gaps.update(summaries.gaps)

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
                symbol=concern.contract_id,
                value=concern.evidence,
                call_context=concern.function,
                proof_type="semantic_contract",
                provenance=(
                    "belief.semantic",
                    f"contract:{concern.contract_id}",
                ),
                confidence=concern.confidence,
                attributes=(
                    ("category", concern.category),
                    ("contract_id", concern.contract_id),
                    ("cwe", concern.cwe),
                    (
                        "missing_states",
                        ",".join(concern.missing_states),
                    ),
                ),
            ),
        )
        source_id = _node_id(
            state,
            "source",
            f"{concern.deterministic_digest}:source",
        )
        sink_id = _node_id(
            state,
            "sink",
            f"{concern.deterministic_digest}:sink",
        )
        resource_id = _node_id(
            state,
            "resource",
            (
                f"{concern.file}:{concern.function}:"
                f"{concern.resource.semantic_key}"
            ),
        )
        _add_node(
            nodes,
            _concern_related_node(
                concern,
                node_id=source_id,
                kind="source",
                identity=concern.source,
                state=state,
            ),
        )
        _add_node(
            nodes,
            _concern_related_node(
                concern,
                node_id=sink_id,
                kind="sink",
                identity=concern.sink,
                state=state,
            ),
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=resource_id,
                kind="resource",
                state=state,
                semantic_identity=(
                    concern.resource.semantic_key
                ),
                file=concern.file,
                function=concern.function,
                line=concern.line,
                symbol=concern.resource.symbol,
                value=concern.resource.semantic_key,
                call_context=concern.function,
                proof_type="resource_identity",
                provenance=("belief.semantic",),
                confidence=concern.confidence,
            ),
        )
        source_edge = EvidenceEdge(
            source=source_id,
            target=concern_id,
            kind="value_flow",
            state=state,
            provenance=("belief.semantic",),
            confidence=concern.confidence,
        )
        sink_edge = EvidenceEdge(
            source=concern_id,
            target=sink_id,
            kind="reaches_sink",
            state=state,
            provenance=("belief.semantic",),
            confidence=concern.confidence,
        )
        resource_edge = EvidenceEdge(
            source=concern_id,
            target=resource_id,
            kind="resource_bound_to",
            state=state,
            provenance=("belief.semantic",),
            confidence=concern.confidence,
        )
        for edge in (
            source_edge,
            sink_edge,
            resource_edge,
        ):
            _add_edge(edges, edge)
        _add_path(
            paths,
            EvidencePath(
                path_id=_path_id(
                    state,
                    concern.contract_id,
                    (source_id, concern_id, sink_id),
                ),
                kind="source_to_sink",
                state=state,
                node_ids=(
                    source_id,
                    concern_id,
                    sink_id,
                ),
                edge_ids=(
                    source_edge.edge_id,
                    sink_edge.edge_id,
                ),
                complete=True,
                confidence=concern.confidence,
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
                    line=concern.line,
                    symbol=missing,
                    value="missing",
                    call_context=concern.function,
                    proof_type="missing_security_state",
                    provenance=("belief.semantic",),
                    confidence=concern.confidence,
                ),
            )
            _add_edge(
                edges,
                EvidenceEdge(
                    source=concern_id,
                    target=node_id,
                    kind="missing_guarantee",
                    state=state,
                    provenance=("belief.semantic",),
                    confidence=concern.confidence,
                ),
            )

    if summaries is not None:
        _add_summary_evidence(
            summaries,
            state,
            nodes,
            edges,
            paths,
        )

    for guard in flow.guards:
        guard_id = _node_id(state, "guard", guard.guard_id)
        resource_id = _node_id(
            state,
            "resource",
            (
                f"{guard.file}:{guard.function}:"
                f"{guard.resource.semantic_key}"
            ),
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=guard_id,
                kind="guard",
                state=state,
                semantic_identity=guard.guard_id,
                file=guard.file,
                function=guard.function,
                line=guard.line,
                column=guard.column,
                symbol=guard.effect,
                value=guard.state_value,
                proof_type="guard_effect",
                provenance=("belief.semantic",),
                attributes=(
                    ("abortive", str(guard.abortive).lower()),
                    ("branch", guard.branch),
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
                file=guard.file,
                function=guard.function,
                line=guard.line,
                column=guard.column,
                symbol=guard.resource.symbol,
                value=guard.resource.semantic_key,
                proof_type="resource_identity",
                provenance=("belief.semantic",),
            ),
        )
        _add_edge(
            edges,
            EvidenceEdge(
                source=guard_id,
                target=resource_id,
                kind="guarded_by",
                state=state,
                provenance=("belief.semantic",),
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
            (
                f"{transition.file}:{transition.function}:"
                f"{transition.resource.semantic_key}"
            ),
        )
        _add_node(
            nodes,
            EvidenceNode(
                node_id=transition_id,
                kind="transition",
                state=state,
                semantic_identity=transition.transition_id,
                file=transition.file,
                function=transition.function,
                line=transition.line,
                column=transition.column,
                symbol=transition.kind,
                value=(
                    f"{transition.before.value}"
                    f"->{transition.after.value}"
                ),
                call_context=transition.before.context,
                proof_type="security_state_transition",
                provenance=("belief.semantic",),
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
                file=transition.file,
                function=transition.function,
                line=transition.line,
                column=transition.column,
                symbol=transition.resource.symbol,
                value=transition.resource.semantic_key,
                call_context=transition.before.context,
                proof_type="resource_identity",
                provenance=("belief.semantic",),
            ),
        )
        _add_edge(
            edges,
            EvidenceEdge(
                source=transition_id,
                target=resource_id,
                kind="transitions_resource",
                state=state,
                provenance=("belief.semantic",),
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
    selected_edge_ids = {
        edge.edge_id
        for edge in ordered_edges
    }
    ordered_paths = sorted(
        (
            path
            for path in paths.values()
            if set(path.node_ids) <= selected_ids
            and set(path.edge_ids) <= selected_edge_ids
        ),
        key=lambda item: item.sort_key,
    )
    observed_path_count = len(ordered_paths)
    if observed_path_count > configured.max_paths:
        gaps.add(
            AnalysisGap(
                code="evidence_graph_path_limit_reached",
                stage="evidence_graph",
                reason=(
                    "Evidence paths beyond the hard limit "
                    "were discarded"
                ),
                limit_name="max_paths",
                limit_value=configured.max_paths,
                observed_value=observed_path_count,
            )
        )
        ordered_paths = ordered_paths[: configured.max_paths]

    metrics = {
        "edge_count": len(ordered_edges),
        "gap_count": len(gaps),
        "node_count": len(ordered_nodes),
        "observed_edge_count": observed_edge_count,
        "observed_node_count": observed_node_count,
        "observed_path_count": observed_path_count,
        "path_count": len(ordered_paths),
        "summary_count": (
            len(summaries.summaries)
            if summaries is not None
            else 0
        ),
    }
    if summaries is not None:
        summary_metrics = dict(summaries.metrics)
        metrics["summary_gap_count"] = len(summaries.gaps)
        metrics["summary_excluded_out_of_focus_gap_count"] = (
            summary_metrics.get(
                "excluded_out_of_focus_gap_count",
                0,
            )
        )
    for kind, count in sorted(
        Counter(node.kind for node in ordered_nodes).items()
    ):
        metrics[f"nodes_{kind}"] = count
    for kind, count in sorted(
        Counter(edge.kind for edge in ordered_edges).items()
    ):
        metrics[f"edges_{kind}"] = count
    for kind, count in sorted(
        Counter(path.kind for path in ordered_paths).items()
    ):
        metrics[f"paths_{kind}"] = count
    return EvidenceGraph(
        target=flow.target,
        state=state,
        nodes=tuple(ordered_nodes),
        edges=tuple(ordered_edges),
        paths=tuple(ordered_paths),
        gaps=tuple(sorted(gaps, key=lambda gap: gap.sort_key)),
        limits=configured,
        metrics=tuple(sorted(metrics.items())),
        flow_digest=flow.deterministic_digest,
        summary_digest=(
            summaries.deterministic_digest
            if summaries is not None
            else ""
        ),
    )


def _concern_related_node(
    concern: SemanticConcern,
    *,
    node_id: str,
    kind: str,
    identity: str,
    state: str,
) -> EvidenceNode:
    return EvidenceNode(
        node_id=node_id,
        kind=kind,
        state=state,
        semantic_identity=identity,
        file=concern.file,
        function=concern.function,
        line=concern.line,
        symbol=identity,
        value=identity,
        call_context=concern.function,
        proof_type=f"semantic_{kind}",
        provenance=(
            "belief.semantic",
            f"contract:{concern.contract_id}",
        ),
        confidence=concern.confidence,
    )


def _add_summary_evidence(
    summaries: FunctionSummaryAnalysis,
    state: str,
    nodes: dict[str, EvidenceNode],
    edges: dict[str, EvidenceEdge],
    paths: dict[str, EvidencePath],
) -> None:
    summaries_by_name = {
        summary.qualified_name: summary
        for summary in summaries.summaries
    }
    for summary in summaries.summaries:
        function_identity = _function_identity(
            summary.file,
            summary.qualified_name,
        )
        function_id = _node_id(
            state,
            "function",
            function_identity,
        )
        lines = [
            effect.line
            for effect in summary.effects
            if effect.line is not None
        ]
        function_line = min(lines) if lines else None
        _add_node(
            nodes,
            EvidenceNode(
                node_id=function_id,
                kind="function",
                state=state,
                semantic_identity=function_identity,
                file=summary.file,
                function=summary.qualified_name,
                line=function_line,
                symbol=summary.qualified_name,
                value="complete" if summary.complete else "incomplete",
                call_context=summary.qualified_name,
                proof_type="function_summary",
                provenance=("belief.function_summary",),
                attributes=(
                    ("complete", str(summary.complete).lower()),
                    ("iterations", str(summary.iterations)),
                    ("scc_id", str(summary.scc_id)),
                ),
            ),
        )
        for callee in summary.callees:
            callee_summary = summaries_by_name.get(callee)
            callee_identity = _function_identity(
                (
                    callee_summary.file
                    if callee_summary is not None
                    else summary.file
                ),
                callee,
            )
            callee_id = _node_id(
                state,
                "function",
                callee_identity,
            )
            _add_node(
                nodes,
                EvidenceNode(
                    node_id=callee_id,
                    kind="function",
                    state=state,
                    semantic_identity=callee_identity,
                    file=summary.file,
                    function=callee,
                    symbol=callee,
                    value="callee",
                    call_context=summary.qualified_name,
                    proof_type="call_graph",
                    provenance=("belief.function_summary",),
                ),
            )
            edge = EvidenceEdge(
                source=function_id,
                target=callee_id,
                kind="invokes",
                state=state,
                provenance=("belief.function_summary",),
            )
            _add_edge(edges, edge)
            _add_path(
                paths,
                EvidencePath(
                    path_id=_path_id(
                        state,
                        "invokes",
                        (function_id, callee_id),
                    ),
                    kind="call",
                    state=state,
                    node_ids=(function_id, callee_id),
                    edge_ids=(edge.edge_id,),
                    complete=summary.complete,
                ),
            )
        for effect in summary.effects:
            effect_material = _semantic_digest(
                effect.to_dict()
            )
            effect_kind = _effect_node_kind(effect.kind)
            effect_id = _node_id(
                state,
                effect_kind,
                f"{function_identity}:{effect_material}",
            )
            _add_node(
                nodes,
                EvidenceNode(
                    node_id=effect_id,
                    kind=effect_kind,
                    state=state,
                    semantic_identity=effect_material,
                    file=summary.file,
                    function=summary.qualified_name,
                    line=effect.line,
                    symbol=effect.value or effect.kind.value,
                    value=effect.value,
                    call_context=effect.context,
                    proof_type=effect.kind.value,
                    provenance=(
                        "belief.function_summary",
                        (
                            "direct"
                            if effect.direct
                            else "propagated"
                        ),
                    ),
                    attributes=(
                        ("direct", str(effect.direct).lower()),
                        (
                            "parameter_index",
                            (
                                str(effect.parameter_index)
                                if effect.parameter_index
                                is not None
                                else ""
                            ),
                        ),
                        (
                            "result_used",
                            str(effect.result_used).lower(),
                        ),
                        ("via", ",".join(effect.via)),
                    ),
                ),
            )
            summary_edge = EvidenceEdge(
                source=function_id,
                target=effect_id,
                kind="has_effect",
                state=state,
                provenance=("belief.function_summary",),
            )
            _add_edge(edges, summary_edge)
            node_ids = [function_id, effect_id]
            edge_ids = [summary_edge.edge_id]
            if effect.resource is not None:
                resource_id = _node_id(
                    state,
                    "resource",
                    (
                        f"{function_identity}:"
                        f"{effect.resource.semantic_key}"
                    ),
                )
                _add_node(
                    nodes,
                    EvidenceNode(
                        node_id=resource_id,
                        kind="resource",
                        state=state,
                        semantic_identity=(
                            effect.resource.semantic_key
                        ),
                        file=summary.file,
                        function=summary.qualified_name,
                        line=effect.line,
                        symbol=effect.resource.symbol,
                        value=effect.resource.semantic_key,
                        call_context=effect.context,
                        proof_type="resource_identity",
                        provenance=(
                            "belief.function_summary",
                        ),
                    ),
                )
                resource_edge = EvidenceEdge(
                    source=effect_id,
                    target=resource_id,
                    kind="acts_on",
                    state=state,
                    provenance=(
                        "belief.function_summary",
                    ),
                )
                _add_edge(edges, resource_edge)
                node_ids.append(resource_id)
                edge_ids.append(resource_edge.edge_id)
            _add_path(
                paths,
                EvidencePath(
                    path_id=_path_id(
                        state,
                        effect.kind.value,
                        tuple(node_ids),
                    ),
                    kind="summary_effect",
                    state=state,
                    node_ids=tuple(node_ids),
                    edge_ids=tuple(edge_ids),
                    complete=summary.complete,
                ),
            )


def _function_identity(file: str, qualified_name: str) -> str:
    if "::" in qualified_name:
        return qualified_name
    return f"{file}::{qualified_name}"


def _effect_node_kind(kind: SummaryKind) -> str:
    return {
        SummaryKind.SOURCE: "source",
        SummaryKind.SINK: "sink",
        SummaryKind.SANITIZER: "sanitizer",
        SummaryKind.VALIDATOR: "guard",
        SummaryKind.PREDICATE_GUARD: "guard",
        SummaryKind.ABORTIVE_GUARD: "guard",
        SummaryKind.PASSTHROUGH_ARGUMENT: "argument",
        SummaryKind.TRANSFORMED_ARGUMENT: "transform",
        SummaryKind.RETURN_FROM_PARAMETER: "return",
        SummaryKind.RETURN_FROM_RECEIVER: "return",
        SummaryKind.RECEIVER_OR_FIELD_READ: "field",
        SummaryKind.RECEIVER_OR_FIELD_WRITE: "field",
        SummaryKind.COLLECTION_INSERT: "collection",
        SummaryKind.COLLECTION_EXTRACT: "collection",
        SummaryKind.WRAPPER: "call",
        SummaryKind.CONSTANT: "value",
        SummaryKind.IDENTITY: "value",
        SummaryKind.UNKNOWN: "unknown",
    }.get(kind, "summary_effect")


def compare_semantic_flows(
    baseline: SemanticFlowAnalysis,
    candidate: SemanticFlowAnalysis,
    *,
    baseline_summaries: FunctionSummaryAnalysis | None = None,
    candidate_summaries: FunctionSummaryAnalysis | None = None,
    graph_limits: EvidenceGraphLimits | None = None,
) -> SemanticComparison:
    """Classify semantic root causes without line-based pairing."""

    baseline_graph = build_evidence_graph(
        baseline,
        "baseline",
        summaries=baseline_summaries,
        limits=graph_limits,
    )
    candidate_graph = build_evidence_graph(
        candidate,
        "candidate",
        summaries=candidate_summaries,
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
    current = values.get(node.node_id)
    if current is None or (
        current.proof_type == "call_graph"
        and node.proof_type == "function_summary"
    ):
        values[node.node_id] = node


def _add_edge(
    values: dict[str, EvidenceEdge],
    edge: EvidenceEdge,
) -> None:
    values.setdefault(edge.edge_id, edge)


def _add_path(
    values: dict[str, EvidencePath],
    path: EvidencePath,
) -> None:
    values.setdefault(path.path_id, path)


def _node_id(state: str, kind: str, identity: str) -> str:
    return _semantic_digest(
        {
            "state": state,
            "kind": kind,
            "identity": identity,
        }
    )


def _path_id(
    state: str,
    kind: str,
    node_ids: tuple[str, ...],
) -> str:
    return _semantic_digest(
        {
            "state": state,
            "kind": kind,
            "node_ids": list(node_ids),
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


def _validate_optional_position(
    value: int | None,
    label: str,
    *,
    zero: bool = False,
) -> None:
    minimum = 0 if zero else 1
    if value is not None and (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
    ):
        raise ValueError(
            f"evidence {label} must be at least {minimum}"
        )


def _validate_provenance(
    values: tuple[str, ...],
) -> None:
    if len(set(values)) != len(values) or any(
        not isinstance(value, str)
        or not value
        for value in values
    ):
        raise ValueError(
            "evidence provenance must contain unique text"
        )


def _validate_confidence(
    value: float | None,
) -> None:
    if value is not None and (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not 0.0 <= float(value) <= 1.0
    ):
        raise ValueError(
            "evidence confidence must be between zero and one"
        )


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
    "EvidencePath",
    "SemanticClassification",
    "SemanticComparison",
    "SemanticDelta",
    "build_evidence_graph",
    "compare_semantic_flows",
]
