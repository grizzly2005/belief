"""
BELIEF — Belief dependency graph.

Organizes beliefs into a directed acyclic graph based on their dependency
relationships. Enables cascade impact analysis and identification of
structurally fragile nodes (high dependents + weak justification).
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .models import Belief, JustificationCategory

logger = logging.getLogger("belief.graph")


@dataclass
class GraphNode:
    """A node in the belief dependency graph."""

    belief: Belief
    dependents: list[str] = field(default_factory=list)  # beliefs that depend on this one
    depth: int = 0  # distance from root

    @property
    def structural_risk(self) -> float:
        """
        High risk = many dependents + weak justification.
        These are the nodes where a single violation cascades maximally.
        """
        dependent_factor = min(len(self.dependents) / 10.0, 1.0)
        weakness_factor = 1.0 - self.belief.justification.robustness_score
        return dependent_factor * 0.5 + weakness_factor * 0.5


class BeliefGraph:
    """
    Directed acyclic graph of belief dependencies.

    Edges point from dependency to dependent:
    if B depends on A, the edge is A → B.
    """

    def __init__(self):
        self.nodes: dict[str, GraphNode] = {}   # belief_id → node
        self.edges: dict[str, set[str]] = defaultdict(set)  # from → {to}
        self.reverse_edges: dict[str, set[str]] = defaultdict(set)  # to → {from}

    def add_beliefs(self, beliefs: list[Belief]):
        """Add beliefs and build edges from dependency declarations."""
        # Add all nodes first
        for b in beliefs:
            self.nodes[b.id] = GraphNode(belief=b)

        # Build edges from dependency expressions
        # Dependencies reference predicate expressions, so we need to match
        expr_to_id: dict[str, str] = {}
        for b in beliefs:
            expr_to_id[b.predicate.expression.lower().strip()] = b.id

        for b in beliefs:
            for dep_expr in b.dependencies:
                dep_key = dep_expr.lower().strip()
                if dep_key in expr_to_id:
                    dep_id = expr_to_id[dep_key]
                    if dep_id != b.id:
                        self.edges[dep_id].add(b.id)
                        self.reverse_edges[b.id].add(dep_id)
                        self.nodes[dep_id].dependents.append(b.id)

        self._compute_depths()

    def cascade_impact(self, belief_id: str) -> list[str]:
        """
        If this belief is violated, which other beliefs collapse?
        Returns all transitively dependent belief IDs.
        """
        if belief_id not in self.nodes:
            return []

        impacted = []
        queue = deque([belief_id])
        visited = {belief_id}

        while queue:
            current = queue.popleft()
            for dependent in self.edges.get(current, set()):
                if dependent not in visited:
                    visited.add(dependent)
                    impacted.append(dependent)
                    queue.append(dependent)

        return impacted

    def fragile_roots(self, top_n: int = 10) -> list[GraphNode]:
        """
        Find the most structurally dangerous beliefs:
        many dependents + weak justification.
        """
        ranked = sorted(
            self.nodes.values(),
            key=lambda n: n.structural_risk,
            reverse=True,
        )
        return ranked[:top_n]

    def unjustified_foundations(self) -> list[GraphNode]:
        """
        Find C5/C6 beliefs that other beliefs depend on.
        These are the most dangerous: pure-faith foundations.
        """
        results = []
        for node in self.nodes.values():
            if (node.belief.justification in (
                    JustificationCategory.C5_NO_JUSTIFICATION,
                    JustificationCategory.C6_OPAQUE_INFERENCE)
                    and node.dependents):
                results.append(node)
        return sorted(results, key=lambda n: len(n.dependents), reverse=True)

    def belief_clusters(self) -> list[list[str]]:
        """Find connected components (clusters of related beliefs)."""
        visited = set()
        clusters = []

        for bid in self.nodes:
            if bid in visited:
                continue
            cluster = []
            queue = deque([bid])
            while queue:
                current = queue.popleft()
                if current in visited:
                    continue
                visited.add(current)
                cluster.append(current)
                for neighbor in self.edges.get(current, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)
                for neighbor in self.reverse_edges.get(current, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)
            if cluster:
                clusters.append(cluster)

        return sorted(clusters, key=len, reverse=True)

    def to_dict(self) -> dict:
        """Serialize for visualization."""
        return {
            "nodes": [
                {
                    "id": bid,
                    "predicate": node.belief.predicate.expression,
                    "justification": node.belief.justification.value,
                    "fragility": round(node.belief.fragility, 3),
                    "structural_risk": round(node.structural_risk, 3),
                    "depth": node.depth,
                    "dependent_count": len(node.dependents),
                    "scope": node.belief.scope.qualified_name,
                }
                for bid, node in self.nodes.items()
            ],
            "edges": [
                {"from": src, "to": tgt}
                for src, targets in self.edges.items()
                for tgt in targets
            ],
            "stats": {
                "total_nodes": len(self.nodes),
                "total_edges": sum(len(t) for t in self.edges.values()),
                "clusters": len(self.belief_clusters()),
                "fragile_roots": len(self.fragile_roots()),
                "unjustified_foundations": len(self.unjustified_foundations()),
            },
        }

    # ── Internal ──

    def _compute_depths(self):
        """Compute depth of each node (distance from roots)."""
        # Roots have no incoming edges
        roots = [
            bid for bid in self.nodes
            if bid not in self.reverse_edges or not self.reverse_edges[bid]
        ]

        queue = deque([(r, 0) for r in roots])
        visited = set()

        while queue:
            bid, depth = queue.popleft()
            if bid in visited:
                continue
            visited.add(bid)
            self.nodes[bid].depth = depth
            for dependent in self.edges.get(bid, set()):
                if dependent not in visited:
                    queue.append((dependent, depth + 1))

        # Handle cycles (shouldn't exist in a DAG, but defensive)
        for bid in self.nodes:
            if bid not in visited:
                self.nodes[bid].depth = -1
