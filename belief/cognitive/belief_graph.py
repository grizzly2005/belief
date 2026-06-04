"""
belief.cognitive.belief_graph — Probabilistic Belief Graph.

The core "brain" data structure. Transforms the flat list of Belief
sextuplets into a typed, weighted graph where:

  - Nodes  = beliefs (with confidence, justification, CWE, etc.)
  - Edges  = typed relations between beliefs
  - Cliques = groups of contradicting beliefs (vulnerability candidates)

Supports:
  1. Typed relations: DEPENDS_ON, CONTRADICTS, SUPPORTS, MITIGATES, WEAKENS
  2. Confidence propagation: a belief supported by strong evidence gains
     confidence; a belief contradicted by strong evidence loses it.
  3. Contradiction detection: finds pairs/cliques where beliefs conflict
     (same scope, opposite predicates, or explicit CONTRADICTS edges).
  4. Subgraph extraction: focus on one file, one CWE, one function.
  5. Serialization: to/from dict for persistence (MemoryEngine).

Does NOT modify belief/models.py — wraps existing Belief objects.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("belief.cognitive.belief_graph")


# ---------------------------------------------------------------------------
# Relation types
# ---------------------------------------------------------------------------

class RelationType(Enum):
    """Typed edge between two beliefs."""
    DEPENDS_ON   = "depends_on"    # B1 assumes B2 is true
    CONTRADICTS  = "contradicts"   # B1 and B2 cannot both be true
    SUPPORTS     = "supports"      # evidence for B2 also strengthens B1
    MITIGATES    = "mitigates"     # B1 is a security control that reduces B2's risk
    WEAKENS      = "weakens"       # B1's existence makes B2 less reliable


@dataclass
class Relation:
    """A directed, typed, weighted edge between two beliefs."""
    source_id: str
    target_id: str
    relation: RelationType
    weight: float = 1.0           # 0–1, how strong is this relation
    evidence: str = ""            # human-readable reason

    def to_dict(self) -> dict:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation.value,
            "weight": round(self.weight, 3),
            "evidence": self.evidence,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Relation":
        return cls(
            source_id=d["source_id"],
            target_id=d["target_id"],
            relation=RelationType(d["relation"]),
            weight=d.get("weight", 1.0),
            evidence=d.get("evidence", ""),
        )


# ---------------------------------------------------------------------------
# Contradiction cluster
# ---------------------------------------------------------------------------

@dataclass
class Contradiction:
    """A set of beliefs that cannot all be true simultaneously."""
    belief_ids: FrozenSet[str]
    severity: float = 0.0        # 0–1, how dangerous is this contradiction
    cwe: str = ""                # mapped CWE if known
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "belief_ids": sorted(self.belief_ids),
            "severity": round(self.severity, 3),
            "cwe": self.cwe,
            "description": self.description,
        }


# ---------------------------------------------------------------------------
# CognitiveGraph
# ---------------------------------------------------------------------------

class CognitiveGraph:
    """Probabilistic belief graph with typed relations and contradiction
    detection.

    Usage:
        from belief.cognitive.belief_graph import CognitiveGraph
        g = CognitiveGraph()
        g.add_beliefs(list_of_beliefs)
        g.auto_relate()               # infer relations from overlapping scopes
        g.propagate_confidence()       # Bayesian-ish update
        contras = g.find_contradictions()
    """

    def __init__(self):
        # belief_id → Belief object
        self._nodes: Dict[str, Any] = {}
        # (source_id, target_id) → Relation
        self._edges: Dict[Tuple[str, str], Relation] = {}
        # Adjacency lists
        self._out: Dict[str, Set[str]] = defaultdict(set)
        self._in: Dict[str, Set[str]] = defaultdict(set)

    # ---- node management --------------------------------------------------

    def add_belief(self, belief) -> str:
        """Add a belief node. Returns its id."""
        bid = belief.id
        self._nodes[bid] = belief
        return bid

    def add_beliefs(self, beliefs) -> int:
        """Bulk add. Returns count added."""
        for b in beliefs:
            self.add_belief(b)
        return len(beliefs)

    def get(self, belief_id: str):
        """Return the Belief object or None."""
        return self._nodes.get(belief_id)

    @property
    def beliefs(self) -> list:
        return list(self._nodes.values())

    @property
    def size(self) -> int:
        return len(self._nodes)

    # ---- edge management --------------------------------------------------

    def add_relation(self, rel: Relation) -> None:
        """Add a typed relation between two beliefs."""
        key = (rel.source_id, rel.target_id)
        self._edges[key] = rel
        self._out[rel.source_id].add(rel.target_id)
        self._in[rel.target_id].add(rel.source_id)

    def relate(self, src_id: str, tgt_id: str, rtype: RelationType,
               weight: float = 1.0, evidence: str = "") -> None:
        """Convenience: create and add a relation in one call."""
        self.add_relation(Relation(
            source_id=src_id, target_id=tgt_id,
            relation=rtype, weight=weight, evidence=evidence,
        ))

    def relations_from(self, bid: str) -> List[Relation]:
        return [self._edges[(bid, t)] for t in self._out.get(bid, set())]

    def relations_to(self, bid: str) -> List[Relation]:
        return [self._edges[(s, bid)] for s in self._in.get(bid, set())]

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    # ---- auto-relation inference ------------------------------------------

    def auto_relate(self) -> int:
        """Infer relations automatically from belief metadata.

        Rules:
          1. Same scope + opposite predicates → CONTRADICTS
          2. Explicit dependencies (belief.dependencies) → DEPENDS_ON
          3. Same scope + one is a mitigation pattern → MITIGATES
          4. Same file + overlapping lines + compatible predicates → SUPPORTS

        Returns the number of relations added.
        """
        added = 0
        beliefs = list(self._nodes.values())

        # Index by file+function for O(n) grouping instead of O(n²)
        by_scope: Dict[str, List] = defaultdict(list)
        for b in beliefs:
            key = f"{b.scope.file_path}:{b.scope.function_name or '*'}"
            by_scope[key].append(b)

        # 1. Explicit dependencies
        for b in beliefs:
            for dep_id in (b.dependencies or []):
                if dep_id in self._nodes and (b.id, dep_id) not in self._edges:
                    self.relate(b.id, dep_id, RelationType.DEPENDS_ON,
                                evidence="explicit dependency")
                    added += 1

        # 2. Same-scope contradiction / support detection
        for group in by_scope.values():
            for i, b1 in enumerate(group):
                for b2 in group[i+1:]:
                    if b1.id == b2.id:
                        continue
                    rel = self._infer_relation(b1, b2)
                    if rel and (b1.id, b2.id) not in self._edges:
                        self.add_relation(rel)
                        added += 1

        logger.info(f"auto_relate: inferred {added} relations")
        return added

    def _infer_relation(self, b1, b2) -> Optional[Relation]:
        """Heuristic: given two beliefs in the same scope, infer their
        relation from predicate text."""
        p1 = b1.predicate.expression.lower()
        p2 = b2.predicate.expression.lower()

        # Contradiction: one negates the other
        if self._is_negation(p1, p2):
            return Relation(
                source_id=b1.id, target_id=b2.id,
                relation=RelationType.CONTRADICTS,
                weight=0.8,
                evidence=f"predicate negation: '{p1}' vs '{p2}'",
            )

        # Mitigation patterns
        MITIGATE_KEYWORDS = {
            "sanitized", "validated", "escaped", "filtered",
            "checked", "verified", "authenticated", "authorized",
        }
        RISK_KEYWORDS = {
            "unsanitized", "unvalidated", "injectable", "tainted",
            "user_controlled", "untrusted", "exploitable",
        }
        p1_mitigates = any(k in p1 for k in MITIGATE_KEYWORDS)
        p2_risky = any(k in p2 for k in RISK_KEYWORDS)
        if p1_mitigates and p2_risky:
            return Relation(
                source_id=b1.id, target_id=b2.id,
                relation=RelationType.MITIGATES,
                weight=0.6,
                evidence="mitigation keyword match",
            )

        # Support: overlapping anchor lines + compatible predicate direction
        if (b1.predicate.anchor_lines and b2.predicate.anchor_lines and
                set(b1.predicate.anchor_lines) & set(b2.predicate.anchor_lines)):
            return Relation(
                source_id=b1.id, target_id=b2.id,
                relation=RelationType.SUPPORTS,
                weight=0.5,
                evidence="overlapping anchor lines",
            )

        return None

    @staticmethod
    def _is_negation(p1: str, p2: str) -> bool:
        """Detect whether one predicate is the negation of the other.

        v4 hotfix #3 (critique #43): the old implementation matched only
        textually-equivalent strings after a single operator flip. Real
        bridges never produce such matched pairs (bandit says "uses md5",
        dlint says "insecure hashlib"). Result: near-zero CONTRADICTS
        edges in practice, killing the core BELIEF hypothesis.

        This replacement uses three orthogonal strategies:

        1. Explicit negation prefix: "not X" vs "X" (original behavior).
        2. Operator flip applied to ALL occurrences (handles compound
           predicates like "x == 1 or y == 2" → "x != 1 or y != 2").
        3. Semantic keyword opposition: one predicate asserts safety
           (sanitized/validated/…) while the other asserts the matching
           risk (unsanitized/injectable/…). This catches the realistic
           cross-bridge case where both predicates TALK ABOUT the same
           code location but with opposite claims.
        """
        p1_s, p2_s = p1.strip().lower(), p2.strip().lower()
        if not p1_s or not p2_s:
            return False

        # Strategy 1: "not X" vs "X"
        if p1_s == f"not {p2_s}" or p2_s == f"not {p1_s}":
            return True
        if p1_s == f"not ({p2_s})" or p2_s == f"not ({p1_s})":
            return True

        # Strategy 2: operator flip — apply to ALL occurrences
        FLIPS = [
            (" <= ", " > "), (" >= ", " < "),
            (" < ", " >= "), (" > ", " <= "),
            (" == ", " != "), (" != ", " == "),
            (" is not ", " is "), (" is ", " is not "),
            (" not in ", " in "), (" in ", " not in "),
        ]
        for a, b in FLIPS:
            if a in p1_s and p1_s.replace(a, b) == p2_s:
                return True
            if a in p2_s and p2_s.replace(a, b) == p1_s:
                return True

        # Strategy 3: semantic opposition via safety/risk keyword families.
        # Both predicates must refer to overlapping variables/identifiers
        # (else we'd match unrelated assertions) AND claim opposite things.
        SAFE = {"sanitized", "validated", "escaped", "filtered",
                "safe", "trusted", "verified", "authenticated",
                "authorized", "parameterized", "checked"}
        RISK = {"unsanitized", "unvalidated", "injectable", "tainted",
                "untrusted", "exploitable", "user_controlled",
                "user-controlled", "unsafe", "vulnerable",
                "insecure", "weak"}

        def tokens(s: str) -> set:
            import re
            return set(re.findall(r"[a-z][a-z0-9_]+", s))

        t1, t2 = tokens(p1_s), tokens(p2_s)
        p1_safe = bool(t1 & SAFE)
        p1_risk = bool(t1 & RISK)
        p2_safe = bool(t2 & SAFE)
        p2_risk = bool(t2 & RISK)

        opposing = (p1_safe and p2_risk) or (p1_risk and p2_safe)
        # Require shared content word (not just safety/risk marker) so we
        # don't flag "X is validated" vs "Y is tainted" when X≠Y.
        CONTENT_STOPWORDS = SAFE | RISK | {
            "the", "a", "an", "is", "are", "be", "not", "of", "in", "to",
            "and", "or", "that", "this", "for",
        }
        shared_content = (t1 & t2) - CONTENT_STOPWORDS
        return opposing and bool(shared_content)

    # ---- confidence propagation (Bayesian-inspired) -------------------------

    def propagate_confidence(self, iterations: int = 3, decay: float = 0.1):
        """Bayesian-inspired confidence propagation through the graph.

        Each edge type has a different effect on the target's confidence:
          - SUPPORTS:    P(H|E) increases — evidence strengthens hypothesis
          - CONTRADICTS: P(H|E) decreases — counter-evidence weakens it
          - MITIGATES:   partial decrease — mitigation reduces risk
          - WEAKENS:     minor decrease — reliability concern

        Uses log-odds form for stable numeric updates:
          logit(p) = log(p / (1-p))
          update:   logit(p) += delta
          recover:  p = sigmoid(logit(p))
        """
        import math

        def _logit(p: float) -> float:
            p = max(0.01, min(0.99, p))
            return math.log(p / (1 - p))

        def _sigmoid(x: float) -> float:
            return 1.0 / (1.0 + math.exp(-max(-20, min(20, x))))

        for _it in range(iterations):
            deltas: Dict[str, float] = defaultdict(float)
            for (src_id, tgt_id), rel in self._edges.items():
                src = self._nodes.get(src_id)
                if src is None:
                    continue
                src_strength = src.confidence_score * rel.weight * decay
                if rel.relation == RelationType.SUPPORTS:
                    deltas[tgt_id] += src_strength
                elif rel.relation == RelationType.CONTRADICTS:
                    deltas[tgt_id] -= src_strength
                elif rel.relation == RelationType.MITIGATES:
                    deltas[tgt_id] -= src_strength * 0.5
                elif rel.relation == RelationType.WEAKENS:
                    deltas[tgt_id] -= src_strength * 0.3

            for bid, delta in deltas.items():
                node = self._nodes.get(bid)
                if node is not None:
                    current_logit = _logit(node.confidence_score)
                    node.confidence_score = _sigmoid(current_logit + delta)

    def bayesian_update(self, belief_id: str, evidence_supports: bool,
                        likelihood_ratio: float = 3.0):
        """Full Bayesian update on a single belief given new evidence.

        P(H|E) = P(E|H) * P(H) / P(E)

        In log-odds form:
          log_odds_posterior = log_odds_prior + log(likelihood_ratio)

        Args:
            belief_id: the belief to update
            evidence_supports: True if evidence supports the hypothesis
            likelihood_ratio: how much more likely is the evidence if H is true
                              vs if H is false. Default 3.0 = moderate evidence.
        """
        import math
        node = self._nodes.get(belief_id)
        if node is None:
            return

        prior = max(0.01, min(0.99, node.confidence_score))
        log_odds = math.log(prior / (1 - prior))

        if evidence_supports:
            log_odds += math.log(likelihood_ratio)
        else:
            log_odds -= math.log(likelihood_ratio)

        log_odds = max(-10, min(10, log_odds))
        node.confidence_score = 1.0 / (1.0 + math.exp(-log_odds))

    # ---- temporal decay ---------------------------------------------------

    def apply_temporal_decay(self, decay_per_session: float = 0.95):
        """Reduce confidence of all beliefs slightly each session.

        Models the intuition that old findings become less certain over time
        (code changes, dependencies update, etc.).

        Args:
            decay_per_session: multiplicative factor (0.95 = 5% decay per session)
        """
        for node in self._nodes.values():
            node.confidence_score = max(
                0.01,
                node.confidence_score * decay_per_session
            )

    # ---- belief pruning & merging -----------------------------------------

    def prune(self, min_confidence: float = 0.05, max_age_sessions: int = 0) -> int:
        """Remove low-value beliefs (noise reduction).

        Args:
            min_confidence: remove beliefs below this threshold
            max_age_sessions: remove beliefs older than N sessions (0 = disabled)

        Returns number of nodes removed.
        """
        to_remove = set()
        for bid, node in self._nodes.items():
            if node.confidence_score < min_confidence:
                to_remove.add(bid)

        # Remove nodes
        for bid in to_remove:
            del self._nodes[bid]
            # Clean edges
            for key in list(self._edges.keys()):
                if bid in key:
                    del self._edges[key]
            self._out.pop(bid, None)
            self._in.pop(bid, None)
            for s in self._out.values():
                s.discard(bid)
            for s in self._in.values():
                s.discard(bid)

        if to_remove:
            logger.info(f"Pruned {len(to_remove)} low-confidence beliefs")
        return len(to_remove)

    def merge_equivalent(self, similarity_threshold: float = 0.9) -> int:
        """Merge beliefs with near-identical predicates in the same scope.

        When two beliefs say essentially the same thing (same file, same
        function, very similar predicate text), keep the one with higher
        confidence and transfer the other's relations.

        NEVER merges beliefs connected by a CONTRADICTS edge — those are
        genuinely different despite textual similarity.

        Returns number of merges performed.
        """
        merged = 0
        beliefs = list(self._nodes.values())

        # Pre-compute contradiction pairs to protect them from merge
        contradiction_pairs: Set[FrozenSet[str]] = set()
        for (src, tgt), rel in self._edges.items():
            if rel.relation == RelationType.CONTRADICTS:
                contradiction_pairs.add(frozenset([src, tgt]))

        # Group by scope
        by_scope: Dict[str, List] = defaultdict(list)
        for b in beliefs:
            key = f"{b.scope.file_path}:{b.scope.function_name or '*'}"
            by_scope[key].append(b)

        to_remove = set()
        for group in by_scope.values():
            for i, b1 in enumerate(group):
                if b1.id in to_remove:
                    continue
                for b2 in group[i+1:]:
                    if b2.id in to_remove:
                        continue
                    # Never merge contradicting beliefs
                    if frozenset([b1.id, b2.id]) in contradiction_pairs:
                        continue
                    sim = self._text_similarity(
                        b1.predicate.expression, b2.predicate.expression)
                    if sim >= similarity_threshold:
                        keep, drop = ((b1, b2) if b1.confidence_score >= b2.confidence_score
                                      else (b2, b1))
                        keep.confidence_score = min(
                            0.99,
                            keep.confidence_score + drop.confidence_score * 0.1
                        )
                        to_remove.add(drop.id)
                        merged += 1

        for bid in to_remove:
            if bid in self._nodes:
                del self._nodes[bid]
                for key in list(self._edges.keys()):
                    if bid in key:
                        del self._edges[key]

        if merged:
            logger.info(f"Merged {merged} equivalent belief pairs")
        return merged

    @staticmethod
    def _text_similarity(a: str, b: str) -> float:
        """Quick Jaccard similarity on word sets."""
        wa = set(a.lower().split())
        wb = set(b.lower().split())
        if not wa or not wb:
            return 0.0
        return len(wa & wb) / len(wa | wb)

    # ---- contradiction detection ------------------------------------------

    def find_contradictions(self, min_severity: float = 0.3) -> List[Contradiction]:
        """Find all contradiction cliques in the graph.

        A contradiction is a pair (or clique) of beliefs connected by
        CONTRADICTS edges where both sides have non-trivial confidence.
        Severity = min(confidence_a, confidence_b) * avg(fragility_a, fragility_b).
        """
        seen: Set[FrozenSet[str]] = set()
        results: List[Contradiction] = []

        for (src, tgt), rel in self._edges.items():
            if rel.relation != RelationType.CONTRADICTS:
                continue
            pair = frozenset([src, tgt])
            if pair in seen:
                continue
            seen.add(pair)

            b_src = self._nodes.get(src)
            b_tgt = self._nodes.get(tgt)
            if b_src is None or b_tgt is None:
                continue

            severity = (
                min(b_src.confidence_score, b_tgt.confidence_score) *
                (b_src.fragility + b_tgt.fragility) / 2
            )
            if severity < min_severity:
                continue

            # Try to infer CWE from predicate keywords
            cwe = self._guess_cwe(b_src, b_tgt)

            results.append(Contradiction(
                belief_ids=pair,
                severity=severity,
                cwe=cwe,
                description=(
                    f"'{b_src.predicate.expression}' contradicts "
                    f"'{b_tgt.predicate.expression}' in "
                    f"{b_src.scope.file_path}:{b_src.scope.function_name}"
                ),
            ))

        results.sort(key=lambda c: c.severity, reverse=True)
        return results

    @staticmethod
    def _guess_cwe(b1, b2) -> str:
        """Best-effort CWE from combined predicates.
        v4 (B-06): delegated to the single-source-of-truth cwe_taxonomy module."""
        from .cwe_taxonomy import guess_cwe
        combined = f"{b1.predicate.expression} {b2.predicate.expression}"
        return guess_cwe(combined)

    # ---- subgraph extraction ----------------------------------------------

    def subgraph(self, *, file_path: str = None, cwe: str = None,
                 min_confidence: float = 0.0) -> "CognitiveGraph":
        """Extract a subgraph by filter criteria."""
        sub = CognitiveGraph()
        for b in self._nodes.values():
            if file_path and b.scope.file_path != file_path:
                continue
            if min_confidence and b.confidence_score < min_confidence:
                continue
            sub.add_belief(b)
        # Copy relevant edges
        for (src, tgt), rel in self._edges.items():
            if src in sub._nodes and tgt in sub._nodes:
                if cwe:
                    # Only keep CONTRADICTS edges matching this CWE
                    if rel.relation == RelationType.CONTRADICTS:
                        b1, b2 = sub._nodes[src], sub._nodes[tgt]
                        if self._guess_cwe(b1, b2) != cwe:
                            continue
                sub.add_relation(rel)
        return sub

    # ---- serialization ----------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "nodes": {bid: b.to_dict() for bid, b in self._nodes.items()},
            "edges": [r.to_dict() for r in self._edges.values()],
        }

    def stats(self) -> dict:
        """Quick summary for logging/reporting."""
        rel_counts = defaultdict(int)
        for rel in self._edges.values():
            rel_counts[rel.relation.value] += 1
        return {
            "nodes": len(self._nodes),
            "edges": len(self._edges),
            "relations": dict(rel_counts),
            "avg_confidence": (
                sum(b.confidence_score for b in self._nodes.values()) /
                max(1, len(self._nodes))
            ),
        }
