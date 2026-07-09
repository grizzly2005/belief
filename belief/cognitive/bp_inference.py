"""
belief/cognitive/bp_inference.py — convergent belief propagation.

Fixes B-07 from the audit: the old `CognitiveGraph.propagate_confidence`
used 3 fixed iterations and the `decay=0.1` parameter was actually a
learning rate (not a temporal decay). On graphs with contradiction cycles
(common: bridge belief vs LLM belief contradicting each other) it did
not converge — just oscillated or plateaued.

This replacement:
  - Runs loopy belief propagation on the full relation graph
  - Converges when max |Δconfidence| < eps (or hits max_iter)
  - Separates learning rate from temporal decay conceptually
  - Uses the graph's existing RelationType enum (CONTRADICTS, SUPPORTS,
    IMPLIES, DUPLICATES) to choose message signs

No external deps. If pgmpy is available it could be wired in later,
but we ship without it so BELIEF stays install-free on Kali.

Signs of messages per relation:
    SUPPORTS:    src ↑ ⇒ tgt ↑     (positive coupling, weight +1)
    CONTRADICTS: src ↑ ⇒ tgt ↓     (negative coupling, weight −1)
    IMPLIES:     src ↑ ⇒ tgt ↑     (positive, weight +1)
    DUPLICATES:  src ≈ tgt        (positive, weight +1, high coupling)
    RELATED/OTHER: weak positive  (weight +0.3)
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Dict

logger = logging.getLogger("belief.cognitive.bp_inference")


# ─────────────────────────────────────────────────────────────────
# Logit / sigmoid helpers (confidence <-> real line)
# ─────────────────────────────────────────────────────────────────

_EPS = 1e-6


def _clip(p: float) -> float:
    return max(_EPS, min(1.0 - _EPS, p))


def confidence_to_logit(c: float) -> float:
    """Map confidence ∈ (0, 1) to logit ∈ ℝ."""
    c = _clip(c)
    return math.log(c / (1.0 - c))


def logit_to_confidence(l: float) -> float:
    """Map logit ∈ ℝ back to confidence ∈ (0, 1)."""
    if l >= 0:
        return 1.0 / (1.0 + math.exp(-l))
    e = math.exp(l)
    return e / (1.0 + e)


# ─────────────────────────────────────────────────────────────────

@dataclass
class BPResult:
    """Outcome of one propagation run."""
    converged: bool
    iterations: int
    max_delta: float
    final_confidences: Dict[str, float]


def _weight_for_relation(relation_name: str) -> float:
    """Map RelationType → signed coupling weight for BP messages.

    Matches belief.cognitive.belief_graph.RelationType:
      DEPENDS_ON, CONTRADICTS, SUPPORTS, MITIGATES, WEAKENS
    """
    r = (relation_name or "").upper()
    if r == "CONTRADICTS":
        return -1.0
    if r == "SUPPORTS":
        return 1.0
    if r == "DEPENDS_ON":
        return 0.7   # if dep is strong, target strengthens moderately
    if r == "MITIGATES":
        return -0.5  # a mitigation weakens the mitigated belief's exploitability
    if r == "WEAKENS":
        return -0.7
    # Unknown / legacy names (IMPLIES, DUPLICATES, RELATED): neutral positive
    return 0.3


def propagate_bp(
    graph,
    learning_rate: float = 0.15,
    max_iter: int = 50,
    tolerance: float = 1e-3,
    log_every: int = 0,
) -> BPResult:
    """Run loopy belief propagation on a CognitiveGraph until convergence.

    Parameters
    ----------
    graph : CognitiveGraph
        The graph whose beliefs will have their .confidence_score updated
        in place. Must expose:
          - graph._nodes: dict[belief_id, Belief]
          - graph._edges: dict[(src, tgt), Relation] where Relation
                          has .relation (str or Enum) and .strength (float)
    learning_rate : float
        Step size on the logit scale. 0.1–0.2 works well for most graphs.
    max_iter : int
        Maximum BP iterations. Return with converged=False if reached.
    tolerance : float
        Convergence threshold on max |Δconfidence| across all nodes.
    log_every : int
        If >0, log intermediate max_delta every N iterations.

    Returns
    -------
    BPResult with convergence info.
    """
    nodes = graph._nodes
    edges = graph._edges

    if not nodes:
        return BPResult(converged=True, iterations=0, max_delta=0.0,
                        final_confidences={})

    # Work in logit space to avoid clipping artifacts
    logits: Dict[str, float] = {
        bid: confidence_to_logit(b.confidence_score)
        for bid, b in nodes.items()
    }
    # Initial confidences (priors) — pulled back toward on each iter
    priors: Dict[str, float] = dict(logits)

    iteration = 0
    max_delta = float("inf")

    while iteration < max_iter and max_delta > tolerance:
        new_logits = dict(logits)

        for (src, tgt), rel in edges.items():
            if src not in logits or tgt not in logits:
                continue
            rel_name = (
                rel.relation.name
                if hasattr(rel.relation, "name")
                else str(rel.relation)
            )
            w = _weight_for_relation(rel_name)
            strength = getattr(rel, "weight", 1.0) or 1.0

            # Message: target's logit shifts by (lr * weight * strength * src_logit)
            delta_l = learning_rate * w * strength * logits[src]
            new_logits[tgt] = new_logits[tgt] + delta_l

        # Anchor on prior (regularization) — prevents runaway on cycles
        for bid in new_logits:
            # 90% new evidence, 10% pull toward prior
            new_logits[bid] = 0.9 * new_logits[bid] + 0.1 * priors[bid]
            # Clamp logits to reasonable range to avoid overflow
            new_logits[bid] = max(-8.0, min(8.0, new_logits[bid]))

        # Compute max delta in confidence space (what the user cares about)
        max_delta = 0.0
        for bid, l in new_logits.items():
            old_c = logit_to_confidence(logits[bid])
            new_c = logit_to_confidence(l)
            d = abs(new_c - old_c)
            if d > max_delta:
                max_delta = d

        logits = new_logits
        iteration += 1

        if log_every and iteration % log_every == 0:
            logger.info(
                f"[bp] iter={iteration} max_delta={max_delta:.5f}"
            )

    # Write back to beliefs
    final_conf: Dict[str, float] = {}
    for bid, l in logits.items():
        c = logit_to_confidence(l)
        final_conf[bid] = c
        nodes[bid].confidence_score = c

    converged = max_delta <= tolerance
    if not converged:
        logger.warning(
            f"[bp] DID NOT CONVERGE after {iteration} iters "
            f"(max_delta={max_delta:.5f}). Graph may have cycles too "
            f"strong for current learning_rate={learning_rate}."
        )
    else:
        logger.info(f"[bp] converged in {iteration} iters "
                    f"(max_delta={max_delta:.5f})")

    return BPResult(
        converged=converged,
        iterations=iteration,
        max_delta=max_delta,
        final_confidences=final_conf,
    )


__all__ = ["propagate_bp", "BPResult", "confidence_to_logit", "logit_to_confidence"]
