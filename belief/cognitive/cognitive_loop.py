"""
belief.cognitive.cognitive_loop — The "nervous system" of BELIEF.

Implements the observe → reason → decide → act → learn cycle that
coordinates all components:

  1. OBSERVE:  collect beliefs from all sources (bridges, LLM, HAR)
  2. REASON:   build belief graph, propagate confidence, find contradictions
  3. DECIDE:   prioritize what to investigate (budget-aware)
  4. ACT:      dispatch Hydra agent to confirm/refute uncertain beliefs
  5. LEARN:    store results in memory, update confidence, mark FPs

This replaces the linear EnhancedOrchestrator with an intelligent loop
that adapts its behavior based on uncertainty and budget.

Usage:
    from belief.cognitive import CognitiveLoop

    loop = CognitiveLoop(
        project_path="/path/to/code",
        config=BeliefConfig(),
    )
    report = loop.run()
    # report.beliefs, report.contradictions, report.verdicts, ...
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .belief_graph import CognitiveGraph, Contradiction, RelationType
from .hydra_agent import HydraAgent, Goal, Verdict, VerdictStatus
from .memory_engine import MemoryEngine, AnalysisRecord

logger = logging.getLogger("belief.cognitive.cognitive_loop")


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class CognitiveReport:
    """Output of one cognitive loop run."""
    project_path: str
    beliefs: list = field(default_factory=list)
    graph_stats: dict = field(default_factory=dict)
    contradictions: List[dict] = field(default_factory=list)
    verdicts: List[dict] = field(default_factory=list)
    drift_signals: List[dict] = field(default_factory=list)  # v4 Phase 6
    phases: Dict[str, float] = field(default_factory=dict)
    total_elapsed_s: float = 0.0

    # Summary
    confirmed_vulns: int = 0
    refuted_fps: int = 0
    inconclusive: int = 0

    def to_dict(self) -> dict:
        return {
            "project_path": self.project_path,
            "total_beliefs": len(self.beliefs),
            "graph_stats": self.graph_stats,
            "contradictions": self.contradictions,
            "verdicts": self.verdicts,
            "drift_signals": self.drift_signals,
            "phases": {k: round(v, 2) for k, v in self.phases.items()},
            "total_elapsed_s": round(self.total_elapsed_s, 2),
            "confirmed_vulns": self.confirmed_vulns,
            "refuted_fps": self.refuted_fps,
            "inconclusive": self.inconclusive,
        }

    def summary(self) -> str:
        lines = [
            f"CognitiveReport: {self.project_path}",
            f"  Beliefs: {len(self.beliefs)}",
            f"  Graph: {self.graph_stats}",
            f"  Contradictions: {len(self.contradictions)}",
            f"  Verdicts: {len(self.verdicts)} "
            f"({self.confirmed_vulns} confirmed, "
            f"{self.refuted_fps} refuted, "
            f"{self.inconclusive} inconclusive)",
            f"  Time: {self.total_elapsed_s:.1f}s "
            f"(phases: {self.phases})",
        ]
        return "\n".join(lines)

    def save(self, path: str) -> None:
        """Serialize report to JSON at `path`. Mirrors AnalysisReport.save()."""
        import json
        from pathlib import Path
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, default=str)


# ---------------------------------------------------------------------------
# Cognitive Loop
# ---------------------------------------------------------------------------

class CognitiveLoop:
    """The intelligent orchestrator.

    Replaces EnhancedOrchestrator's linear pipeline with an adaptive
    observe-reason-decide-act-learn cycle.
    """

    def __init__(
        self,
        project_path: str,
        config=None,
        enabled_bridges: Optional[Set[str]] = None,
        memory_dir: str = "~/.belief/memory",
        max_investigation_budget_s: float = 60.0,
        investigation_confidence_threshold: float = 0.5,
        max_goals: int = 10,
        sources: Optional[list] = None,
    ):
        self.project_path = project_path
        self.config = config
        self.enabled_bridges = enabled_bridges or {
            "bandit", "dlint", "path_traversal", "safety_db", "supply_chain",
        }
        self.max_budget_s = max_investigation_budget_s
        self.conf_threshold = investigation_confidence_threshold
        self.max_goals = max_goals

        # v4 (B-10): pluggable BeliefSource list. If None, _observe() builds
        # a default WhiteBoxSource + bridges pipeline (legacy behavior).
        self.sources = sources

        # Components
        self.graph = CognitiveGraph()
        self.memory = MemoryEngine(memory_dir)
        self._agent: Optional[HydraAgent] = None

        # v4 (B-05): pre-load memory into sets for O(1) novelty lookups.
        # Old code built these sets on EVERY _score_candidate call.
        self._fp_ids: set = set(self.memory.all_fp_ids())
        self._validated_ids: set = set(
            e.belief_id for e in self.memory.recall_validated()
        )

        # v4 (B-05 deep): Thompson sampling bandit over (cwe, bridge) arms.
        # Replaces the old novelty=0.8 constant with a proper Bayesian
        # exploration/exploitation tradeoff.
        from .bandit import ThompsonBandit
        self.bandit = ThompsonBandit(persistence_dir=memory_dir)
        self.bandit.load()

    # ---- main entry point -------------------------------------------------

    def run(self) -> CognitiveReport:
        """Execute the full cognitive loop.

        Returns a CognitiveReport with beliefs, contradictions, verdicts.
        """
        t0 = time.time()
        report = CognitiveReport(project_path=self.project_path)

        # ═══════════════════════════════════════════════════════
        # Phase 1: OBSERVE — collect beliefs from all sources
        # ═══════════════════════════════════════════════════════
        t_phase = time.time()
        beliefs = self._observe()
        report.phases["observe"] = time.time() - t_phase
        logger.info(f"[cognitive] OBSERVE: {len(beliefs)} beliefs collected")

        # ═══════════════════════════════════════════════════════
        # Phase 2: REASON — build graph, propagate, find contradictions
        # ═══════════════════════════════════════════════════════
        t_phase = time.time()
        contradictions = self._reason(beliefs)
        report.phases["reason"] = time.time() - t_phase
        logger.info(f"[cognitive] REASON: {self.graph.size} nodes, "
                     f"{self.graph.edge_count} edges, "
                     f"{len(contradictions)} contradictions")

        # ═══════════════════════════════════════════════════════
        # Phase 2b (v4): DRIFT — check historical belief drift
        # ═══════════════════════════════════════════════════════
        t_phase = time.time()
        drift_signals = self._check_drift(beliefs)
        report.phases["drift"] = time.time() - t_phase
        if drift_signals:
            logger.info(
                f"[cognitive] DRIFT: {len(drift_signals)} beliefs drifted "
                f"since last analysis"
            )
            # Drifted beliefs get their confidence bumped (more worth revisiting)
            drifted_ids = {d.belief_id for d in drift_signals}
            for b in beliefs:
                if b.id in drifted_ids:
                    # Drift → uncertainty. Push confidence toward 0.5 to
                    # signal "we're not sure anymore, investigate."
                    b.confidence_score = 0.5 * b.confidence_score + 0.5 * 0.5

        # ═══════════════════════════════════════════════════════
        # Phase 3: DECIDE — prioritize investigation goals
        # ═══════════════════════════════════════════════════════
        t_phase = time.time()
        goals = self._decide(beliefs, contradictions)
        report.phases["decide"] = time.time() - t_phase
        logger.info(f"[cognitive] DECIDE: {len(goals)} investigation goals")

        # ═══════════════════════════════════════════════════════
        # Phase 4: ACT — dispatch Hydra agent
        # ═══════════════════════════════════════════════════════
        t_phase = time.time()
        verdicts = self._act(goals)
        report.phases["act"] = time.time() - t_phase
        logger.info(f"[cognitive] ACT: {len(verdicts)} verdicts")

        # ═══════════════════════════════════════════════════════
        # Phase 5: LEARN — update memory, adjust confidence
        # ═══════════════════════════════════════════════════════
        t_phase = time.time()
        self._learn(beliefs, verdicts)
        report.phases["learn"] = time.time() - t_phase
        logger.info(f"[cognitive] LEARN: memory updated")

        # ═══════════════════════════════════════════════════════
        # Assemble report
        # ═══════════════════════════════════════════════════════
        report.beliefs = beliefs
        report.graph_stats = self.graph.stats()
        report.contradictions = [c.to_dict() for c in contradictions]
        report.verdicts = [v.to_dict() for v in verdicts]
        report.drift_signals = [d.to_dict() for d in drift_signals]
        report.total_elapsed_s = time.time() - t0

        for v in verdicts:
            if v.status == VerdictStatus.CONFIRMED:
                report.confirmed_vulns += 1
            elif v.status == VerdictStatus.REFUTED:
                report.refuted_fps += 1
            else:
                report.inconclusive += 1

        return report

    # ---- Phase implementations --------------------------------------------

    def _observe(self) -> list:
        """Phase 1: Collect beliefs from all available sources.

        v4 change (B-10): if `self.sources` was provided at init, use those
        directly (each implements BeliefSource.collect_beliefs()). Otherwise
        fall back to the legacy pipeline (bridges + orchestrator + memory).
        """
        # v4 path: use injected BeliefSource list if present.
        if self.sources:
            all_beliefs: list = []
            for src in self.sources:
                try:
                    produced = src.collect_beliefs()
                    logger.info(
                        f"[observe] source={src.__class__.__name__}: "
                        f"{len(produced)} beliefs"
                    )
                    all_beliefs.extend(produced)
                except Exception as e:
                    logger.warning(
                        f"[observe] source {src.__class__.__name__} failed: {e}"
                    )

            # Historical adjustment + FP filter (same as legacy path)
            for b in all_beliefs:
                adjusted = self.memory.suggest_confidence_adjustment(b)
                if adjusted is not None and adjusted != b.confidence_score:
                    b.confidence_score = adjusted
            all_beliefs = [
                b for b in all_beliefs
                if b.id not in self._fp_ids
            ]
            return all_beliefs

        # Legacy path: bridges + orchestrator
        from ..bridges import registry
        from ..bridges.belief_adapter import adapt_all

        all_beliefs = []

        # 1a. Run bridges
        bridge_results = {}
        available = set(registry.available())
        active = self.enabled_bridges & available

        for name in sorted(active):
            try:
                r = registry.run(name, project_path=self.project_path)
                bridge_results[name] = r
                if not r.errors:
                    logger.debug(f"[observe] {name}: {len(r)} findings")
            except Exception as e:
                logger.warning(f"[observe] {name} failed: {e}")

        # 1b. Adapt to beliefs
        bridge_beliefs = adapt_all(bridge_results)
        all_beliefs.extend(bridge_beliefs)

        # 1c. Base orchestrator (LLM-based) if config available
        if self.config:
            try:
                from ..orchestrator import Orchestrator
                orch = Orchestrator(self.config)
                base_report = orch.analyze_project(
                    project_path=self.project_path,
                    max_frontiers=20,
                )
                all_beliefs.extend(base_report.beliefs)
            except Exception as e:
                logger.warning(f"[observe] Base orchestrator failed: {e}")

        # 1d. Historical confidence adjustment from memory
        for b in all_beliefs:
            adjusted = self.memory.suggest_confidence_adjustment(b)
            if adjusted is not None and adjusted != b.confidence_score:
                logger.debug(f"[observe] Adjusted {b.id[:8]} confidence: "
                             f"{b.confidence_score:.2f} → {adjusted:.2f}")
                b.confidence_score = adjusted

        # 1e. Filter known FPs (O(1) via pre-loaded set — v4 B-05 fix)
        all_beliefs = [
            b for b in all_beliefs
            if b.id not in self._fp_ids
        ]

        return all_beliefs

    def _reason(self, beliefs: list) -> List[Contradiction]:
        """Phase 2: Build belief graph, propagate, find contradictions."""

        # Build graph
        self.graph = CognitiveGraph()
        self.graph.add_beliefs(beliefs)

        # Infer relations
        self.graph.auto_relate()

        # Propagate confidence — v4 B-07 fix: convergent BP on logits,
        # not 3 fixed iterations of a custom scheme that didn't converge
        # on contradiction cycles.
        from .bp_inference import propagate_bp
        bp_result = propagate_bp(
            self.graph,
            learning_rate=0.15,
            max_iter=50,
            tolerance=1e-3,
        )
        if not bp_result.converged:
            logger.warning(
                f"[reason] BP did not converge: "
                f"max_delta={bp_result.max_delta:.5f} "
                f"after {bp_result.iterations} iterations"
            )
        else:
            logger.debug(
                f"[reason] BP converged in {bp_result.iterations} iterations"
            )

        # Find contradictions
        contradictions = self.graph.find_contradictions(min_severity=0.2)

        return contradictions

    def _decide(self, beliefs: list, contradictions: List[Contradiction]) -> List[Goal]:
        """Phase 3: Strategic decision engine.

        Scores every candidate goal on 4 factors:
          - uncertainty:     how unsure are we? (1 - confidence)
          - exploitability:  how likely is this exploitable? (CWE severity)
          - impact:          how many other beliefs depend on this?
          - novelty:         have we seen this pattern before? (memory check)

        Then picks the top-N goals within budget, balancing exploration
        (novel/uncertain) vs exploitation (high-impact/exploitable).
        """
        candidates: List[dict] = []  # {"goal": Goal, "score": float, "reason": str}

        # ── Candidate source 1: contradictions ──
        for contra in contradictions:
            belief_ids = sorted(contra.belief_ids)
            target = None
            for bid in belief_ids:
                b = self.graph.get(bid)
                if b and (target is None or b.confidence_score < target.confidence_score):
                    target = b
            if not target:
                continue

            score = self._score_candidate(target, contra=contra)
            candidates.append({
                "goal": Goal(
                    hypothesis=f"Contradiction: {contra.description[:80]}",
                    target_file=target.scope.file_path or "",
                    target_function=target.scope.function_name or "",
                    target_line=(target.predicate.anchor_lines[0]
                                 if target.predicate.anchor_lines else 0),
                    cwe=contra.cwe,
                    max_budget_s=self.max_budget_s / max(1, self.max_goals),
                ),
                "score": score,
                "reason": f"contradiction (severity={contra.severity:.2f})",
            })

        # ── Candidate source 2: uncertain beliefs OR severe-CWE beliefs ──
        # Historical bug: only low-confidence beliefs became goals, so a
        # high-confidence dlint/safety_db finding on a CWE-78/CWE-502 was
        # silently skipped — the cognitive layer produced 0 goals on every
        # benchmark sample. Fix: a belief is also eligible for verification
        # when its CWE severity is >= 0.5, regardless of confidence.
        #
        # Threshold rationale (0.5): the DEFAULT_SEVERITY for unknown CWEs
        # is also 0.5, so we explicitly require b_cwe != "" below — a
        # belief with no identifiable CWE doesn't clear this path. With
        # 0.5 as threshold, every known CWE in the taxonomy (0.45+) that
        # matches a real pattern gets verified. CWE-327 (0.65) and
        # CWE-338 (0.55) now route to Hydra, which was the root cause of
        # dec_qual=0 on crypto/random samples.
        from .cwe_taxonomy import guess_cwe_from_belief, cwe_severity
        SEVERE_THRESHOLD = 0.5

        for b in beliefs:
            # Path A — belief is uncertain, investigate to resolve uncertainty
            is_uncertain = b.confidence_score < self.conf_threshold

            # Path B — belief is confident but the CWE is severe: Hydra
            # should still verify exploitability (sink reachable from source?).
            # We require an IDENTIFIED CWE (b_cwe != "") so we don't promote
            # every confident belief to a goal via the severity=0.5 default.
            b_cwe = b.cwe or guess_cwe_from_belief(b)
            severity = cwe_severity(b_cwe) if b_cwe else 0.0
            is_severe_confident = (
                not is_uncertain
                and bool(b_cwe)
                and severity >= SEVERE_THRESHOLD
            )

            if not (is_uncertain or is_severe_confident):
                continue

            score = self._score_candidate(b)

            # target_line: prefer anchor_lines, fall back to scope.line_start
            tline = 0
            if b.predicate.anchor_lines:
                tline = b.predicate.anchor_lines[0]
            elif b.scope.line_start:
                tline = b.scope.line_start

            if is_uncertain:
                reason = f"uncertain (conf={b.confidence_score:.2f})"
            else:
                reason = (f"severe-CWE verify "
                          f"({b_cwe}, sev={severity:.2f}, "
                          f"conf={b.confidence_score:.2f})")

            candidates.append({
                "goal": Goal(
                    hypothesis=(b.predicate.natural_language or
                                b.predicate.expression),
                    target_file=b.scope.file_path or "",
                    target_function=b.scope.function_name or "",
                    target_line=tline,
                    cwe=b_cwe,
                    confidence_threshold=self.conf_threshold,
                    max_budget_s=self.max_budget_s / max(1, self.max_goals),
                ),
                "score": score,
                "reason": reason,
            })

        # ── Rank and select ──
        candidates.sort(key=lambda c: c["score"], reverse=True)

        # Dedupe by (file, line) — don't investigate the same spot twice
        seen_targets = set()
        goals: List[Goal] = []
        for c in candidates:
            key = (c["goal"].target_file, c["goal"].target_line)
            if key in seen_targets:
                continue
            seen_targets.add(key)
            goals.append(c["goal"])
            logger.debug(f"[decide] Goal #{len(goals)}: score={c['score']:.3f} "
                         f"reason={c['reason']}")
            if len(goals) >= self.max_goals:
                break

        return goals

    # ── Scoring engine ──
    # CWE severity now comes from belief.cognitive.cwe_taxonomy (single source of truth).

    def _score_candidate(self, belief, contra=None) -> float:
        """Multi-factor scoring for a candidate investigation goal.

        score = uncertainty * 0.30
              + exploitability * 0.30
              + impact * 0.20
              + novelty * 0.20

        v4 fixes:
          - B-05: memory lookups O(1) via pre-built sets in __init__.
          - B-06: CWE guessing delegated to cwe_taxonomy.guess_cwe_from_belief.
          - B-05 bootstrap: on empty memory, novelty uses bridge FP-rate prior
            via MemoryEngine.suggest_prior_novelty(), not a constant 0.8.
        """
        from .cwe_taxonomy import guess_cwe_from_belief, cwe_severity

        # Factor 1: Uncertainty (how unsure → higher = more worth investigating)
        uncertainty = 1.0 - belief.confidence_score

        # Factor 2: Exploitability (CWE severity)
        cwe = (contra.cwe if contra else "") or getattr(belief, "cwe", "") \
              or guess_cwe_from_belief(belief)
        exploitability = cwe_severity(cwe)
        if contra:
            # Contradictions are inherently more exploitable
            exploitability = min(1.0, exploitability + 0.15)

        # Factor 3: Impact (how many other beliefs depend on this one)
        dependents = len(self.graph.relations_to(belief.id))
        impact = min(1.0, dependents * 0.2)  # caps at 5 dependents
        # Fragility is also an impact signal
        impact = max(impact, belief.fragility)

        # Factor 4: Novelty (never seen before → explore)
        # Use pre-loaded sets (self._fp_ids, self._validated_ids) for O(1)
        # look-up. v4 bandit integration: for unseen beliefs, use a
        # Thompson-sampled score per (cwe, bridge) arm instead of the
        # old constant 0.8.
        if belief.id in self._fp_ids:
            novelty = 0.0  # already known FP, don't waste time
        elif belief.id in self._validated_ids:
            novelty = 0.1  # already validated, low novelty
        else:
            # Identify arm (cwe, bridge) if possible
            bridge_hint = ""
            justif = str(getattr(belief, "justification", "") or "").lower()
            for name in ("bandit", "dlint", "pyt", "semgrep", "safety_db",
                         "path_traversal", "supply_chain"):
                if name in justif:
                    bridge_hint = name
                    break
            # Thompson-sample this arm. High variance (uncertain) arms
            # sample high more often → exploration. Low variance + low
            # mean arms sample low → exploitation by avoidance.
            bandit_score = self.bandit.sample_score(cwe, bridge_hint)
            # Blend with memory prior (safety net if bandit has no history
            # yet): 70% bandit, 30% memory-based prior
            mem_prior = self.memory.suggest_prior_novelty(belief, cwe)
            novelty = 0.7 * bandit_score + 0.3 * mem_prior

        score = (uncertainty * 0.30 +
                 exploitability * 0.30 +
                 impact * 0.20 +
                 novelty * 0.20)

        return round(score, 4)

    # B-06: _guess_cwe_from_belief DELETED — use cwe_taxonomy module instead.

    def _act(self, goals: List[Goal]) -> List[Verdict]:
        """Phase 4: Dispatch Hydra agent with multi-step planning."""
        if not goals:
            return []

        from ..bridges import registry
        agent = HydraAgent(bridge_registry=registry, memory=self.memory)

        verdicts = []
        for goal in goals:
            try:
                # Use planning for CWE-specific goals, simple investigate otherwise
                if goal.cwe:
                    plan = agent.plan_attack(goal)
                    logger.debug(f"[act] Plan: {plan}")
                    v = agent.execute_plan(plan)
                else:
                    v = agent.investigate(goal)
                verdicts.append(v)
            except Exception as e:
                logger.warning(f"[act] Investigation failed: {e}")

        return verdicts

    def _learn(self, beliefs: list, verdicts: List[Verdict]) -> None:
        """Phase 5: Update memory + bandit based on investigation results."""
        from .cwe_taxonomy import guess_cwe_from_belief

        # Store all beliefs — v4 (B-06): unified taxonomy, no inline mini-map
        for b in beliefs:
            tags = []
            cwe = getattr(b, "cwe", "") or guess_cwe_from_belief(b)
            if cwe:
                tags.append(cwe)
            self.memory.store_belief(b, tags=tags)

        # Update confidence based on verdicts + update bandit arms
        for verdict in verdicts:
            matched = [b for b in beliefs if self._verdict_matches_belief(verdict, b)]
            reward = 0.0
            if verdict.status == VerdictStatus.CONFIRMED:
                reward = 1.0
                for b in matched:
                    b.confidence_score = min(0.99, b.confidence_score + 0.2)
                    self.memory.mark_validated(b.id, method="hydra_agent")
            elif verdict.status == VerdictStatus.REFUTED:
                reward = 0.0
                for b in matched:
                    b.confidence_score = max(0.01, b.confidence_score - 0.3)
                    self.memory.mark_false_positive(b.id)
            else:
                # Inconclusive → small positive reward (it was worth looking)
                reward = 0.3

            # v4 bandit update: for each matched belief, update its (cwe, bridge) arm
            for b in matched:
                cwe = getattr(b, "cwe", "") or guess_cwe_from_belief(b)
                bridge_hint = ""
                justif = str(getattr(b, "justification", "") or "").lower()
                for name in ("bandit", "dlint", "pyt", "semgrep", "safety_db",
                             "path_traversal", "supply_chain"):
                    if name in justif:
                        bridge_hint = name
                        break
                self.bandit.update(cwe=cwe, bridge=bridge_hint, reward=reward)

        # Record analysis run
        self.memory.record_analysis(AnalysisRecord(
            timestamp=time.time(),
            project_path=self.project_path,
            total_beliefs=len(beliefs),
            contradictions_found=len(self.graph.find_contradictions()),
            true_positives=sum(1 for v in verdicts
                              if v.status == VerdictStatus.CONFIRMED),
            false_positives=sum(1 for v in verdicts
                               if v.status == VerdictStatus.REFUTED),
            bridges_used=sorted(self.enabled_bridges),
        ))

        # Persist memory + bandit
        self.memory.save()
        self.bandit.save()

    def _check_drift(self, beliefs: list) -> list:
        """v4 Phase 6: detect historical drift via git history.

        If the project isn't a git repo, returns empty list (fail-closed)."""
        try:
            from .drift_detector import GitDriftDetector
            det = GitDriftDetector(project_path=self.project_path)
            if not det._is_repo:
                return []
            return det.check_beliefs(beliefs, since_days=90)
        except Exception as e:
            logger.debug(f"[cognitive] drift check failed: {e}")
            return []

    @staticmethod
    def _verdict_matches_belief(verdict: Verdict, belief) -> bool:
        """Check if a verdict's goal matches a belief's scope.

        Robust path comparison: the belief's file_path is often the absolute
        tempdir path (e.g. /tmp/belief_bench_cog_xxx/vulnerable.py) while the
        goal.target_file is whatever was set when the goal was created.
        Historical bug: a naive substring match failed when the goal carried
        a relative or differently-rooted path, so verdicts never reconciled
        with beliefs. Fix: match on abspath equality OR basename equality OR
        bidirectional substring.
        """
        import os
        goal = verdict.goal
        if goal.target_file and belief.scope.file_path:
            gf, bf = goal.target_file, belief.scope.file_path
            g_abs, b_abs = os.path.abspath(gf), os.path.abspath(bf)
            g_base, b_base = os.path.basename(gf), os.path.basename(bf)
            paths_match = (
                g_abs == b_abs
                or gf in bf
                or bf in gf
                or (g_base and g_base == b_base)
            )
            if not paths_match:
                return False
        if goal.target_line:
            anchors = list(belief.predicate.anchor_lines or ())
            if belief.scope.line_start and belief.scope.line_start not in anchors:
                anchors.append(belief.scope.line_start)
            if anchors and not any(abs(goal.target_line - l) <= 5 for l in anchors):
                return False
        return True
