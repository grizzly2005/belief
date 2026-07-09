"""
belief.cognitive.hydra_agent — Goal-driven security testing agent.

Transforms Hydra from a "tool wrapper" into an "agent" that receives
high-level objectives and autonomously explores to confirm or refute them.

Instead of:
    registry.run("bandit", project_path="/code")  # fire-and-forget

You get:
    agent = HydraAgent(bridges=registry)
    result = agent.investigate(
        goal=Goal(hypothesis="SQL injection in login()",
                  target_file="auth.py", cwe="CWE-89")
    )
    # → agent chooses which bridges to run, in what order,
    #   generates targeted payloads, and returns a Verdict.

Architecture:
  - Goal: what we want to confirm/refute (hypothesis + context)
  - Strategy: which tools to use and in what order
  - Verdict: confirmed / refuted / inconclusive + evidence

Uses existing bridges — does NOT re-implement scanning. It ORCHESTRATES
them intelligently based on the hypothesis.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

logger = logging.getLogger("belief.cognitive.hydra_agent")


# ---------------------------------------------------------------------------
# Goal / Verdict
# ---------------------------------------------------------------------------

class VerdictStatus(Enum):
    CONFIRMED    = "confirmed"       # vulnerability exists
    REFUTED      = "refuted"         # false positive
    INCONCLUSIVE = "inconclusive"    # couldn't determine
    ERROR        = "error"           # agent failed


@dataclass
class Goal:
    """A hypothesis to investigate."""
    hypothesis: str                  # "SQL injection via string formatting"
    target_file: str = ""            # specific file to focus on
    target_function: str = ""        # specific function
    target_line: int = 0             # specific line
    cwe: str = ""                    # CWE-89, CWE-78, etc.
    confidence_threshold: float = 0.7  # below this → investigate
    max_budget_s: float = 30.0       # time budget in seconds

    def to_dict(self) -> dict:
        return {
            "hypothesis": self.hypothesis,
            "target_file": self.target_file,
            "target_function": self.target_function,
            "target_line": self.target_line,
            "cwe": self.cwe,
        }


@dataclass
class Evidence:
    """One piece of evidence gathered during investigation."""
    source: str          # bridge name or method
    finding: Dict[str, Any] = field(default_factory=dict)
    supports_hypothesis: bool = True
    confidence: float = 0.5
    elapsed_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "finding": self.finding,
            "supports_hypothesis": self.supports_hypothesis,
            "confidence": self.confidence,
            "elapsed_s": round(self.elapsed_s, 3),
        }


@dataclass
class Verdict:
    """Result of an investigation."""
    goal: Goal
    status: VerdictStatus
    evidence: List[Evidence] = field(default_factory=list)
    final_confidence: float = 0.0
    explanation: str = ""
    total_elapsed_s: float = 0.0

    def to_dict(self) -> dict:
        return {
            "goal": self.goal.to_dict(),
            "status": self.status.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "final_confidence": round(self.final_confidence, 3),
            "explanation": self.explanation,
            "total_elapsed_s": round(self.total_elapsed_s, 2),
        }


# ---------------------------------------------------------------------------
# Strategy: which tools for which CWE
# ---------------------------------------------------------------------------

# Maps CWE → ordered list of bridges to try (cheapest first)
# v4 hotfix #3: these bridges are function-level verifiers. They need
# `module_file` + `func_name`, not `project_path`. Hydra is a project-level
# orchestrator, so calling them here raises a TypeError. The try/except in
# _run_bridge catches it, but registry.run logs it noisily — better to not
# schedule them at all. Re-enable them only when plan_attack is wired for
# per-function targets (future work).
FUNCTION_LEVEL_BRIDGES: set = {"crosshair", "pyexz3"}


CWE_STRATEGY: Dict[str, List[str]] = {
    "CWE-22":  ["path_traversal", "bandit", "semgrep", "pyt"],
    "CWE-78":  ["bandit", "dlint", "semgrep", "pyt"],
    "CWE-79":  ["semgrep", "bandit", "pyt"],
    "CWE-89":  ["bandit", "dlint", "semgrep", "pyt"],
    "CWE-95":  ["bandit", "dlint", "semgrep"],
    "CWE-327": ["bandit", "dlint"],
    "CWE-338": ["bandit", "dlint"],
    "CWE-502": ["bandit", "dlint", "semgrep"],
    "CWE-798": ["bandit", "semgrep"],
    "CWE-918": ["bandit", "semgrep", "pyt"],
}

# Default strategy when CWE is unknown
DEFAULT_STRATEGY = ["bandit", "dlint", "path_traversal", "semgrep"]

# v4 (B-06): KEYWORD_TO_CWE kept as legacy reference only.
# All CWE guessing goes through belief.cognitive.cwe_taxonomy.guess_cwe().
# DO NOT add new patterns here — add them to cwe_taxonomy._KEYWORD_CWE.
KEYWORD_TO_CWE: Dict[str, str] = {
    "sql injection": "CWE-89", "sqli": "CWE-89",
    "command injection": "CWE-78", "shell injection": "CWE-78", "os.system": "CWE-78",
    "path traversal": "CWE-22", "directory traversal": "CWE-22",
    "xss": "CWE-79", "cross-site scripting": "CWE-79",
    "deserialization": "CWE-502", "pickle": "CWE-502", "yaml.load": "CWE-502",
    "eval": "CWE-95", "exec": "CWE-95", "code injection": "CWE-95",
    "hardcoded": "CWE-798", "password": "CWE-798", "api key": "CWE-798",
    "ssrf": "CWE-918", "server-side request": "CWE-918",
    "weak crypto": "CWE-327", "md5": "CWE-327", "sha1": "CWE-327",
    "insecure random": "CWE-338",
}


# ---------------------------------------------------------------------------
# Attack Planning
# ---------------------------------------------------------------------------

@dataclass
class AttackPhase:
    """One phase of a multi-step attack plan."""
    name: str                       # "recon", "confirm", "deep", "validate"
    bridges: List[str]              # bridges to run in this phase
    purpose: str = ""               # human-readable explanation
    stop_on_confirm: bool = False   # stop phase early if confirmed

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "bridges": self.bridges,
            "purpose": self.purpose,
        }


@dataclass
class AttackPlan:
    """Multi-step attack plan created by HydraAgent.plan_attack()."""
    goal: Goal
    phases: List[AttackPhase] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "goal": self.goal.to_dict(),
            "phases": [p.to_dict() for p in self.phases],
            "total_bridges": sum(len(p.bridges) for p in self.phases),
        }

    def __repr__(self) -> str:
        phase_summary = " → ".join(
            f"{p.name}({','.join(p.bridges)})" for p in self.phases)
        return f"AttackPlan[{self.goal.cwe}]: {phase_summary}"


# ---------------------------------------------------------------------------
# HydraAgent
# ---------------------------------------------------------------------------

class HydraAgent:
    """Goal-driven security investigation agent.

    Usage:
        from belief.bridges import registry
        from belief.cognitive.hydra_agent import HydraAgent, Goal

        agent = HydraAgent(registry)
        verdict = agent.investigate(Goal(
            hypothesis="SQL injection in login()",
            target_file="auth.py",
            cwe="CWE-89",
        ))
        print(verdict.status, verdict.final_confidence)
    """

    def __init__(self, bridge_registry, memory=None):
        """
        Args:
            bridge_registry: belief.bridges.registry instance
            memory: optional MemoryEngine for historical FP filtering
        """
        self._registry = bridge_registry
        self._memory = memory

    def investigate(self, goal: Goal) -> Verdict:
        """Run a targeted investigation for a specific hypothesis.

        Steps:
          1. Resolve CWE if not provided (from hypothesis keywords)
          2. Pick strategy (ordered list of bridges)
          3. Run bridges one by one, cheapest first, stop early if confirmed
          4. Aggregate evidence, compute final confidence
          5. Return Verdict
        """
        t0 = time.time()
        evidence: List[Evidence] = []

        # 1. Resolve CWE
        cwe = goal.cwe or self._infer_cwe(goal.hypothesis)
        if cwe:
            goal.cwe = cwe

        # 2. Pick strategy (v4 B-14: reweight dynamically from memory)
        base_strategy = list(CWE_STRATEGY.get(cwe, DEFAULT_STRATEGY))
        available = set(self._registry.available())
        strategy = [s for s in base_strategy if s in available]

        # v4 B-14: if we have memory, sort bridges by (1 - fp_rate) so the
        # cheapest+cleanest bridges run first. Static CWE_STRATEGY order is
        # the TIEBREAKER (preserves domain expertise), not the primary sort.
        if self._memory and strategy:
            def bridge_priority(b: str) -> tuple[float, int]:
                fp_rate = self._memory.fp_rate_for_bridge(b)
                static_idx = base_strategy.index(b) if b in base_strategy else 99
                # Primary: lower FP rate first. Secondary: static idx.
                return (fp_rate, static_idx)
            strategy.sort(key=bridge_priority)
            logger.debug(f"[hydra] Strategy after memory reweighting: {strategy}")

        if not strategy:
            return Verdict(
                goal=goal, status=VerdictStatus.ERROR,
                explanation="No applicable bridges available for this CWE",
                total_elapsed_s=time.time() - t0,
            )

        logger.info(f"[hydra] Investigating: {goal.hypothesis} "
                     f"(CWE={cwe}, strategy={strategy})")

        # 3. Run bridges, accumulate evidence
        project_path = self._resolve_project_path(goal)
        confirmed_evidence: List[Evidence] = []

        for bridge_name in strategy:
            # Budget check
            elapsed = time.time() - t0
            if elapsed > goal.max_budget_s:
                logger.info(f"[hydra] Budget exhausted ({elapsed:.1f}s)")
                break

            ev = self._run_bridge(bridge_name, project_path, goal)
            evidence.append(ev)

            if ev.supports_hypothesis and ev.confidence > 0.5:
                confirmed_evidence.append(ev)

            # Early stop: if 2+ independent sources confirm, high confidence
            if len(confirmed_evidence) >= 2:
                logger.info("[hydra] Early stop: 2+ sources confirmed")
                break

        # 4. Filter known false positives
        if self._memory:
            evidence = self._filter_known_fps(evidence)

        # 5. Compute final confidence + verdict
        verdict = self._compute_verdict(goal, evidence, time.time() - t0)
        logger.info(f"[hydra] Verdict: {verdict.status.value} "
                     f"(confidence={verdict.final_confidence:.2f})")
        return verdict

    def investigate_beliefs(self, beliefs, confidence_threshold: float = 0.5,
                            max_goals: int = 10) -> List[Verdict]:
        """Auto-generate goals from low-confidence beliefs and investigate.

        This is the main entry point for the CognitiveLoop: take beliefs
        that are uncertain and try to confirm/refute them.
        """
        goals = []
        for b in beliefs:
            if b.confidence_score < confidence_threshold and len(goals) < max_goals:
                goals.append(Goal(
                    hypothesis=b.predicate.natural_language or b.predicate.expression,
                    target_file=b.scope.file_path or "",
                    target_function=b.scope.function_name or "",
                    target_line=(b.predicate.anchor_lines[0]
                                 if b.predicate.anchor_lines else 0),
                    cwe=self._infer_cwe(b.predicate.expression),
                    confidence_threshold=confidence_threshold,
                ))

        return [self.investigate(g) for g in goals]

    # ---- multi-step planning ----------------------------------------------

    def plan_attack(self, goal: Goal) -> "AttackPlan":
        """Create a multi-step attack plan for a goal.

        Instead of running all bridges at once, creates an ordered plan
        where each step can adapt based on previous results.

        Steps are organized in phases:
          Phase 1 (recon):    cheap static analysis (bandit, dlint)
          Phase 2 (confirm):  targeted analysis (semgrep with CWE rules, pyt)
          Phase 3 (exploit):  active testing (path_traversal, crosshair, pyexz3)
          Phase 4 (validate): verification (re-run with different params)

        Returns an AttackPlan that can be executed step by step.
        """
        cwe = goal.cwe or self._infer_cwe(goal.hypothesis)
        available = set(self._registry.available())

        # Build phases
        phases = []

        # Phase 1: Recon (cheap, fast)
        recon_bridges = [b for b in ["bandit", "dlint"] if b in available]
        if recon_bridges:
            phases.append(AttackPhase(
                name="recon", bridges=recon_bridges,
                purpose="Quick static scan to identify obvious patterns",
                stop_on_confirm=False,  # always run recon fully
            ))

        # Phase 2: Confirm (targeted)
        cwe_strategy = CWE_STRATEGY.get(cwe, [])
        confirm_bridges = [b for b in cwe_strategy
                          if b in available and b not in recon_bridges]
        if confirm_bridges:
            phases.append(AttackPhase(
                name="confirm", bridges=confirm_bridges[:3],
                purpose=f"Targeted scan for {cwe}",
                stop_on_confirm=True,  # if 2 sources agree, skip rest
            ))

        # Phase 3: Deep analysis (expensive)
        # v4 hotfix #3: skip FUNCTION_LEVEL_BRIDGES (crosshair, pyexz3) here.
        # plan_attack operates at project level; these verifiers need per-function
        # args and will crash otherwise. Only pyt is project-level-capable.
        deep_bridges = [b for b in ["crosshair", "pyexz3", "pyt"]
                       if b in available
                       and b not in recon_bridges + confirm_bridges
                       and b not in FUNCTION_LEVEL_BRIDGES]
        if deep_bridges:
            phases.append(AttackPhase(
                name="deep", bridges=deep_bridges[:2],
                purpose="Symbolic/taint analysis for exploitation proof",
                stop_on_confirm=True,
            ))

        return AttackPlan(goal=goal, phases=phases)

    def execute_plan(self, plan: "AttackPlan") -> Verdict:
        """Execute an attack plan with inter-phase adaptation.

        After each phase, checks results and adapts:
          - If recon finds nothing → skip expensive phases
          - If recon finds something → narrow target for confirm phase
          - If confirm agrees → high confidence, skip deep
          - If results conflict → escalate to deep
        """
        t0 = time.time()
        all_evidence: List[Evidence] = []
        project_path = self._resolve_project_path(plan.goal)

        for phase in plan.phases:
            # Budget check
            if time.time() - t0 > plan.goal.max_budget_s:
                logger.info(f"[hydra] Plan budget exhausted at phase '{phase.name}'")
                break

            logger.info(f"[hydra] Phase '{phase.name}': {phase.bridges} "
                         f"({phase.purpose})")

            phase_evidence: List[Evidence] = []
            for bridge_name in phase.bridges:
                ev = self._run_bridge(bridge_name, project_path, plan.goal)
                phase_evidence.append(ev)
                all_evidence.append(ev)

            # Adaptation between phases
            supporting = [e for e in phase_evidence
                         if e.supports_hypothesis and e.confidence > 0.5]

            if phase.name == "recon" and not supporting:
                # Recon found nothing → still continue but lower expectations
                logger.info("[hydra] Recon clean — continuing with lower priority")

            if phase.stop_on_confirm and len(supporting) >= 2:
                logger.info(f"[hydra] Phase '{phase.name}' confirmed by "
                             f"{len(supporting)} sources — stopping early")
                break

        # Filter FPs and compute verdict
        if self._memory:
            all_evidence = self._filter_known_fps(all_evidence)

        return self._compute_verdict(plan.goal, all_evidence, time.time() - t0)

    # ---- internal ---------------------------------------------------------

    def _infer_cwe(self, text: str) -> str:
        """Guess CWE from free-text hypothesis.
        v4 (B-06): delegated to cwe_taxonomy single source of truth."""
        from .cwe_taxonomy import guess_cwe
        return guess_cwe(text)

    def _resolve_project_path(self, goal: Goal) -> str:
        """Get the project path from the goal's target file."""
        if goal.target_file:
            from pathlib import Path
            p = Path(goal.target_file)
            if p.is_file():
                return str(p.parent)
            if p.exists():
                return str(p)
        return goal.target_file or "."

    # ── Bridge confidence priors ──────────────────────────────────────
    # When a bridge reports a finding relevant to the current goal, how
    # confident should Hydra be that the finding represents a real issue?
    #
    # Historical bug: the old formula was `min(0.9, 0.5 + 0.15 * N)`, which
    # caps a single-finding match at 0.65 — below the CONFIRMED threshold of
    # 0.70 in _compute_verdict. Result: every benchmark sample produced one
    # matching finding and came back `inconclusive`, so hyd_eff stayed at
    # 0.00 across the board.
    #
    # Priors here reflect per-bridge precision observed in the CVE
    # benchmark (dlint: 100%, safety_db: definitional, etc.). These are
    # intentionally higher than the generic LLM prior (0.5) because the
    # bridges in question are deterministic pattern/CVE matchers, not
    # probabilistic inferencers.
    _BRIDGE_PRIOR = {
        "safety_db":      0.95,   # CVE match is definitive
        "crosshair":      0.92,   # produces concrete counter-examples
        "path_traversal": 0.85,   # AST-based taint check, low FP
        "dlint":          0.80,   # flake8-deterministic; 100% in CVE bench
        "pyre":           0.75,
        "bandit":         0.75,
        "semgrep":        0.72,
        "pyt":            0.65,
        "supply_chain":   0.85,
        "contextgem":     0.60,
    }
    _BRIDGE_PRIOR_DEFAULT = 0.60

    def _bridge_confidence(self, bridge_name: str, relevant: list,
                           goal: Goal) -> float:
        """Confidence that `relevant` findings from `bridge_name` support
        the hypothesis encoded by `goal`.

        Components:
          * prior:  per-bridge precision (see _BRIDGE_PRIOR)
          * multi:  +0.03 per finding beyond the first, capped at +0.09
          * exact:  +0.10 if ANY finding's line equals goal.target_line
                    (only ±5 would match in _filter_relevant; exact equality
                    is a much stronger signal of reproducibility)
        Capped at 0.97 — never claim certainty, always leave slack for
        downstream refutation by memory / contradiction.
        """
        if not relevant:
            return 0.0
        prior = self._BRIDGE_PRIOR.get(bridge_name, self._BRIDGE_PRIOR_DEFAULT)
        multi_bonus = min(0.09, 0.03 * max(0, len(relevant) - 1))
        exact_hit = False
        if goal.target_line:
            for f in relevant:
                f_line = f.get("line") or f.get("line_number") or f.get("anchor_line") or 0
                if f_line and int(f_line) == int(goal.target_line):
                    exact_hit = True
                    break
        exact_bonus = 0.10 if exact_hit else 0.0
        return min(0.97, prior + multi_bonus + exact_bonus)

    def _run_bridge(self, bridge_name: str, project_path: str,
                    goal: Goal) -> Evidence:
        """Run one bridge and interpret its results relative to the goal."""
        t0 = time.time()
        try:
            result = self._registry.run(bridge_name, project_path=project_path)
            elapsed = time.time() - t0

            if result.errors:
                return Evidence(
                    source=bridge_name,
                    supports_hypothesis=False,
                    confidence=0.0,
                    elapsed_s=elapsed,
                    finding={"error": result.errors[0][:100]},
                )

            # Filter findings relevant to the goal (same file, same line range)
            relevant = self._filter_relevant(result.findings, goal)

            if relevant:
                # Per-bridge prior + exact-line bonus (v4 hotfix 2, Pack D)
                bridge_conf = self._bridge_confidence(bridge_name, relevant, goal)
                return Evidence(
                    source=bridge_name,
                    finding=relevant[0],  # best match
                    supports_hypothesis=True,
                    confidence=bridge_conf,
                    elapsed_s=elapsed,
                )
            else:
                # No relevant findings → weak evidence against hypothesis
                return Evidence(
                    source=bridge_name,
                    supports_hypothesis=False,
                    confidence=0.3,
                    elapsed_s=elapsed,
                )

        except Exception as e:
            return Evidence(
                source=bridge_name,
                supports_hypothesis=False,
                confidence=0.0,
                elapsed_s=time.time() - t0,
                finding={"error": str(e)[:100]},
            )

    def _filter_relevant(self, findings: list, goal: Goal) -> list:
        """Keep only findings that match the goal's target.

        v4 hotfix #3.2: when the goal target_file is an absolute temp path
        and Hydra re-invokes bridges on a narrowed project_path (computed
        via _resolve_project_path), the bridge may return findings with
        paths relative to THAT narrowed dir — so the substring check fails
        ('/tmp/ABC/services/user_service.py' vs './user_service.py'). Add a
        basename fallback so we still match when the two agree on the
        actual filename.
        """
        if not goal.target_file and not goal.target_line:
            return findings  # no filter if no target specified

        from pathlib import Path as _P
        goal_base = _P(goal.target_file).name if goal.target_file else ""

        relevant = []
        for f in findings:
            # File match
            if goal.target_file:
                f_file = f.get("file", "") or f.get("filename", "")
                f_base = _P(f_file).name if f_file else ""

                path_match = (goal.target_file in f_file) or (f_file in goal.target_file)
                name_match = bool(goal_base) and bool(f_base) and goal_base == f_base
                if not (path_match or name_match):
                    continue
            # Line match (±5 tolerance)
            if goal.target_line:
                f_line = f.get("line", 0) or f.get("line_number", 0)
                if f_line and abs(f_line - goal.target_line) > 5:
                    continue
            relevant.append(f)

        return relevant

    def _filter_known_fps(self, evidence: List[Evidence]) -> List[Evidence]:
        """Remove evidence that matches known false positives in memory."""
        if not self._memory:
            return evidence
        # For now, just tag — don't remove (let the verdict computation handle it)
        for ev in evidence:
            finding_id = ev.finding.get("id", "")
            if finding_id and self._memory.is_known_fp(finding_id):
                ev.supports_hypothesis = False
                ev.confidence *= 0.1  # drastically reduce
        return evidence

    def _compute_verdict(self, goal: Goal, evidence: List[Evidence],
                         elapsed: float) -> Verdict:
        """Aggregate evidence into a final verdict."""
        supporting = [e for e in evidence if e.supports_hypothesis]
        refuting = [e for e in evidence if not e.supports_hypothesis and e.confidence > 0]

        if not evidence:
            return Verdict(
                goal=goal, status=VerdictStatus.INCONCLUSIVE,
                evidence=evidence, final_confidence=0.0,
                explanation="No bridges could be run",
                total_elapsed_s=elapsed,
            )

        # Confidence aggregation: 1 - product(1 - conf_i) for supporting evidence
        if supporting:
            conf = 1.0
            for e in supporting:
                conf *= (1.0 - e.confidence)
            final_conf = 1.0 - conf
        else:
            final_conf = 0.0

        # Determine verdict
        if final_conf >= 0.7:
            status = VerdictStatus.CONFIRMED
            explanation = (f"Confirmed by {len(supporting)} source(s): "
                          f"{', '.join(e.source for e in supporting)}")
        elif final_conf <= 0.2 and len(refuting) >= 2:
            status = VerdictStatus.REFUTED
            explanation = (f"No supporting evidence from {len(evidence)} bridges")
        else:
            status = VerdictStatus.INCONCLUSIVE
            explanation = (f"Partial evidence (confidence={final_conf:.2f}) "
                          f"from {len(evidence)} bridges")

        return Verdict(
            goal=goal,
            status=status,
            evidence=evidence,
            final_confidence=round(final_conf, 3),
            explanation=explanation,
            total_elapsed_s=elapsed,
        )
