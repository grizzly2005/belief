"""
BELIEF — Multi-modal verification orchestrator (v2).

v2 changes:
- The ConflictDetector now receives a `repair_fn` callback that points back
  at the extractor's `repair_predicate()`. When Z3 fails to translate a
  predicate, the orchestrator can ask the LLM to reformulate it in DSL.
- We pass a closure that knows the source code of the belief's scope so
  the repair prompt has full context.
- Z3 stats are logged at the end (translation success rate is the key
  metric to track over time).
- Code cache is now richer (key by qualified_name) so the repair callback
  can look up the right code for any belief.
"""

from __future__ import annotations

import json
import logging

from pathlib import Path
from typing import Optional, Set

from .cache import BeliefCache
from .config import BeliefConfig
from .extractor import BeliefExtractor
from .graph import BeliefGraph
from .llm_client import LLMClient
from .structural import StructuralExtractor
from .models import (
    AnalysisReport,
    Belief,
    Conflict,
    ConflictSeverity,
    Finding,
    Frontier,
    LogicType,
    Scope,
)
from .parser import CodeParser
from .prompts import DETECT_CONFLICTS_PROMPT, SYSTEM_PROMPT
from .z3_verifier import ConflictDetector

logger = logging.getLogger("belief.orchestrator")


class Orchestrator:
    """Main BELIEF orchestrator.

    v4 merge: absorbs the former EnhancedOrchestrator via `enable_bridges`
    and `enabled_bridges`. Bridges run after LLM extraction and before
    cross-verification / Z3 / graph phases.
    """

    def __init__(
        self,
        config: BeliefConfig,
        enable_bridges: bool = False,
        enabled_bridges: Optional[Set[str]] = None,
        dedupe_bridge_beliefs: bool = True,
    ):
        self.config = config
        self.llm = LLMClient(config)
        self.extractor = BeliefExtractor(config, self.llm)
        self.structural = StructuralExtractor()

        # Cache of source code keyed by qualified_name — used by the repair
        # callback to give the LLM proper context when asking it to
        # reformulate a non-translatable predicate.
        self._code_cache: dict[str, str] = {}

        def _repair(belief: Belief, error: str) -> Optional[Belief]:
            code = self._code_cache.get(belief.scope.qualified_name, "")
            if not code:
                return None
            return self.extractor.repair_predicate(belief, code, error)

        self.conflict_detector = ConflictDetector(
            timeout_ms=config.z3_timeout_ms,
            repair_fn=_repair if config.enable_z3_repair_loop else None,
        )

        self.graph = BeliefGraph()
        self.cache = BeliefCache(cache_dir=config.output_dir)

        # Bridges configuration (formerly EnhancedOrchestrator)
        self.enable_bridges = enable_bridges
        self.dedupe_bridge_beliefs = dedupe_bridge_beliefs
        self.active_bridges: Set[str] = set()
        if enable_bridges:
            try:
                from .bridges import registry
                requested = enabled_bridges or {
                    "bandit", "dlint", "semgrep", "pyt", "safety_db"
                }
                available = set(registry.available())
                self.active_bridges = requested & available
                if not self.active_bridges:
                    logger.warning(
                        f"No bridges available. Requested={requested}, "
                        f"available={available}"
                    )
                else:
                    logger.info(
                        f"Orchestrator bridges enabled: "
                        f"{sorted(self.active_bridges)}"
                    )
            except ImportError as e:
                logger.warning(f"Bridges disabled: {e}")
                self.enable_bridges = False

    # ── Public API ──

    def analyze_project(
        self,
        project_path: str,
        project_name: str = "",
        max_frontiers: int | None = None,
        exclude_dirs: set[str] | None = None,
    ) -> AnalysisReport:
        if not project_name:
            project_name = Path(project_path).name

        report = AnalysisReport(project_name=project_name)

        # ── Step 1: Perception ──
        logger.info(f"[1/5] Parsing codebase: {project_path}")
        parser = CodeParser(project_path, exclude_dirs=exclude_dirs)
        report.source_metadata = {
            "source": "orchestrator",
            "project_path": project_path,
            "parser_exclude_dirs": sorted(parser.exclude_dirs),
        }
        functions = parser.parse()
        logger.info(f"  Found {len(functions)} functions")

        frontiers = parser.detect_frontiers(trust_threshold=0.3)
        max_f = max_frontiers or self.config.max_frontiers_per_run
        frontiers = frontiers[:max_f]
        report.frontiers = frontiers
        logger.info(f"  Detected {len(frontiers)} frontiers (analyzing top {len(frontiers)})")

        # ── Step 2: Comprehension ──
        logger.info("[2/5] Extracting beliefs from frontiers...")
        all_beliefs: list[Belief] = []
        analyzed_functions: set[str] = set()

        for i, frontier in enumerate(frontiers):
            for scope in [frontier.caller_scope, frontier.callee_scope]:
                qname = scope.qualified_name
                if qname in analyzed_functions:
                    continue
                analyzed_functions.add(qname)

                context = parser.get_function_with_context(qname)
                if not context:
                    continue

                code = context.get("code", "")
                self._code_cache[qname] = code  # for repair callback

                cached_beliefs = self.cache.get(code, qname)
                if cached_beliefs is not None:
                    logger.info(
                        f"  [{i + 1}/{len(frontiers)}] {qname} (cached: "
                        f"{len(cached_beliefs)} beliefs)"
                    )
                    beliefs = cached_beliefs
                else:
                    logger.info(
                        f"  [{i + 1}/{len(frontiers)}] Analyzing {qname}..."
                    )
                    extractor_keys = {
                        "code", "file_path", "function_name",
                        "module_name", "callers", "documentation", "test_info",
                    }
                    extractor_context = {
                        k: v for k, v in context.items() if k in extractor_keys
                    }
                    beliefs = self.extractor.extract_from_function(**extractor_context)
                    if beliefs:
                        self.cache.put(code, beliefs, qname,
                                       context.get("file_path", ""))

                all_beliefs.extend(beliefs)

                if code:
                    structural_beliefs = self.structural.extract(
                        source_code=code,
                        file_path=context.get("file_path", ""),
                        module=context.get("module_name", ""),
                        function_name=context.get("function_name"),
                    )
                    existing_exprs = {
                        b.predicate.expression.lower().strip()
                        for b in beliefs
                    }
                    for sb in structural_beliefs:
                        if sb.predicate.expression.lower().strip() not in existing_exprs:
                            all_beliefs.append(sb)

        self.cache.flush()
        report.beliefs = all_beliefs
        logger.info(f"  Total beliefs extracted: {len(all_beliefs)}")

        # ── Step 2a-bis: Bridges (merged from EnhancedOrchestrator) ──
        if self.enable_bridges and self.active_bridges:
            logger.info(f"[2a'] Running bridges: {sorted(self.active_bridges)}")
            from .bridges import registry
            from .bridges.belief_adapter import adapt_all, adapt_all_findings
            bridge_results = {}
            for name in self.active_bridges:
                try:
                    r = registry.run(name, project_path=project_path)
                    bridge_results[name] = r
                    if r.errors:
                        logger.warning(f"  {name}: {r.errors[0][:80]}")
                    else:
                        logger.info(
                            f"  {name}: {len(r)} findings "
                            f"(cache_hit={r.cache_hit}, {r.elapsed_s:.1f}s)"
                        )
                except Exception as e:
                    logger.warning(f"  {name}: exception {e}")
            bridge_beliefs = adapt_all(bridge_results)
            report.findings.extend(adapt_all_findings(bridge_results))
            logger.info(f"  Bridge beliefs produced: {len(bridge_beliefs)}")
            if self.dedupe_bridge_beliefs:
                merged = self._merge_bridge_beliefs(all_beliefs, bridge_beliefs)
                added = len(merged) - len(all_beliefs)
                logger.info(f"  After dedupe: +{added} unique bridge beliefs")
                all_beliefs = merged
            else:
                all_beliefs.extend(bridge_beliefs)
            report.beliefs = all_beliefs
            report.bridge_summary = {
                name: {
                    "status": getattr(r, "status", "available"),
                    "findings": len(r),
                    "errors": list(r.errors),
                    "elapsed_s": r.elapsed_s,
                    "cache_hit": r.cache_hit,
                    "metadata": getattr(r, "metadata", {}),
                }
                for name, r in bridge_results.items()
            }

        # ── Step 2b: Cross-verification ──
        if self.config.enable_cross_verification and all_beliefs:
            logger.info("[2b] Cross-verifying high-impact beliefs...")
            high_impact = [b for b in all_beliefs if b.fragility > 0.5]
            if high_impact:
                by_scope: dict[str, list[Belief]] = {}
                for b in high_impact:
                    by_scope.setdefault(b.scope.qualified_name, []).append(b)
                for scope_name, scope_beliefs in by_scope.items():
                    code = self._code_cache.get(scope_name, "")
                    if code:
                        self.extractor.cross_verify_beliefs(scope_beliefs, code)

        # ── Step 3: Reasoning ──
        logger.info("[3/5] Detecting conflicts...")
        all_conflicts: list[Conflict] = []

        beliefs_by_scope: dict[str, list[Belief]] = {}
        for b in all_beliefs:
            beliefs_by_scope.setdefault(b.scope.qualified_name, []).append(b)

        for frontier in frontiers:
            caller_beliefs = beliefs_by_scope.get(
                frontier.caller_scope.qualified_name, []
            )
            callee_beliefs = beliefs_by_scope.get(
                frontier.callee_scope.qualified_name, []
            )
            if not caller_beliefs or not callee_beliefs:
                continue

            fol_conflicts = self.conflict_detector.detect_pairwise(
                caller_beliefs, callee_beliefs, frontier
            )
            for c in fol_conflicts:
                c.frontier = frontier
            all_conflicts.extend(fol_conflicts)

            semantic_conflicts = self._detect_semantic_conflicts(
                caller_beliefs, callee_beliefs, frontier
            )
            all_conflicts.extend(semantic_conflicts)

        logger.info("  Checking transitive conflicts...")
        transitive = self.conflict_detector.detect_transitive(
            all_beliefs, parser.call_graph, frontiers
        )
        all_conflicts.extend(transitive)

        report.conflicts = all_conflicts
        logger.info(f"  Total conflicts found: {len(all_conflicts)}")

        z3_stats = self.conflict_detector.report_stats()
        logger.info(
            f"  Z3 stats: success_rate={z3_stats['translation_success_rate']:.1%} "
            f"(ok={z3_stats['translated_ok']}, "
            f"repaired={z3_stats['translated_after_repair']}, "
            f"failed={z3_stats['translation_failed']})"
        )

        # ── Step 4: Graph Analysis ──
        logger.info("[4/5] Building belief dependency graph...")
        self.graph.add_beliefs(all_beliefs)
        fragile_roots = self.graph.fragile_roots()
        unjustified = self.graph.unjustified_foundations()
        logger.info(
            f"  Fragile roots: {len(fragile_roots)}, "
            f"Unjustified foundations: {len(unjustified)}"
        )

        # ── Step 5: Incomprehensibility ──
        logger.info("[5/5] Identifying incomprehensible zones...")
        threshold = self.config.low_confidence_threshold
        low_confidence = [b for b in all_beliefs if b.confidence_score < threshold]
        if low_confidence:
            zones = {b.scope for b in low_confidence}
            report.incomprehensible_zones = list(zones)
            logger.info(f"  Incomprehensible zones: {len(report.incomprehensible_zones)}")

        belief_findings = [
            Finding.from_belief(b)
            for b in report.beliefs
            if getattr(b, "cwe", "") or getattr(b, "source_metadata", {})
        ]
        seen_findings = {f.dedup_key for f in report.findings}
        for finding in belief_findings:
            if finding.dedup_key not in seen_findings:
                report.findings.append(finding)
                seen_findings.add(finding.dedup_key)

        if getattr(self.config, "include_cycles", False):
            from .cycle_detector import detect_cycle_findings_with_metadata

            cycle_findings, cycle_metadata = detect_cycle_findings_with_metadata(
                parser.call_graph,
                max_cycles=getattr(self.config, "max_cycles", 100),
            )
            for finding in cycle_findings:
                if finding.dedup_key not in seen_findings:
                    report.findings.append(finding)
                    seen_findings.add(finding.dedup_key)
            report.run_metadata["cycle_analysis"] = cycle_metadata

        # ── Summary ──
        logger.info("=" * 50)
        logger.info(f"BELIEF Analysis Complete: {project_name}")
        logger.info(f"  Beliefs: {len(report.beliefs)}")
        logger.info(f"  Frontiers: {len(report.frontiers)}")
        logger.info(f"  Conflicts: {len(report.conflicts)}")
        logger.info(f"  Cognitive Debt: {report.cognitive_debt:.1%}")
        logger.info(f"  Mean Fragility: {report.mean_fragility:.3f}")
        logger.info("=" * 50)

        return report

    def analyze_single_frontier(
        self,
        code_a: str,
        code_b: str,
        name_a: str = "ComponentA",
        name_b: str = "ComponentB",
        file_path: str = "unknown.py",
    ) -> dict:
        beliefs_a = self.extractor.extract_from_function(
            code=code_a, file_path=file_path, function_name=name_a,
        )
        beliefs_b = self.extractor.extract_from_function(
            code=code_b, file_path=file_path, function_name=name_b,
        )

        scope_a = Scope(file_path=file_path, function_name=name_a)
        scope_b = Scope(file_path=file_path, function_name=name_b)
        self._code_cache[scope_a.qualified_name] = code_a
        self._code_cache[scope_b.qualified_name] = code_b
        frontier = Frontier(caller_scope=scope_a, callee_scope=scope_b)

        conflicts = self.conflict_detector.detect_pairwise(
            beliefs_a, beliefs_b, frontier
        )

        return {
            "beliefs_a": [b.to_dict() for b in beliefs_a],
            "beliefs_b": [b.to_dict() for b in beliefs_b],
            "conflicts": [c.to_dict() for c in conflicts],
            "z3_stats": self.conflict_detector.report_stats(),
        }

    # ── Internal ──

    def _detect_semantic_conflicts(
        self,
        beliefs_a: list[Belief],
        beliefs_b: list[Belief],
        frontier: Frontier,
    ) -> list[Conflict]:
        """LLM-based detection for non-FOL beliefs."""
        non_fol_a = [b for b in beliefs_a if b.logic_type != LogicType.FOL]
        non_fol_b = [b for b in beliefs_b if b.logic_type != LogicType.FOL]
        if not non_fol_a and not non_fol_b:
            return []

        caller_json = json.dumps([b.to_dict() for b in beliefs_a], indent=2)
        callee_json = json.dumps([b.to_dict() for b in beliefs_b], indent=2)
        prompt = DETECT_CONFLICTS_PROMPT.format(
            caller_beliefs=caller_json,
            callee_beliefs=callee_json,
            caller_name=frontier.caller_scope.qualified_name,
            callee_name=frontier.callee_scope.qualified_name,
            interaction_type="function call",
        )

        try:
            raw_conflicts = self.llm.complete_json(prompt, system=SYSTEM_PROMPT)
        except Exception as e:
            logger.warning(f"Semantic conflict detection failed: {e}")
            return []

        conflicts: list[Conflict] = []
        if isinstance(raw_conflicts, list):
            belief_map_a = {b.id: b for b in beliefs_a}
            belief_map_b = {b.id: b for b in beliefs_b}
            for raw in raw_conflicts:
                ba = belief_map_a.get(raw.get("belief_a_id"))
                bb = belief_map_b.get(raw.get("belief_b_id"))
                if not ba or not bb:
                    continue
                if ba.logic_type == LogicType.FOL and bb.logic_type == LogicType.FOL:
                    continue
                try:
                    severity = ConflictSeverity(raw.get("severity", "medium"))
                except ValueError:
                    severity = ConflictSeverity.MEDIUM
                conflicts.append(Conflict(
                    belief_a=ba,
                    belief_b=bb,
                    frontier=frontier,
                    severity=severity,
                    description=raw.get("description", ""),
                    verified_by="llm_semantic",
                ))
        return conflicts

    def close(self):
        self.llm.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    # ── Merged from EnhancedOrchestrator ──

    @staticmethod
    def _merge_bridge_beliefs(base: list, bridge: list) -> list:
        """Merge bridge beliefs onto base list, dropping duplicates.

        Two beliefs are duplicates if same (file, line) and predicate share
        their first 20 chars (or exact match for short predicates).
        Base wins on ties — richer semantic context."""
        if not bridge:
            return list(base)
        index: dict = {}
        canonical_seen = {
            getattr(b, "canonical_key", "") for b in base
            if getattr(b, "canonical_key", "") and getattr(b, "cwe", "")
        }
        for b in base:
            key = (b.scope.file_path or "", b.scope.line_start or 0)
            index.setdefault(key, []).append(b)

        def is_duplicate(new_b) -> bool:
            canonical_key = getattr(new_b, "canonical_key", "")
            if canonical_key and getattr(new_b, "cwe", "") and canonical_key in canonical_seen:
                return True
            key = (new_b.scope.file_path or "", new_b.scope.line_start or 0)
            for existing in index.get(key, []):
                e_expr = (existing.predicate.expression or "").lower()
                n_expr = (new_b.predicate.expression or "").lower()
                if len(e_expr) < 20 or len(n_expr) < 20:
                    if e_expr == n_expr:
                        return True
                else:
                    if e_expr[:20] == n_expr[:20]:
                        return True
            return False

        out = list(base)
        for b in bridge:
            if not is_duplicate(b):
                out.append(b)
                if getattr(b, "canonical_key", "") and getattr(b, "cwe", ""):
                    canonical_seen.add(b.canonical_key)
                key = (b.scope.file_path or "", b.scope.line_start or 0)
                index.setdefault(key, []).append(b)
        return out
