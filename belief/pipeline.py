"""
belief/pipeline.py — unified, checkpointable pipeline orchestration.

Fixes B-08 and B-15 from the audit: before v4 BELIEF had three parallel
pipelines (Orchestrator, EnhancedOrchestrator via shim, CognitiveLoop),
each instantiating its own bridges/memory/graph. That's now ONE Pipeline
built from composable Phase objects.

Design goals (matches Rapport 1's LangGraph recommendation without
pulling in LangGraph as a hard dependency):
  - Explicit phase sequence, visible at the top of the file
  - Typed state object passed between phases
  - Each phase is isolated: reads state, mutates state, returns state
  - Checkpointing: serialize state to disk between phases
  - Resume from checkpoint on crash
  - Disableable phases via configuration

When the user needs a hard LangGraph migration, the `Phase` interface
here is 1-to-1 with LangGraph's node interface, so the port is mechanical.
For now we avoid the dependency.

Usage:
    pipe = Pipeline.default_analysis(config)
    state = pipe.run(project_path="/path/to/project")
    state.report.save("report.json")
"""
from __future__ import annotations

import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("belief.pipeline")


# ─────────────────────────────────────────────────────────────────
# State passed between phases
# ─────────────────────────────────────────────────────────────────

@dataclass
class PipelineState:
    """Mutable shared state. Each phase reads from it and writes to it."""
    project_path: str
    project_name: str = ""
    config: Any = None

    # Produced by phases:
    functions: List[Any] = field(default_factory=list)
    frontiers: List[Any] = field(default_factory=list)
    beliefs: List[Any] = field(default_factory=list)
    findings: List[Any] = field(default_factory=list)
    bridge_results: Dict[str, Any] = field(default_factory=dict)
    bridge_summary: Dict[str, Any] = field(default_factory=dict)
    conflicts: List[Any] = field(default_factory=list)
    report: Optional[Any] = None  # AnalysisReport
    cognitive_report: Optional[Any] = None
    source_metadata: Dict[str, Any] = field(default_factory=dict)

    # Cross-phase caches
    code_cache: Dict[str, str] = field(default_factory=dict)

    # Checkpointing metadata
    completed_phases: List[str] = field(default_factory=list)
    phase_timings: Dict[str, float] = field(default_factory=dict)

    def mark_done(self, name: str, elapsed_s: float) -> None:
        if name not in self.completed_phases:
            self.completed_phases.append(name)
        self.phase_timings[name] = elapsed_s

    def summary(self) -> str:
        return (
            f"PipelineState(project={self.project_name}, "
            f"phases_done={len(self.completed_phases)}/{len(self.phase_timings)}, "
            f"beliefs={len(self.beliefs)}, conflicts={len(self.conflicts)})"
        )


# ─────────────────────────────────────────────────────────────────
# Phase base class
# ─────────────────────────────────────────────────────────────────

class Phase(ABC):
    """One step of the pipeline. Stateless — all state goes in PipelineState."""

    name: str = "unnamed"

    @abstractmethod
    def run(self, state: PipelineState) -> PipelineState: ...

    def should_skip(self, state: PipelineState) -> bool:
        """Return True to skip this phase. Default: skip if already done."""
        return self.name in state.completed_phases


class PipelineCheckpointError(RuntimeError):
    """Raised when a checkpoint cannot be resumed safely."""


# ─────────────────────────────────────────────────────────────────
# Built-in phases
# ─────────────────────────────────────────────────────────────────

class ParsePhase(Phase):
    """Perception layer: scan source code, build call graph, detect frontiers."""
    name = "parse"

    def run(self, state: PipelineState) -> PipelineState:
        from .parser import CodeParser
        logger.info(f"[{self.name}] Parsing {state.project_path}")
        parser = CodeParser(state.project_path)
        state.functions = parser.parse()
        if state.config:
            max_f = getattr(state.config, "max_frontiers_per_run", 200)
            frontiers = parser.detect_frontiers(trust_threshold=0.3)[:max_f]
        else:
            frontiers = parser.detect_frontiers(trust_threshold=0.3)[:200]
        state.frontiers = frontiers
        state._parser = parser  # stash for later phases (Parser itself is non-serializable)
        return state


class ExtractBeliefsPhase(Phase):
    """Comprehension layer: LLM-powered belief extraction from functions."""
    name = "extract_beliefs"

    def run(self, state: PipelineState) -> PipelineState:
        if state.config is None:
            logger.info(f"[{self.name}] No config → skipping LLM extraction")
            return state
        from .extractor import BeliefExtractor
        from .llm_client import LLMClient
        from .structural import StructuralExtractor

        llm = LLMClient(state.config)
        extractor = BeliefExtractor(state.config, llm)
        structural = StructuralExtractor()

        parser = getattr(state, "_parser", None)
        if not parser:
            logger.warning(f"[{self.name}] No parser → skipping extraction")
            return state

        analyzed = set()
        for i, frontier in enumerate(state.frontiers):
            for scope in (frontier.caller_scope, frontier.callee_scope):
                qname = scope.qualified_name
                if qname in analyzed:
                    continue
                analyzed.add(qname)
                context = parser.get_function_with_context(qname)
                if not context:
                    continue
                code = context.get("code", "")
                state.code_cache[qname] = code

                extractor_keys = {"code", "file_path", "function_name",
                                  "module_name", "callers", "documentation",
                                  "test_info"}
                ectx = {k: v for k, v in context.items() if k in extractor_keys}
                try:
                    produced = extractor.extract_from_function(**ectx)
                    state.beliefs.extend(produced)
                except Exception as e:
                    logger.warning(f"[{self.name}] {qname}: {e}")

                # Structural beliefs (regex-based, no LLM)
                if code:
                    try:
                        sb = structural.extract(
                            source_code=code,
                            file_path=context.get("file_path", ""),
                            module=context.get("module_name", ""),
                            function_name=context.get("function_name"),
                        )
                        existing = {b.predicate.expression.lower().strip()
                                    for b in state.beliefs}
                        for s in sb:
                            if s.predicate.expression.lower().strip() not in existing:
                                state.beliefs.append(s)
                    except Exception:
                        pass

        llm.close()
        return state


class BridgesPhase(Phase):
    """Run static-analysis bridges (bandit, dlint, semgrep, pyt, safety_db)."""
    name = "bridges"

    def __init__(self, enabled: Optional[set] = None, dedupe: bool = True):
        self.enabled = enabled
        self.dedupe = dedupe

    def run(self, state: PipelineState) -> PipelineState:
        try:
            from .bridges import registry
            from .bridges.belief_adapter import adapt_all, adapt_all_findings
        except ImportError:
            logger.warning(f"[{self.name}] bridges unavailable")
            return state

        available = set(registry.available())
        requested = self.enabled or {"bandit", "dlint", "semgrep",
                                     "pyt", "safety_db"}
        active = requested & available
        if not active:
            logger.warning(
                f"[{self.name}] no bridges available; requested={requested}"
            )
            return state

        logger.info(f"[{self.name}] Running {sorted(active)}")
        results = {}
        for name in active:
            try:
                r = registry.run(name, project_path=state.project_path)
                results[name] = r
            except Exception as e:
                logger.warning(f"[{self.name}] {name} failed: {e}")
        state.bridge_results = results
        state.findings.extend(adapt_all_findings(results))
        state.bridge_summary = {
            name: {
                "status": getattr(r, "status", "available"),
                "findings": len(r),
                "errors": list(getattr(r, "errors", [])),
                "elapsed_s": getattr(r, "elapsed_s", 0.0),
                "cache_hit": getattr(r, "cache_hit", False),
                "metadata": getattr(r, "metadata", {}),
            }
            for name, r in results.items()
        }

        bridge_beliefs = adapt_all(results)
        if self.dedupe:
            from .orchestrator import Orchestrator
            merged = Orchestrator._merge_bridge_beliefs(state.beliefs, bridge_beliefs)
            added = len(merged) - len(state.beliefs)
            logger.info(f"[{self.name}] +{added} unique bridge beliefs")
            state.beliefs = merged
        else:
            state.beliefs.extend(bridge_beliefs)
        return state


class ConflictsPhase(Phase):
    """Reasoning layer: detect pairwise and transitive conflicts."""
    name = "conflicts"

    def run(self, state: PipelineState) -> PipelineState:
        if state.config is None:
            return state
        from .z3_verifier import ConflictDetector
        from .extractor import BeliefExtractor
        from .llm_client import LLMClient

        llm = LLMClient(state.config)
        extractor = BeliefExtractor(state.config, llm)

        def _repair(b, err):
            code = state.code_cache.get(b.scope.qualified_name, "")
            if not code:
                return None
            return extractor.repair_predicate(b, code, err)

        det = ConflictDetector(
            timeout_ms=state.config.z3_timeout_ms,
            repair_fn=_repair if state.config.enable_z3_repair_loop else None,
        )

        by_scope: Dict[str, List] = {}
        for b in state.beliefs:
            by_scope.setdefault(b.scope.qualified_name, []).append(b)

        for fr in state.frontiers:
            caller = by_scope.get(fr.caller_scope.qualified_name, [])
            callee = by_scope.get(fr.callee_scope.qualified_name, [])
            if not caller or not callee:
                continue
            c = det.detect_pairwise(caller, callee, fr)
            for ci in c:
                ci.frontier = fr
            state.conflicts.extend(c)

        parser = getattr(state, "_parser", None)
        if parser:
            trans = det.detect_transitive(
                state.beliefs, parser.call_graph, state.frontiers
            )
            state.conflicts.extend(trans)

        llm.close()
        return state


class ReportPhase(Phase):
    """Package everything into an AnalysisReport."""
    name = "report"

    def run(self, state: PipelineState) -> PipelineState:
        from .models import AnalysisReport, Finding
        report = AnalysisReport(project_name=state.project_name or "project")
        report.beliefs = state.beliefs
        report.findings = list(state.findings)
        seen_findings = {f.dedup_key for f in report.findings}
        for finding in [
            Finding.from_belief(b)
            for b in state.beliefs
            if getattr(b, "cwe", "") or getattr(b, "source_metadata", {})
        ]:
            if finding.dedup_key not in seen_findings:
                report.findings.append(finding)
                seen_findings.add(finding.dedup_key)

        run_metadata = {
            "phase_timings": dict(state.phase_timings),
        }
        if _cycle_analysis_enabled(state.config):
            from .cycle_detector import detect_cycle_findings_with_metadata

            parser = getattr(state, "_parser", None)
            call_graph = getattr(parser, "call_graph", {}) if parser else {}
            cycle_findings, cycle_metadata = detect_cycle_findings_with_metadata(
                call_graph,
                max_cycles=_cycle_analysis_max_cycles(state.config),
            )
            for finding in cycle_findings:
                if finding.dedup_key not in seen_findings:
                    report.findings.append(finding)
                    seen_findings.add(finding.dedup_key)
            run_metadata["cycle_analysis"] = cycle_metadata

        state.findings = report.findings
        report.conflicts = state.conflicts
        report.frontiers = state.frontiers
        report.bridge_summary = state.bridge_summary
        report.source_metadata = state.source_metadata or {
            "project_path": state.project_path,
            "pipeline_phases": list(state.completed_phases),
        }
        report.run_metadata = run_metadata
        state.report = report
        return state


class CognitiveLoopPhase(Phase):
    """Run the observe→reason→decide→act→learn loop on current state."""
    name = "cognitive"

    def __init__(self, memory_dir: str = "~/.belief/memory",
                 max_budget_s: float = 60.0, max_goals: int = 10):
        self.memory_dir = memory_dir
        self.max_budget_s = max_budget_s
        self.max_goals = max_goals

    def run(self, state: PipelineState) -> PipelineState:
        from .cognitive.cognitive_loop import CognitiveLoop
        loop = CognitiveLoop(
            project_path=state.project_path,
            config=state.config,
            memory_dir=self.memory_dir,
            max_investigation_budget_s=self.max_budget_s,
            max_goals=self.max_goals,
        )
        # Pre-feed already-extracted beliefs into loop's graph so observation
        # doesn't recompute everything (B-08 fix: share state).
        if state.beliefs:
            loop.graph.add_beliefs(state.beliefs)
        state.cognitive_report = loop.run()
        return state


# ─────────────────────────────────────────────────────────────────
# Pipeline orchestrator
# ─────────────────────────────────────────────────────────────────

class Pipeline:
    """A list of phases run in sequence with optional checkpointing."""

    def __init__(self, phases: List[Phase],
                 checkpoint_dir: Optional[str] = None):
        self.phases = phases
        self.checkpoint_dir = (
            Path(checkpoint_dir).expanduser() if checkpoint_dir else None
        )

    # ── factory methods ─────────────────────────────────────────

    @classmethod
    def default_analysis(cls, config, enable_bridges: bool = False,
                         enabled_bridges: Optional[set] = None) -> "Pipeline":
        """Standard BELIEF analysis pipeline (no cognitive loop)."""
        phases: List[Phase] = [
            ParsePhase(),
            ExtractBeliefsPhase(),
        ]
        if enable_bridges:
            phases.append(BridgesPhase(enabled=enabled_bridges))
        phases += [
            ConflictsPhase(),
            ReportPhase(),
        ]
        return cls(phases)

    @classmethod
    def full_cognitive(cls, config, enabled_bridges: Optional[set] = None,
                       memory_dir: str = "~/.belief/memory") -> "Pipeline":
        """Full pipeline including cognitive loop."""
        return cls([
            ParsePhase(),
            ExtractBeliefsPhase(),
            BridgesPhase(enabled=enabled_bridges),
            ConflictsPhase(),
            ReportPhase(),
            CognitiveLoopPhase(memory_dir=memory_dir),
        ])

    @classmethod
    def bridges_only(cls, enabled_bridges: Optional[set] = None) -> "Pipeline":
        """Fast pipeline: bridges + report, no LLM extraction."""
        return cls([
            ParsePhase(),
            BridgesPhase(enabled=enabled_bridges),
            ReportPhase(),
        ])

    # ── execution ──────────────────────────────────────────────

    def run(self, project_path: str, config: Any = None,
            project_name: str = "",
            resume_from_checkpoint: bool = False) -> PipelineState:
        state = PipelineState(
            project_path=project_path,
            project_name=project_name or Path(project_path).name,
            config=config,
        )

        if resume_from_checkpoint and not self.checkpoint_dir:
            raise PipelineCheckpointError(
                "Cannot resume pipeline: checkpoint_dir is not configured."
            )

        if resume_from_checkpoint and self.checkpoint_dir:
            state = self._load_checkpoint(state)

        for phase in self.phases:
            if phase.should_skip(state):
                logger.info(f"[pipeline] skip (already done): {phase.name}")
                continue
            t0 = time.time()
            try:
                state = phase.run(state)
            except Exception as e:
                logger.exception(
                    f"[pipeline] phase={phase.name} crashed: {e}"
                )
                if self.checkpoint_dir:
                    self._save_checkpoint(state, failed_phase=phase.name)
                raise
            elapsed = time.time() - t0
            state.mark_done(phase.name, elapsed)
            logger.info(f"[pipeline] {phase.name} done in {elapsed:.2f}s")

            if self.checkpoint_dir:
                self._save_checkpoint(state)

        return state

    def describe(self) -> str:
        """Render the pipeline as an ASCII graph (for docs / stdout)."""
        lines = ["Pipeline:"]
        for i, p in enumerate(self.phases):
            arrow = "  │"
            if i == len(self.phases) - 1:
                arrow = "  └"
            lines.append(f"{arrow}── {p.name}  ({p.__class__.__name__})")
        return "\n".join(lines)

    # ── checkpointing ──────────────────────────────────────────

    def _save_checkpoint(self, state: PipelineState,
                         failed_phase: Optional[str] = None) -> None:
        if not self.checkpoint_dir:
            return
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        path = self.checkpoint_dir / "state.json"
        payload = {
            "version": 2,
            "state": self._state_to_payload(state),
            "n_beliefs": len(state.beliefs),
            "n_conflicts": len(state.conflicts),
            "failed_phase": failed_phase,
        }
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        tmp.replace(path)

    def _load_checkpoint(self, state: PipelineState) -> PipelineState:
        if not self.checkpoint_dir:
            return state
        path = self.checkpoint_dir / "state.json"
        if not path.exists():
            return state
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            raise PipelineCheckpointError(
                f"Cannot resume pipeline: checkpoint is unreadable: {e}"
            ) from e

        if data.get("version") != 2 or "state" not in data:
            raise PipelineCheckpointError(
                "Cannot resume pipeline: checkpoint is incomplete. "
                "It contains only summary counters from an older runtime; "
                "rerun without --resume or delete the checkpoint."
            )

        state = self._state_from_payload(data["state"], state)
        logger.info(
            f"[pipeline] resumed from checkpoint - already done: "
            f"{state.completed_phases}"
        )
        return state

    # ── checkpoint serialization helpers ───────────────────────

    def _state_to_payload(self, state: PipelineState) -> dict:
        parser = getattr(state, "_parser", None)
        call_graph = getattr(parser, "call_graph", {})
        return {
            "project_path": state.project_path,
            "project_name": state.project_name,
            "functions": [self._function_to_dict(f) for f in state.functions],
            "frontiers": [self._frontier_to_dict(f) for f in state.frontiers],
            "beliefs": [b.to_dict() for b in state.beliefs],
            "findings": [f.to_dict() for f in state.findings],
            "bridge_summary": state.bridge_summary,
            "conflicts": [c.to_dict() for c in state.conflicts],
            "report": state.report.to_dict() if state.report else None,
            "code_cache": state.code_cache,
            "source_metadata": state.source_metadata,
            "call_graph": {
                name: sorted(callees) for name, callees in call_graph.items()
            },
            "completed_phases": list(state.completed_phases),
            "phase_timings": dict(state.phase_timings),
        }

    def _state_from_payload(self, payload: dict, state: PipelineState) -> PipelineState:
        if not isinstance(payload, dict):
            raise PipelineCheckpointError(
                "Cannot resume pipeline: checkpoint state is not an object."
            )

        checkpoint_project = payload.get("project_path", "")
        if checkpoint_project and Path(checkpoint_project).resolve() != Path(state.project_path).resolve():
            raise PipelineCheckpointError(
                "Cannot resume pipeline: checkpoint project_path does not match "
                f"requested project_path ({checkpoint_project!r} != {state.project_path!r})."
            )

        completed = list(payload.get("completed_phases", []))
        self._validate_checkpoint_payload(payload, completed)

        state.project_path = checkpoint_project or state.project_path
        state.project_name = payload.get("project_name") or state.project_name
        state.completed_phases = completed
        state.phase_timings = dict(payload.get("phase_timings", {}))
        state.code_cache = dict(payload.get("code_cache", {}))
        state.bridge_summary = dict(payload.get("bridge_summary", {}))
        state.source_metadata = dict(payload.get("source_metadata", {}))

        state.functions = [self._function_from_dict(f) for f in payload.get("functions", [])]
        state.frontiers = [self._frontier_from_dict(f) for f in payload.get("frontiers", [])]
        state.beliefs = [self._belief_from_dict(b) for b in payload.get("beliefs", [])]
        state.findings = [self._finding_from_dict(f) for f in payload.get("findings", [])]

        belief_map = {b.id: b for b in state.beliefs}
        frontier_map = {f.id: f for f in state.frontiers}
        state.conflicts = [
            c for c in (
                self._conflict_from_dict(raw, belief_map, frontier_map)
                for raw in payload.get("conflicts", [])
            )
            if c is not None
        ]

        call_graph = {
            name: set(callees) for name, callees in payload.get("call_graph", {}).items()
        }
        if state.functions or call_graph:
            from .parser import CodeParser
            parser = CodeParser(state.project_path)
            parser.functions = {f.qualified_name: f for f in state.functions}
            parser.call_graph = call_graph
            state._parser = parser

        if payload.get("report"):
            state.report = self._report_from_dict(payload["report"], state)

        return state

    def _validate_checkpoint_payload(self, payload: dict, completed: list[str]) -> None:
        required_by_phase = {
            "parse": ("functions", "frontiers", "call_graph"),
            "extract_beliefs": ("beliefs", "code_cache"),
            "bridges": ("beliefs", "bridge_summary"),
            "conflicts": ("conflicts",),
            "report": ("report",),
        }
        missing = []
        for phase in completed:
            for key in required_by_phase.get(phase, ()):
                if key not in payload or (key == "report" and payload.get(key) is None):
                    missing.append(f"{phase}.{key}")
        if missing:
            raise PipelineCheckpointError(
                "Cannot resume pipeline: checkpoint is incomplete; missing "
                + ", ".join(missing)
                + ". Rerun without --resume or delete the checkpoint."
            )

    @staticmethod
    def _function_to_dict(func: Any) -> dict:
        if hasattr(func, "__dataclass_fields__"):
            return asdict(func)
        return {
            key: value for key, value in getattr(func, "__dict__", {}).items()
            if not key.startswith("_")
        }

    @staticmethod
    def _function_from_dict(data: dict) -> Any:
        from .parser import ParsedFunction
        fields = ParsedFunction.__dataclass_fields__
        clean = {key: data.get(key) for key in fields if key in data}
        return ParsedFunction(**clean)

    @staticmethod
    def _scope_to_dict(scope: Any) -> dict:
        return {
            "file_path": scope.file_path,
            "function_name": scope.function_name,
            "class_name": scope.class_name,
            "module": scope.module,
            "line_start": scope.line_start,
            "line_end": scope.line_end,
            "introduced_commit": scope.introduced_commit,
            "last_validated_commit": scope.last_validated_commit,
        }

    @staticmethod
    def _scope_from_dict(data: dict) -> Any:
        from .models import Scope
        return Scope(
            file_path=data.get("file_path", ""),
            function_name=data.get("function_name"),
            class_name=data.get("class_name"),
            module=data.get("module"),
            line_start=data.get("line_start"),
            line_end=data.get("line_end"),
            introduced_commit=data.get("introduced_commit"),
            last_validated_commit=data.get("last_validated_commit"),
        )

    def _frontier_to_dict(self, frontier: Any) -> dict:
        trust_profile = (
            asdict(frontier.trust_profile)
            if getattr(frontier, "trust_profile", None) is not None
            else None
        )
        return {
            "id": frontier.id,
            "caller_scope": self._scope_to_dict(frontier.caller_scope),
            "callee_scope": self._scope_to_dict(frontier.callee_scope),
            "call_site_line": frontier.call_site_line,
            "trust_asymmetry": frontier.trust_asymmetry,
            "trust_profile": trust_profile,
            "description": frontier.description,
        }

    def _frontier_from_dict(self, data: dict) -> Any:
        from .models import Frontier, TrustProfile
        profile_data = data.get("trust_profile")
        return Frontier(
            caller_scope=self._scope_from_dict(data.get("caller_scope", {})),
            callee_scope=self._scope_from_dict(data.get("callee_scope", {})),
            call_site_line=data.get("call_site_line"),
            trust_asymmetry=data.get("trust_asymmetry", 0.0),
            trust_profile=TrustProfile(**profile_data) if profile_data else None,
            description=data.get("description", ""),
            id=data.get("id", ""),
        )

    @staticmethod
    def _belief_from_dict(data: dict) -> Any:
        from .models import Belief
        return Belief.from_dict(data)

    @staticmethod
    def _finding_from_dict(data: dict) -> Any:
        from .models import Finding
        return Finding.from_dict(data)

    def _conflict_from_dict(
        self,
        data: dict,
        belief_map: dict[str, Any],
        frontier_map: dict[str, Any],
    ) -> Any:
        from .models import Conflict, ConflictSeverity
        belief_a = belief_map.get(data.get("belief_a_id"))
        belief_b = belief_map.get(data.get("belief_b_id"))
        if not belief_a or not belief_b:
            return None
        try:
            severity = ConflictSeverity(data.get("severity", "medium"))
        except ValueError:
            severity = ConflictSeverity.MEDIUM
        return Conflict(
            belief_a=belief_a,
            belief_b=belief_b,
            frontier=frontier_map.get(data.get("frontier_id")),
            severity=severity,
            is_transitive=data.get("is_transitive", False),
            transitive_path=list(data.get("transitive_path", [])),
            description=data.get("description", ""),
            exploitable=data.get("exploitable"),
            possible_world=data.get("possible_world"),
            verified_by=data.get("verified_by", ""),
        )

    @staticmethod
    def _report_from_dict(data: dict, state: PipelineState) -> Any:
        from .models import AnalysisReport
        report = AnalysisReport(project_name=data.get("project_name", state.project_name))
        report.beliefs = state.beliefs
        report.findings = state.findings
        if not report.findings:
            report.findings = [
                report_finding
                for report_finding in (
                    Pipeline._finding_from_dict(raw)
                    for raw in data.get("findings", [])
                    if isinstance(raw, dict)
                )
            ]
        report.frontiers = state.frontiers
        report.conflicts = state.conflicts
        report.bridge_summary = data.get("bridge_summary", state.bridge_summary) or {}
        report.source_metadata = data.get("source_metadata", state.source_metadata) or {}
        report.run_metadata = data.get("run_metadata", {}) or {}
        return report


def _cycle_analysis_enabled(config: Any) -> bool:
    return bool(getattr(config, "include_cycles", False))


def _cycle_analysis_max_cycles(config: Any) -> int:
    try:
        return max(0, int(getattr(config, "max_cycles", 100)))
    except (TypeError, ValueError):
        return 100


__all__ = [
    "Pipeline", "PipelineState", "Phase", "PipelineCheckpointError",
    "ParsePhase", "ExtractBeliefsPhase", "BridgesPhase",
    "ConflictsPhase", "ReportPhase", "CognitiveLoopPhase",
]
