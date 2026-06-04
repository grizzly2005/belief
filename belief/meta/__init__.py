"""
BELIEF — Meta Self-Analysis (The C+ Loop).

BELIEF analyzes its own source code to:
1. Find its own implicit beliefs (self-awareness)
2. Measure its own cognitive debt (credibility)
3. Track self-improvement over versions (evolution)

This is the "auto-réflexif" feature that makes BELIEF unique:
the framework detects its own weaknesses and reports them honestly.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Belief, JustificationCategory
from ..structural import StructuralExtractor
from ..security_patterns import SecurityPatternExtractor
from ..taint import TaintEngine

logger = logging.getLogger("belief.meta")


@dataclass
class SelfAnalysisResult:
    """Results of BELIEF analyzing itself."""
    total_beliefs: int = 0
    unjustified_beliefs: int = 0    # C5 beliefs in our own code
    structural_findings: int = 0
    security_findings: int = 0
    taint_findings: int = 0
    cognitive_debt: float = 0.0
    own_weaknesses: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    beliefs: list[Belief] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_beliefs": self.total_beliefs,
            "unjustified_beliefs": self.unjustified_beliefs,
            "structural_findings": self.structural_findings,
            "security_findings": self.security_findings,
            "taint_findings": self.taint_findings,
            "cognitive_debt": round(self.cognitive_debt, 3),
            "weaknesses": self.own_weaknesses,
            "recommendations": self.recommendations,
        }

    def summary(self) -> str:
        lines = [
            "BELIEF Self-Analysis Results",
            "=" * 40,
            f"Total beliefs about own code: {self.total_beliefs}",
            f"Unjustified (C5) beliefs:     {self.unjustified_beliefs}",
            f"Structural findings:          {self.structural_findings}",
            f"Security findings:            {self.security_findings}",
            f"Taint findings:               {self.taint_findings}",
            f"Own cognitive debt:            {self.cognitive_debt:.1%}",
            "",
            "Known weaknesses:",
        ]
        for w in self.own_weaknesses:
            lines.append(f"  - {w}")
        lines.append("")
        lines.append("Recommendations:")
        for r in self.recommendations:
            lines.append(f"  - {r}")
        return "\n".join(lines)


class SelfAnalyzer:
    """
    BELIEF's self-analysis engine.

    Uses the same tools (StructuralExtractor, SecurityPatternExtractor,
    TaintEngine) on BELIEF's own source code.
    """

    def __init__(self, belief_src_path: str | None = None):
        # Find BELIEF's own source code
        if belief_src_path:
            self.src_path = Path(belief_src_path)
        else:
            # Auto-detect: this file is in belief/meta/__init__.py
            self.src_path = Path(__file__).parent.parent

        self.structural = StructuralExtractor()
        self.security = SecurityPatternExtractor()
        self.taint = TaintEngine()

    def analyze(self) -> SelfAnalysisResult:
        """Run self-analysis on BELIEF's own code."""
        result = SelfAnalysisResult()

        if not self.src_path.exists():
            result.own_weaknesses.append("Cannot locate own source code")
            return result

        # Collect all Python files (exclude examples and reference code)
        py_files = sorted(self.src_path.rglob("*.py"))
        exclude_patterns = [
            "__pycache__", "examples/", "_ref.py", "_adapted/",
            "z3_examples/", "angr_examples/", "rules_data.py",
            "tests/", "venv", "benchmark_suite/", ".git",
        ]
        py_files = [
            f for f in py_files
            if not any(pat in str(f) for pat in exclude_patterns)
        ]

        logger.info(f"Self-analysis: scanning {len(py_files)} files in {self.src_path}")

        all_beliefs: list[Belief] = []

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8")
            except Exception:
                continue

            rel_path = str(py_file.relative_to(self.src_path))

            # Structural analysis
            structural_beliefs = self.structural.extract(source, rel_path)
            result.structural_findings += len(structural_beliefs)
            all_beliefs.extend(structural_beliefs)

            # Security patterns
            security_beliefs = self.security.extract(source, rel_path)
            result.security_findings += len(security_beliefs)
            all_beliefs.extend(security_beliefs)

            # Taint analysis
            taint_beliefs = self.taint.analyze_to_beliefs(source, rel_path)
            result.taint_findings += len(taint_beliefs)
            all_beliefs.extend(taint_beliefs)

        result.beliefs = all_beliefs
        result.total_beliefs = len(all_beliefs)
        result.unjustified_beliefs = sum(
            1 for b in all_beliefs
            if b.justification == JustificationCategory.C5_NO_JUSTIFICATION
        )

        # Calculate own cognitive debt
        if all_beliefs:
            result.cognitive_debt = result.unjustified_beliefs / len(all_beliefs)

        # Generate honest self-assessment
        result.own_weaknesses = self._identify_weaknesses(all_beliefs, result)
        result.recommendations = self._generate_recommendations(result)

        logger.info(f"Self-analysis complete: {result.total_beliefs} beliefs, "
                     f"{result.cognitive_debt:.1%} cognitive debt")
        return result

    def _identify_weaknesses(self, beliefs: list[Belief],
                              result: SelfAnalysisResult) -> list[str]:
        """Honestly identify BELIEF's own weaknesses."""
        weaknesses = []

        if result.unjustified_beliefs > 0:
            weaknesses.append(
                f"BELIEF's own code has {result.unjustified_beliefs} unjustified assumptions (C5)"
            )

        if result.security_findings > 0:
            weaknesses.append(
                f"BELIEF's own code has {result.security_findings} security-related findings"
            )

        if result.taint_findings > 0:
            weaknesses.append(
                f"BELIEF's own code has {result.taint_findings} taint flow findings"
            )

        # Check for specific patterns
        untyped = sum(1 for b in beliefs if "untyped" in b.predicate.expression.lower())
        if untyped > 5:
            weaknesses.append(f"{untyped} functions with untyped parameters")

        no_timeout = sum(1 for b in beliefs if "timeout" in b.predicate.natural_language.lower())
        if no_timeout > 0:
            weaknesses.append(f"{no_timeout} network calls without timeout")

        # Acknowledge fundamental limitation
        weaknesses.append(
            "LLM extraction (C5 by definition): beliefs from LLM are not formally verified"
        )

        return weaknesses

    def _generate_recommendations(self, result: SelfAnalysisResult) -> list[str]:
        """Generate self-improvement recommendations."""
        recs = []

        if result.cognitive_debt > 0.5:
            recs.append(
                "Add type annotations and assertions to reduce cognitive debt below 50%"
            )

        if result.structural_findings > 20:
            recs.append(
                f"Address {result.structural_findings} structural findings "
                f"(untyped params, missing error handling, etc.)"
            )

        if result.security_findings > 0:
            recs.append(
                "Fix security findings in own code before analyzing others"
            )

        recs.append("Increase test coverage for edge cases in Z3 translator")
        recs.append("Add formal verification for core predicate logic (C5→C1)")

        return recs
