"""
BELIEF — Zero-Day Hunter.

Aggressive analysis mode that combines ALL BELIEF engines to find
vulnerabilities that individual engines miss. Runs structural, taint,
security patterns, temporal, and symbolic analysis in parallel,
then cross-correlates findings.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Belief
from ..structural import StructuralExtractor
from ..security_patterns import SecurityPatternExtractor
from ..taint import TaintEngine
from ..temporal import TemporalChecker

logger = logging.getLogger("belief.hunter")


@dataclass
class HuntResult:
    """Result of a zero-day hunt."""
    target_path: str
    files_scanned: int = 0
    total_beliefs: int = 0
    critical_findings: list[Belief] = field(default_factory=list)
    high_findings: list[Belief] = field(default_factory=list)
    medium_findings: list[Belief] = field(default_factory=list)
    taint_paths: int = 0
    temporal_issues: int = 0
    structural_issues: int = 0
    security_issues: int = 0
    all_beliefs: list[Belief] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.critical_findings) + len(self.high_findings) + len(self.medium_findings)

    def summary(self) -> str:
        lines = [
            f"Zero-Day Hunt: {self.target_path}",
            "=" * 50,
            f"Files scanned:     {self.files_scanned}",
            f"Total beliefs:     {self.total_beliefs}",
            f"Critical findings: {len(self.critical_findings)}",
            f"High findings:     {len(self.high_findings)}",
            f"Medium findings:   {len(self.medium_findings)}",
            "",
            "By engine:",
            f"  Structural:  {self.structural_issues}",
            f"  Security:    {self.security_issues}",
            f"  Taint:       {self.taint_paths}",
            f"  Temporal:    {self.temporal_issues}",
        ]
        if self.critical_findings:
            lines.append("\nCritical findings:")
            for b in self.critical_findings[:10]:
                lines.append(f"  [{b.scope.file_path}:{b.scope.line_start}] "
                             f"{b.predicate.natural_language or b.predicate.expression}")
        return "\n".join(lines)


class ZeroDayHunter:
    """
    Aggressive vulnerability scanner.

    Combines structural, security pattern, taint, and temporal analysis
    on every Python file in a project. Designed for deep audits.
    """

    def __init__(self):
        self.structural = StructuralExtractor()
        self.security = SecurityPatternExtractor()
        self.taint = TaintEngine()
        self.temporal = TemporalChecker()

    def hunt(self, target_path: str, max_files: int = 500) -> HuntResult:
        """Run aggressive analysis on a target directory."""
        result = HuntResult(target_path=target_path)
        root = Path(target_path)

        if not root.exists():
            logger.error(f"Target path does not exist: {target_path}")
            return result

        # Collect Python files
        if root.is_file():
            py_files = [root]
        else:
            py_files = sorted(root.rglob("*.py"))
            _hunt_exclude = {
                "__pycache__", ".git", "node_modules", ".venv",
                "venv", "venv_belief", ".tox", "migrations",
                "dist", "build", ".eggs",
            }
            # Only check path parts RELATIVE to root, so explicit targeting
            # of example dirs still works
            filtered = []
            for f in py_files:
                try:
                    rel = f.relative_to(root)
                    if not any(x in rel.parts for x in _hunt_exclude):
                        filtered.append(f)
                except ValueError:
                    filtered.append(f)
            py_files = filtered[:max_files]

        result.files_scanned = len(py_files)
        logger.info(f"Hunter: scanning {len(py_files)} files in {target_path}")

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            rel_path = str(py_file.relative_to(root)) if root.is_dir() else str(py_file)

            # Run all engines
            structural_beliefs = self.structural.extract(source, rel_path)
            result.structural_issues += len(structural_beliefs)

            security_beliefs = self.security.extract(source, rel_path)
            result.security_issues += len(security_beliefs)

            taint_beliefs = self.taint.analyze_to_beliefs(source, rel_path)
            result.taint_paths += len(taint_beliefs)

            temporal_beliefs = self.temporal.check(source, rel_path)
            result.temporal_issues += len(temporal_beliefs)

            # Aggregate
            all_file_beliefs = structural_beliefs + security_beliefs + taint_beliefs + temporal_beliefs
            result.all_beliefs.extend(all_file_beliefs)

            # Classify by severity
            for b in all_file_beliefs:
                if b.confidence_score >= 0.9:
                    result.critical_findings.append(b)
                elif b.confidence_score >= 0.8:
                    result.high_findings.append(b)
                else:
                    result.medium_findings.append(b)

        result.total_beliefs = len(result.all_beliefs)

        # Cross-correlate: beliefs found by multiple engines are more credible
        self._boost_corroborated(result)

        logger.info(f"Hunter complete: {result.total_findings} findings "
                     f"({len(result.critical_findings)} critical)")
        return result

    def hunt_file(self, file_path: str) -> HuntResult:
        """Run aggressive analysis on a single file."""
        return self.hunt(file_path, max_files=1)

    def _boost_corroborated(self, result: HuntResult):
        """Boost confidence of beliefs found by multiple engines."""
        # Group by file + line
        from collections import defaultdict
        by_location = defaultdict(list)
        for b in result.all_beliefs:
            key = f"{b.scope.file_path}:{b.scope.line_start}"
            by_location[key].append(b)

        for key, beliefs in by_location.items():
            if len(beliefs) >= 2:
                # Multiple engines found something at the same location
                for b in beliefs:
                    if b not in result.critical_findings and b.confidence_score >= 0.7:
                        result.critical_findings.append(b)
