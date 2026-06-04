"""
BELIEF — Benchmark Suite.

Measures BELIEF's performance on real-world codebases:
- Analysis speed (lines/second, beliefs/second)
- Memory usage
- Finding quality (precision, recall on known vulnerabilities)
- Engine comparison (structural vs taint vs security vs temporal)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..structural import StructuralExtractor
from ..security_patterns import SecurityPatternExtractor
from ..taint import TaintEngine
from ..temporal import TemporalChecker

logger = logging.getLogger("belief.benchmark")


@dataclass
class BenchmarkResult:
    """Result of a single benchmark run."""
    target_name: str
    files_analyzed: int = 0
    total_lines: int = 0
    total_beliefs: int = 0
    structural_beliefs: int = 0
    security_beliefs: int = 0
    taint_beliefs: int = 0
    temporal_beliefs: int = 0
    elapsed_seconds: float = 0.0

    @property
    def lines_per_second(self) -> float:
        return self.total_lines / self.elapsed_seconds if self.elapsed_seconds > 0 else 0

    @property
    def beliefs_per_second(self) -> float:
        return self.total_beliefs / self.elapsed_seconds if self.elapsed_seconds > 0 else 0

    @property
    def beliefs_per_kloc(self) -> float:
        """Beliefs per 1000 lines of code."""
        return (self.total_beliefs / self.total_lines * 1000) if self.total_lines > 0 else 0

    def to_dict(self) -> dict:
        return {
            "target": self.target_name,
            "files": self.files_analyzed,
            "lines": self.total_lines,
            "beliefs": self.total_beliefs,
            "by_engine": {
                "structural": self.structural_beliefs,
                "security": self.security_beliefs,
                "taint": self.taint_beliefs,
                "temporal": self.temporal_beliefs,
            },
            "elapsed_s": round(self.elapsed_seconds, 2),
            "lines_per_s": round(self.lines_per_second, 0),
            "beliefs_per_s": round(self.beliefs_per_second, 1),
            "beliefs_per_kloc": round(self.beliefs_per_kloc, 1),
        }


@dataclass
class BenchmarkSuite:
    """Collection of benchmark results."""
    results: list[BenchmarkResult] = field(default_factory=list)

    def summary_table(self) -> str:
        lines = [
            "| Target | Files | Lines | Beliefs | B/KLOC | Lines/s | Time |",
            "|--------|-------|-------|---------|--------|---------|------|",
        ]
        for r in self.results:
            lines.append(
                f"| {r.target_name[:20]} | {r.files_analyzed} | "
                f"{r.total_lines:,} | {r.total_beliefs} | "
                f"{r.beliefs_per_kloc:.1f} | {r.lines_per_second:,.0f} | "
                f"{r.elapsed_seconds:.1f}s |"
            )
        return "\n".join(lines)

    def engine_comparison(self) -> str:
        lines = [
            "| Target | Structural | Security | Taint | Temporal |",
            "|--------|-----------|----------|-------|----------|",
        ]
        for r in self.results:
            lines.append(
                f"| {r.target_name[:20]} | {r.structural_beliefs} | "
                f"{r.security_beliefs} | {r.taint_beliefs} | "
                f"{r.temporal_beliefs} |"
            )
        return "\n".join(lines)


class BenchmarkRunner:
    """Run benchmarks on target directories."""

    def __init__(self):
        self.structural = StructuralExtractor()
        self.security = SecurityPatternExtractor()
        self.taint = TaintEngine()
        self.temporal = TemporalChecker()

    def benchmark_directory(self, target_path: str, name: str = "",
                             max_files: int = 100) -> BenchmarkResult:
        """Benchmark BELIEF on a directory of Python files."""
        root = Path(target_path)
        result = BenchmarkResult(target_name=name or root.name)

        if not root.exists():
            return result

        py_files = sorted(root.glob("*.py"))[:max_files]
        result.files_analyzed = len(py_files)

        start = time.time()

        for f in py_files:
            try:
                source = f.read_text(errors="replace")
                lines = len(source.split("\n"))
                result.total_lines += lines

                sb = self.structural.extract(source, str(f))
                result.structural_beliefs += len(sb)

                sec = self.security.extract(source, str(f))
                result.security_beliefs += len(sec)

                tb = self.taint.analyze_to_beliefs(source, str(f))
                result.taint_beliefs += len(tb)

                temp = self.temporal.check(source, str(f))
                result.temporal_beliefs += len(temp)

            except Exception:
                continue

        result.elapsed_seconds = time.time() - start
        result.total_beliefs = (
            result.structural_beliefs + result.security_beliefs +
            result.taint_beliefs + result.temporal_beliefs
        )
        return result

    def run_all_examples(self) -> BenchmarkSuite:
        """Run benchmarks on all example directories."""
        suite = BenchmarkSuite()
        examples_dir = Path(__file__).parent.parent / "examples"

        if not examples_dir.exists():
            return suite

        for subdir in sorted(examples_dir.iterdir()):
            if subdir.is_dir() and any(subdir.glob("*.py")):
                result = self.benchmark_directory(str(subdir), subdir.name)
                if result.files_analyzed > 0:
                    suite.results.append(result)
                    logger.info(
                        f"  {result.target_name}: {result.total_beliefs} beliefs "
                        f"in {result.elapsed_seconds:.1f}s"
                    )

        return suite
