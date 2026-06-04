"""
BELIEF — Performance metrics collector.

Tracks timing, LLM usage, extraction quality, and conflict detection
statistics for each analysis run. Outputs structured metrics that can
be included in reports and academic evaluations.
"""

from __future__ import annotations

import time
import logging
from dataclasses import dataclass, field

logger = logging.getLogger("belief.metrics")


@dataclass
class LLMCallMetrics:
    """Metrics for a single LLM call."""
    provider: str = ""
    prompt_chars: int = 0
    response_chars: int = 0
    elapsed_seconds: float = 0.0
    success: bool = True
    retries: int = 0


@dataclass
class AnalysisMetrics:
    """Aggregate metrics for a complete BELIEF analysis run."""

    # Timing
    start_time: float = 0.0
    end_time: float = 0.0
    parse_seconds: float = 0.0
    extraction_seconds: float = 0.0
    verification_seconds: float = 0.0
    total_seconds: float = 0.0

    # LLM usage
    llm_calls: list[LLMCallMetrics] = field(default_factory=list)
    llm_total_calls: int = 0
    llm_failed_calls: int = 0
    llm_total_prompt_chars: int = 0
    llm_total_response_chars: int = 0

    # Extraction quality
    functions_analyzed: int = 0
    beliefs_extracted_llm: int = 0
    beliefs_extracted_structural: int = 0
    beliefs_filtered_out: int = 0
    beliefs_total: int = 0

    # Verification
    z3_checks: int = 0
    z3_contradictions: int = 0
    heuristic_checks: int = 0
    semantic_checks: int = 0
    conflicts_found: int = 0
    transitive_conflicts: int = 0

    # Codebase
    files_parsed: int = 0
    functions_found: int = 0
    frontiers_detected: int = 0

    def record_llm_call(
        self, provider: str, prompt_chars: int, response_chars: int,
        elapsed: float, success: bool, retries: int = 0,
    ):
        self.llm_calls.append(LLMCallMetrics(
            provider=provider,
            prompt_chars=prompt_chars,
            response_chars=response_chars,
            elapsed_seconds=elapsed,
            success=success,
            retries=retries,
        ))
        self.llm_total_calls += 1
        if not success:
            self.llm_failed_calls += 1
        self.llm_total_prompt_chars += prompt_chars
        self.llm_total_response_chars += response_chars

    def finalize(self):
        """Compute derived metrics."""
        if self.start_time and self.end_time:
            self.total_seconds = self.end_time - self.start_time
        self.beliefs_total = self.beliefs_extracted_llm + self.beliefs_extracted_structural

    @property
    def llm_success_rate(self) -> float:
        if self.llm_total_calls == 0:
            return 1.0
        return (self.llm_total_calls - self.llm_failed_calls) / self.llm_total_calls

    @property
    def beliefs_per_function(self) -> float:
        if self.functions_analyzed == 0:
            return 0.0
        return self.beliefs_total / self.functions_analyzed

    @property
    def filter_rate(self) -> float:
        """Fraction of LLM beliefs that were filtered out as noise."""
        raw_total = self.beliefs_extracted_llm + self.beliefs_filtered_out
        if raw_total == 0:
            return 0.0
        return self.beliefs_filtered_out / raw_total

    @property
    def avg_llm_latency(self) -> float:
        """Average LLM call latency in seconds."""
        successful = [c for c in self.llm_calls if c.success]
        if not successful:
            return 0.0
        return sum(c.elapsed_seconds for c in successful) / len(successful)

    def to_dict(self) -> dict:
        self.finalize()
        return {
            "timing": {
                "total_seconds": round(self.total_seconds, 2),
                "parse_seconds": round(self.parse_seconds, 2),
                "extraction_seconds": round(self.extraction_seconds, 2),
                "verification_seconds": round(self.verification_seconds, 2),
            },
            "llm_usage": {
                "total_calls": self.llm_total_calls,
                "failed_calls": self.llm_failed_calls,
                "success_rate": round(self.llm_success_rate, 3),
                "avg_latency_seconds": round(self.avg_llm_latency, 2),
                "total_prompt_chars": self.llm_total_prompt_chars,
                "total_response_chars": self.llm_total_response_chars,
            },
            "extraction": {
                "functions_analyzed": self.functions_analyzed,
                "beliefs_llm": self.beliefs_extracted_llm,
                "beliefs_structural": self.beliefs_extracted_structural,
                "beliefs_filtered_out": self.beliefs_filtered_out,
                "beliefs_total": self.beliefs_total,
                "beliefs_per_function": round(self.beliefs_per_function, 1),
                "filter_rate": round(self.filter_rate, 3),
            },
            "verification": {
                "z3_checks": self.z3_checks,
                "z3_contradictions": self.z3_contradictions,
                "heuristic_checks": self.heuristic_checks,
                "semantic_checks": self.semantic_checks,
                "conflicts_found": self.conflicts_found,
                "transitive_conflicts": self.transitive_conflicts,
            },
            "codebase": {
                "files_parsed": self.files_parsed,
                "functions_found": self.functions_found,
                "frontiers_detected": self.frontiers_detected,
            },
        }

    def summary(self) -> str:
        """Human-readable summary string."""
        self.finalize()
        lines = [
            f"Analysis completed in {self.total_seconds:.1f}s",
            f"  Parsed {self.files_parsed} files, {self.functions_found} functions",
            f"  Analyzed {self.functions_analyzed} functions across {self.frontiers_detected} frontiers",
            f"  Extracted {self.beliefs_total} beliefs "
            f"({self.beliefs_extracted_llm} LLM + {self.beliefs_extracted_structural} structural, "
            f"{self.beliefs_filtered_out} filtered out)",
            f"  LLM: {self.llm_total_calls} calls, "
            f"{self.llm_success_rate:.0%} success rate, "
            f"{self.avg_llm_latency:.1f}s avg latency",
            f"  Conflicts: {self.conflicts_found} found "
            f"({self.transitive_conflicts} transitive)",
        ]
        return "\n".join(lines)


class MetricsTimer:
    """Context manager for timing code sections."""

    def __init__(self, metrics: AnalysisMetrics, field_name: str):
        self.metrics = metrics
        self.field_name = field_name
        self.start = 0.0

    def __enter__(self):
        self.start = time.time()
        return self

    def __exit__(self, *args):
        elapsed = time.time() - self.start
        setattr(self.metrics, self.field_name, elapsed)
